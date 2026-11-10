# docker-nat66

IPv6 for Docker containers on a host that has **only a single /64** (for example a LXC or
VM behind a FRITZ!Box). Start it once, then just keep working on your normal compose
files. Every network gets IPv6 automatically, and containers can reach the internet over
IPv6.

- one small container (static Rust binary, `FROM scratch`, < 1 MB)
- configured entirely through `.env`
- no `nft`/`ip6tables` binaries, no shell; it talks to the kernel over netlink

## What it does

In both modes docker-nat66:

1. **Keeps the host sysctls right.** It sets `net.ipv6.conf.all.forwarding=1` and
   `net.ipv6.conf.<wan>.accept_ra=2` and writes them to `/etc/sysctl.d`. Without
   `accept_ra=2`, the WAN loses its public IPv6 as soon as Docker enables forwarding.
2. **Sets up Docker.** It merges into `/etc/docker/daemon.json` (keeping all other keys and
   making a backup):
   ```json
   { "ipv6": true, "ip6tables": true|false,
     "default-network-opts": { "bridge": { "com.docker.network.enable_ipv6": "true" } } }
   ```
   With this, Docker gives **every** network a ULA /64 automatically (Docker ≥ 28; on 25–27
   docker-nat66 also adds a `fixed-cidr-v6`). If the config changed, or is not active yet,
   docker-nat66 restarts Docker **once** on the host. Docker brings docker-nat66 back
   afterwards, and it does not restart Docker again.

| | `DOCKER_NAT66_MODE=docker` (default) | `DOCKER_NAT66_MODE=nat66` |
|---|---|---|
| Containers → internet over IPv6 | ✔ Docker does NAT66 (`ip6tables: true`) | ✔ docker-nat66 does NAT66 (own nftables table) |
| Inbound | `ports:` in compose, as usual | `DOCKER_NAT66_FORWARDS` (WAN port → container) |
| Inbound firewall | Docker | docker-nat66 (`ct state` + drop WAN → bridges) |
| Extra kernel modules | none | `nft_nat`, `nft_masq`, `nft_ct` on the host |

## Setup

```sh
cp .env.example .env      # set DOCKER_NAT66_WAN (e.g. eth1) and the mode
docker compose up -d --build
docker logs -f docker-nat66
```

On the first start, docker-nat66 restarts Docker once. After that, networks created
**before** IPv6 was enabled still have no IPv6. docker-nat66 lists them in its log, and you
recreate them once with `docker compose down && docker compose up -d` in the affected
project.

Required mounts and rights (already in `docker-compose.yml`): `network_mode: host`,
`pid: host`, `privileged: true`, `/var/run/docker.sock`,
`/etc/docker → /host/etc/docker` and `/etc/sysctl.d → /host/etc/sysctl.d`.

### `.env`

| Variable | Meaning | Default |
|---|---|---|
| `DOCKER_NAT66_MODE` | `docker` or `nat66` | `docker` |
| `DOCKER_NAT66_WAN` | interface with the public IPv6; empty = auto (IPv6 default route with a global address) | auto |
| `DOCKER_NAT66_FORWARDS` | nat66 only: `proto/port[-end]=container[:port]` or `=[ipv6][:port]`, separated by spaces or commas | – |
| `DOCKER_NAT66_SETUP_DOCKER` | manage `daemon.json` and the one-time restart | `true` |
| `DOCKER_NAT66_SYSCTL` | manage and persist the sysctls | `true` |
| `DOCKER_NAT66_INTERVAL` | re-check interval (seconds) | `10` |
| `RUST_LOG` | `info` / `debug` (debug prints the nftables ruleset) | `info` |

Advanced settings, usually not needed: `DOCKER_NAT66_BRIDGES`, `DOCKER_NAT66_SUBNETS`,
`DOCKER_NAT66_AUTO`, `DOCKER_NAT66_TABLE`, `DOCKER_NAT66_CLEANUP_ON_EXIT`,
`DOCKER_NAT66_RESTART_CMD` (default `systemctl --no-block restart docker || service docker restart`),
`DOCKER_NAT66_DAEMON_JSON`, `DOCKER_NAT66_SYSCTL_DIR`, `DOCKER_NAT66_DOCKER_SOCK`.

### Forwards (nat66 mode)

```env
DOCKER_NAT66_FORWARDS=tcp/443=web:443 tcp/2222=gitea:22 udp/10000-10100=game
```

Targets are **container names**. docker-nat66 looks up their current IPv6 through the
Docker API on every tick, so a restarted container with a new address is followed
automatically. A forward whose container is not running is skipped, and docker-nat66 logs
a warning.

The resulting table (`RUST_LOG=debug` or `docker-nat66 --dry-run`):

```
table ip6 docker-nat66 {
  chain postrouting { type nat hook postrouting priority srcnat;
    iifname "br-…" oifname "eth1" masquerade }
  chain prerouting { type nat hook prerouting priority dstnat;
    iifname "eth1" tcp dport 443 dnat to [fd…::2]:443 }
  chain forward { type filter hook forward priority filter;
    iifname "eth1" ct state established,related accept
    iifname "eth1" ip6 daddr fd…::2 tcp dport 443 accept
    iifname "eth1" oifname "br-…" drop }
}
```

docker-nat66 owns only this table. It replaces it atomically, re-creates it if it gets
flushed and removes it on stop. It never touches Docker's or any other table.

### Proxmox LXC: kernel modules (nat66 mode only)

A container cannot load kernel modules itself. On the **Proxmox host**:

```sh
modprobe -a nft_nat nft_masq nft_ct
printf '%s\n' nft_nat nft_masq nft_ct > /etc/modules-load.d/docker-nat66.conf
```

## CLI

```
docker-nat66 --dry-run   # show the daemon.json merge + ruleset, change nothing
docker-nat66 --once      # apply sysctls + table once
docker-nat66 --cleanup   # remove the nftables table
```

## Development

```sh
cargo test                              # unit tests
unshare -rn cargo test -- --ignored     # kernel test in a rootless netns
docker build -t docker-nat66 .
```

## License

MIT
