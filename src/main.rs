//! docker-nat66 — IPv6 for Docker containers on a host that only has a single /64.
//!
//! Two modes (DOCKER_NAT66_MODE):
//! - `docker`: configure Docker so that every network gets a ULA /64 and Docker itself does
//!   NAT66 (`ip6tables: true`). Inbound via the usual compose `ports:`.
//! - `nat66`:  same Docker setup but `ip6tables: false`; docker-nat66 does the NAT66, the
//!   inbound firewall and port forwards (DOCKER_NAT66_FORWARDS) via its own nftables table.
//!
//! In both modes it keeps the host sysctls right (forwarding=1 + accept_ra=2 on the WAN).

mod config;
mod docker;
mod net;
mod nfnl;
mod nft;
mod ruleset;
mod sysctl;

use config::{Config, Mode, Target};
use docker::Api;
use log::{debug, error, info, warn};
use nfnl::{Socket, NFPROTO_IPV6};
use ruleset::{Desired, Forward};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const USAGE: &str = "\
docker-nat66 — IPv6 for Docker containers behind a single /64

USAGE:
    docker-nat66 [--once | --dry-run | --cleanup]

    (no option)   run: set up Docker + sysctls, keep the nftables table in sync
    --once        apply sysctls + table once and exit
    --dry-run     show what would be done (daemon.json + ruleset) and exit
    --cleanup     remove the nftables table and exit

Configuration is read from the environment (see .env.example).
";

#[derive(PartialEq)]
enum Cmd {
    Run,
    Once,
    DryRun,
    Cleanup,
}

type Addrs = BTreeMap<String, Vec<net::IfAddr>>;

// ---- nftables helpers ----------------------------------------------------------------------

/// Apply `d` (empty = remove). Returns whether anything was sent to the kernel.
fn apply(table: &str, d: &Desired) -> std::io::Result<bool> {
    let sock = Socket::open()?;
    let exists = sock.table_exists(NFPROTO_IPV6, table)?;
    if d.is_empty() && !exists {
        return Ok(false);
    }
    sock.commit(&ruleset::build_batch(table, d, exists))?;
    Ok(true)
}

fn table_exists(table: &str) -> std::io::Result<bool> {
    Socket::open()?.table_exists(NFPROTO_IPV6, table)
}

// ---- state shared across ticks -------------------------------------------------------------

#[derive(Default)]
struct State {
    wan: Option<String>,
    wan_global: Option<Vec<Ipv6Addr>>,
    wan_missing_warned: bool,
    sysctl_warned: bool,
    applied: Option<Desired>,
    unresolved: BTreeSet<String>,
    no_ipv6_nets: Vec<String>,
    docker_unreachable_warned: bool,
}

fn resolve_wan(cfg: &Config, addrs: &Addrs) -> Option<String> {
    match &cfg.wan {
        Some(w) if net::iface_exists(w) => Some(w.clone()),
        Some(_) => None,
        None => net::detect_wan(addrs),
    }
}

fn resolve_forwards(cfg: &Config, api: &Api, st: &mut State) -> Vec<Forward> {
    let mut out = Vec::new();
    let mut unresolved = BTreeSet::new();
    for f in &cfg.forwards {
        let host = match &f.target {
            Target::Addr(a) => Some(*a),
            Target::Container(name) => match api.container_ipv6(name) {
                Ok(Some(a)) => Some(a),
                Ok(None) => {
                    unresolved.insert(name.clone());
                    None
                }
                Err(e) => {
                    unresolved.insert(format!("{name} ({e})"));
                    None
                }
            },
        };
        if let Some(host) = host {
            out.push(Forward {
                proto: f.proto.clone(),
                port: f.port,
                port_end: f.port_end,
                host,
                host_port: f.target_port.unwrap_or(f.port),
            });
        }
    }
    if unresolved != st.unresolved {
        for n in unresolved.difference(&st.unresolved) {
            warn!("forward target container {n}: not running or has no IPv6 — forward skipped");
        }
        st.unresolved = unresolved;
    }
    out.sort();
    out.dedup();
    out
}

fn desired(cfg: &Config, api: &Api, wan: &str, addrs: &Addrs, st: &mut State) -> Desired {
    if cfg.mode == Mode::Docker {
        return Desired::default(); // Docker NATs itself; make sure our table is gone
    }
    Desired {
        wan: wan.to_string(),
        bridges: ruleset::select_bridges(cfg, wan, addrs, net::iface_exists),
        forwards: resolve_forwards(cfg, api, st),
    }
}

// ---- Docker setup --------------------------------------------------------------------------

fn restart_marker(cfg: &Config) -> std::path::PathBuf {
    cfg.daemon_json.with_file_name(".docker-nat66-restart")
}

/// Bring daemon.json in line with the mode; restart Docker when the config changed or is not
/// active yet. Returns true if a restart was triggered.
fn setup_docker(cfg: &Config, api: &Api, dry_run: bool) -> bool {
    let version = match api.version() {
        Ok(v) => v,
        Err(e) => {
            error!(
                "Docker API at {} not reachable: {e} — is /var/run/docker.sock mounted?",
                cfg.docker_sock.display()
            );
            return false;
        }
    };
    if version.0 < 25 {
        error!(
            "Docker {}.{} is too old (need >= 25, recommended >= 28) — not touching daemon.json",
            version.0, version.1
        );
        return false;
    }
    let current = match docker::read_daemon_json(&cfg.daemon_json) {
        Ok(v) => v,
        Err(e) => {
            error!("{e} — not touching it");
            return false;
        }
    };
    let merged = docker::merge_daemon_json(&current, cfg.mode, version, docker::random_ula64);
    let changed = merged != current;

    if dry_run {
        println!(
            "# Docker {}.{} — {} ({})",
            version.0,
            version.1,
            cfg.daemon_json.display(),
            if changed {
                "would change"
            } else {
                "up to date"
            }
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&merged).unwrap_or_default()
        );
        return false;
    }

    if changed {
        if let Err(e) = docker::write_daemon_json(&cfg.daemon_json, &merged) {
            error!(
                "writing {}: {e} — is /etc/docker mounted to /host/etc/docker (rw)?",
                cfg.daemon_json.display()
            );
            return false;
        }
        info!(
            "updated daemon.json for mode '{}' (backup: daemon.json.docker-nat66.bak)",
            cfg.mode
        );
    } else {
        // Config is right — is it active? (no IPv6 on docker0 = daemon not restarted yet)
        match api.default_bridge_ipv6() {
            Ok(true) => {
                info!("Docker {}.{}: IPv6 config is active", version.0, version.1);
                return false;
            }
            Ok(false) => {}
            Err(e) => {
                warn!("cannot inspect the default bridge: {e}");
                return false;
            }
        }
        // Guard against a restart loop if the restart does not take effect.
        let recent = std::fs::metadata(restart_marker(cfg))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age < Duration::from_secs(600));
        if recent {
            error!("daemon.json is set, but Docker still has no IPv6 after a restart < 10 min ago — check `journalctl -u docker`");
            return false;
        }
        info!("daemon.json is set but not active yet");
    }

    let _ = std::fs::write(restart_marker(cfg), b"");
    warn!(
        "restarting Docker to activate IPv6 (this container comes back with it): `{}`",
        cfg.restart_cmd
    );
    match docker::run_on_host(&cfg.restart_cmd) {
        Ok(st) if st.success() => true,
        Ok(st) => {
            error!("Docker restart command failed ({st}) — restart Docker manually once");
            false
        }
        Err(e) => {
            error!("cannot run the restart on the host: {e} (needs `pid: host` + `privileged: true`) — restart Docker manually once");
            false
        }
    }
}

fn warn_networks_without_ipv6(api: &Api, st: &mut State) {
    match api.bridge_networks_without_ipv6() {
        Ok(nets) => {
            st.docker_unreachable_warned = false;
            if nets != st.no_ipv6_nets {
                if !nets.is_empty() {
                    warn!(
                        "networks without IPv6 (created before IPv6 was enabled): {} — recreate once: `docker compose down && docker compose up -d`",
                        nets.join(", ")
                    );
                }
                st.no_ipv6_nets = nets;
            }
        }
        Err(e) => {
            if !st.docker_unreachable_warned {
                warn!("Docker API not reachable: {e}");
                st.docker_unreachable_warned = true;
            }
        }
    }
}

// ---- one tick ------------------------------------------------------------------------------

fn tick(cfg: &Config, api: &Api, st: &mut State) {
    let addrs = match net::read_addresses() {
        Ok(a) => a,
        Err(e) => {
            error!("reading /proc/net/if_inet6: {e}");
            return;
        }
    };

    let Some(wan) = resolve_wan(cfg, &addrs) else {
        if !st.wan_missing_warned {
            match &cfg.wan {
                Some(w) => warn!("WAN interface '{w}' does not exist (yet)"),
                None => warn!("no WAN found (no IPv6 default route with a global address) — set DOCKER_NAT66_WAN"),
            }
            st.wan_missing_warned = true;
        }
        return;
    };
    st.wan_missing_warned = false;

    if st.wan.as_deref() != Some(wan.as_str()) {
        info!(
            "WAN interface: {wan}{}",
            if cfg.wan.is_none() {
                " (auto-detected)"
            } else {
                ""
            }
        );
        if cfg.manage_sysctl {
            sysctl::persist(&cfg.sysctl_dir, &wan);
        }
        st.wan = Some(wan.clone());
    }
    sysctl::ensure(&wan, cfg.manage_sysctl, &mut st.sysctl_warned);

    let global: Vec<Ipv6Addr> = addrs
        .get(&wan)
        .map(|l| l.iter().map(|a| a.addr).filter(net::is_global).collect())
        .unwrap_or_default();
    if st.wan_global.as_ref() != Some(&global) {
        if global.is_empty() {
            warn!("no global IPv6 on '{wan}' yet — waiting for a router advertisement");
        } else {
            info!("WAN '{wan}' global IPv6: {global:?}");
        }
        st.wan_global = Some(global);
    }

    if cfg.setup_docker || !cfg.forwards.is_empty() {
        warn_networks_without_ipv6(api, st);
    }

    let d = desired(cfg, api, &wan, &addrs, st);
    let changed = st.applied.as_ref() != Some(&d);
    if !changed && (d.is_empty() || table_exists(&cfg.table).unwrap_or(false)) {
        return;
    }
    if !changed {
        warn!("table ip6 {} vanished — re-applying", cfg.table);
    }
    match apply(&cfg.table, &d) {
        Ok(touched) => {
            if d.is_empty() {
                if touched {
                    info!("removed table ip6 {}", cfg.table);
                }
            } else {
                info!(
                    "nat66: masquerade {:?} -> {wan}, {} forward(s){}",
                    d.bridges,
                    d.forwards.len(),
                    if d.bridges.is_empty() {
                        " (no IPv6 Docker bridges yet)"
                    } else {
                        ""
                    }
                );
                debug!("\n{}", ruleset::render(&cfg.table, &d));
            }
            st.applied = Some(d);
        }
        Err(e) => {
            error!("applying nftables failed: {e} — kernel modules nft_nat, nft_masq, nft_ct loaded on the host?");
            st.applied = None;
        }
    }
}

// ---- main ----------------------------------------------------------------------------------

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut cmd = Cmd::Run;
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--once" => cmd = Cmd::Once,
            "--dry-run" => cmd = Cmd::DryRun,
            "--cleanup" => cmd = Cmd::Cleanup,
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("docker-nat66 {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("config: {e}");
            return ExitCode::from(2);
        }
    };
    let api = Api::new(&cfg.docker_sock);

    match cmd {
        Cmd::Cleanup => {
            return match apply(&cfg.table, &Desired::default()) {
                Ok(t) => {
                    info!(
                        "table ip6 {} {}",
                        cfg.table,
                        if t { "removed" } else { "not present" }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    error!("cleanup failed: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Cmd::DryRun => {
            println!("# mode: {}", cfg.mode);
            if cfg.setup_docker {
                setup_docker(&cfg, &api, true);
            }
            let addrs = net::read_addresses().unwrap_or_default();
            let wan = resolve_wan(&cfg, &addrs).unwrap_or_else(|| "<no WAN>".into());
            println!("# WAN: {wan}");
            let mut st = State::default();
            print!(
                "{}",
                ruleset::render(&cfg.table, &desired(&cfg, &api, &wan, &addrs, &mut st))
            );
            return ExitCode::SUCCESS;
        }
        Cmd::Once => {
            let mut st = State::default();
            tick(&cfg, &api, &mut st);
            let ok = st.wan.is_some() && st.applied.is_some();
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Cmd::Run => {}
    }

    info!(
        "docker-nat66 {} starting: mode={}, wan={}, table=ip6 {}",
        env!("CARGO_PKG_VERSION"),
        cfg.mode,
        cfg.wan.as_deref().unwrap_or("auto"),
        cfg.table
    );
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&stop)) {
            error!("signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut st = State::default();
    // Sysctls first (accept_ra=2 before anything else), then Docker.
    tick(&cfg, &api, &mut st);
    if cfg.setup_docker && setup_docker(&cfg, &api, false) {
        info!("waiting for the Docker restart");
    }

    let interval = Duration::from_secs(cfg.interval_secs);
    while !stop.load(Ordering::Relaxed) {
        let until = Instant::now() + interval;
        while Instant::now() < until && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
        if !stop.load(Ordering::Relaxed) {
            tick(&cfg, &api, &mut st);
        }
    }

    info!("shutting down");
    if cfg.cleanup_on_exit && cfg.mode == Mode::Nat66 {
        match apply(&cfg.table, &Desired::default()) {
            Ok(true) => info!("removed table ip6 {}", cfg.table),
            Ok(false) => {}
            Err(e) => {
                error!("cleanup failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
