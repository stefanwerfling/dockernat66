//! Configuration — environment only (intended to come from the compose `.env`).

use crate::net::Prefix6;
use std::fmt;
use std::net::Ipv6Addr;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Docker does IPv6 + NAT66 itself (`ip6tables: true`); docker-nat66 only sets it up.
    Docker,
    /// docker-nat66 does NAT66, the forward firewall and port forwards (`ip6tables: false`).
    Nat66,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Docker => "docker",
            Mode::Nat66 => "nat66",
        })
    }
}

/// Where an inbound forward goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Container name/ID — its IPv6 is looked up via the Docker API on every tick.
    Container(String),
    Addr(Ipv6Addr),
}

/// `proto/port[-end]=target[:port]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub proto: String,
    pub port: u16,
    pub port_end: Option<u16>,
    pub target: Target,
    pub target_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    /// WAN interface; `None` = auto-detect (default route with a global address).
    pub wan: Option<String>,
    /// Set forwarding / accept_ra (and persist them if the host sysctl.d is mounted).
    pub manage_sysctl: bool,
    /// Write daemon.json and restart Docker when needed.
    pub setup_docker: bool,
    pub daemon_json: PathBuf,
    pub sysctl_dir: PathBuf,
    pub docker_sock: PathBuf,
    /// Shell command run in the host's mount namespace to restart Docker.
    pub restart_cmd: String,
    pub table: String,
    pub interval_secs: u64,
    pub cleanup_on_exit: bool,
    pub forwards: Vec<ForwardSpec>,
    // nat66 bridge selection
    pub bridges: Vec<String>,
    pub auto_bridges: bool,
    pub bridge_prefixes: Vec<String>,
    pub subnets: Vec<Prefix6>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_getter(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }

    pub fn from_getter(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let s = |k: &str, d: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| d.to_string())
        };
        let b = |k: &str, d: bool| get(k).map(|v| parse_bool(k, &v)).unwrap_or(Ok(d));

        let mode = match s("DOCKER_NAT66_MODE", "docker")
            .to_ascii_lowercase()
            .as_str()
        {
            "docker" => Mode::Docker,
            "nat66" => Mode::Nat66,
            other => {
                return Err(format!(
                    "DOCKER_NAT66_MODE: expected 'docker' or 'nat66', got '{other}'"
                ))
            }
        };
        let wan = get("DOCKER_NAT66_WAN").map(|v| v.trim().to_string());
        if let Some(w) = &wan {
            check_ifname("DOCKER_NAT66_WAN", w)?;
        }
        let bridges = split_list(&s("DOCKER_NAT66_BRIDGES", ""));
        for br in &bridges {
            check_ifname("DOCKER_NAT66_BRIDGES", br)?;
        }
        let subnets = split_list(&s("DOCKER_NAT66_SUBNETS", ""))
            .iter()
            .map(|p| p.parse().map_err(|e| format!("DOCKER_NAT66_SUBNETS: {e}")))
            .collect::<Result<_, _>>()?;
        let interval_secs: u64 = s("DOCKER_NAT66_INTERVAL", "10")
            .parse()
            .map_err(|_| "DOCKER_NAT66_INTERVAL: invalid number".to_string())?;
        if interval_secs == 0 {
            return Err("DOCKER_NAT66_INTERVAL must be > 0".into());
        }
        let table = s("DOCKER_NAT66_TABLE", "docker-nat66");
        if table.is_empty() || table.len() > 255 {
            return Err("DOCKER_NAT66_TABLE: invalid name".into());
        }
        let forwards = split_list(&s("DOCKER_NAT66_FORWARDS", ""))
            .iter()
            .map(|f| parse_forward(f))
            .collect::<Result<Vec<_>, _>>()?;
        if !forwards.is_empty() && mode == Mode::Docker {
            return Err(
                "DOCKER_NAT66_FORWARDS needs DOCKER_NAT66_MODE=nat66 (in docker mode use `ports:` in compose)".into(),
            );
        }

        Ok(Self {
            mode,
            wan,
            manage_sysctl: b("DOCKER_NAT66_SYSCTL", true)?,
            setup_docker: b("DOCKER_NAT66_SETUP_DOCKER", true)?,
            daemon_json: s("DOCKER_NAT66_DAEMON_JSON", "/host/etc/docker/daemon.json").into(),
            sysctl_dir: s("DOCKER_NAT66_SYSCTL_DIR", "/host/etc/sysctl.d").into(),
            docker_sock: s("DOCKER_NAT66_DOCKER_SOCK", "/var/run/docker.sock").into(),
            restart_cmd: s(
                "DOCKER_NAT66_RESTART_CMD",
                "systemctl --no-block restart docker || service docker restart",
            ),
            table,
            interval_secs,
            cleanup_on_exit: b("DOCKER_NAT66_CLEANUP_ON_EXIT", true)?,
            forwards,
            bridges,
            auto_bridges: b("DOCKER_NAT66_AUTO", true)?,
            bridge_prefixes: vec!["br-".into(), "docker0".into()],
            subnets,
        })
    }
}

/// Parse `tcp/443=web:8443`, `udp/10000-10100=game`, `tcp/22=[fd00::5]:22`.
pub fn parse_forward(s: &str) -> Result<ForwardSpec, String> {
    let err = |m: &str| {
        format!("DOCKER_NAT66_FORWARDS: '{s}': {m} (format: proto/port[-end]=container[:port])")
    };
    let (left, right) = s.split_once('=').ok_or_else(|| err("missing '='"))?;
    let (proto, ports) = left
        .split_once('/')
        .ok_or_else(|| err("missing 'proto/'"))?;
    let proto = proto.trim().to_ascii_lowercase();
    if proto != "tcp" && proto != "udp" {
        return Err(err("proto must be tcp or udp"));
    }
    let port_num = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| err("invalid port"))
    };
    let (port, port_end) = match ports.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (port_num(a)?, port_num(b)?);
            if b < a {
                return Err(err("port range end < start"));
            }
            (a, if b > a { Some(b) } else { None })
        }
        None => (port_num(ports)?, None),
    };

    let right = right.trim();
    let (target, tport) = if let Some(rest) = right.strip_prefix('[') {
        let (addr, after) = rest.split_once(']').ok_or_else(|| err("missing ']'"))?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| err("invalid IPv6 address"))?;
        let tport = match after.strip_prefix(':') {
            Some(p) => Some(port_num(p)?),
            None if after.is_empty() => None,
            None => return Err(err("garbage after ']'")),
        };
        (Target::Addr(addr), tport)
    } else {
        let (name, p) = match right.split_once(':') {
            Some((n, p)) => (n, Some(port_num(p)?)),
            None => (right, None),
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
        {
            return Err(err(
                "invalid container name (use [addr] for an IPv6 address)",
            ));
        }
        (Target::Container(name.to_string()), p)
    };
    if port_end.is_some() && tport.is_some() {
        return Err(err("a port range cannot be remapped to another port"));
    }
    Ok(ForwardSpec {
        proto,
        port,
        port_end,
        target,
        target_port: tport,
    })
}

fn check_ifname(field: &str, name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 || name.contains(['/', ' ']) {
        return Err(format!("{field}: invalid interface name '{name}'"));
    }
    Ok(())
}

fn parse_bool(key: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{key}: invalid boolean '{v}'")),
    }
}

fn split_list(v: &str) -> Vec<String> {
    v.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_getter(|k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        })
    }

    #[test]
    fn defaults() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.mode, Mode::Docker);
        assert!(c.wan.is_none() && c.manage_sysctl && c.setup_docker && c.forwards.is_empty());
    }

    #[test]
    fn forwards_parse() {
        let c = cfg(&[
            ("DOCKER_NAT66_MODE", "nat66"),
            ("DOCKER_NAT66_WAN", "eth1"),
            (
                "DOCKER_NAT66_FORWARDS",
                "tcp/443=web:8443, udp/10000-10100=game tcp/22=[fd00::5]",
            ),
        ])
        .unwrap();
        assert_eq!(c.forwards.len(), 3);
        assert_eq!(
            c.forwards[0],
            ForwardSpec {
                proto: "tcp".into(),
                port: 443,
                port_end: None,
                target: Target::Container("web".into()),
                target_port: Some(8443)
            }
        );
        assert_eq!(c.forwards[1].port_end, Some(10100));
        assert_eq!(
            c.forwards[2].target,
            Target::Addr("fd00::5".parse().unwrap())
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(cfg(&[("DOCKER_NAT66_MODE", "foo")]).is_err());
        assert!(
            cfg(&[("DOCKER_NAT66_FORWARDS", "tcp/443=web")]).is_err(),
            "forwards need nat66 mode"
        );
        for bad in [
            "tcp443=web",
            "icmp/1=web",
            "tcp/0=web",
            "tcp/5-1=web",
            "tcp/1=[zz]",
            "tcp/1-5=web:9",
            "tcp/1=we b",
        ] {
            assert!(parse_forward(bad).is_err(), "{bad}");
        }
        assert!(cfg(&[("DOCKER_NAT66_WAN", "a-very-long-interface-name")]).is_err());
    }
}
