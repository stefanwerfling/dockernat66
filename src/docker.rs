//! Docker side: a tiny Engine API client over the unix socket, the daemon.json merge and the
//! Docker restart in the host's mount namespace.

use crate::config::Mode;
use serde_json::{json, Map, Value};
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---- Engine API --------------------------------------------------------------------------

pub struct Api {
    sock: PathBuf,
}

impl Api {
    pub fn new(sock: impl Into<PathBuf>) -> Self {
        Self { sock: sock.into() }
    }

    /// `GET path` → (status, JSON body). HTTP/1.0 so the reply is never chunked.
    pub fn get(&self, path: &str) -> io::Result<(u16, Value)> {
        let mut s = UnixStream::connect(&self.sock)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        write!(s, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw)?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad HTTP reply"))?;
        let head = String::from_utf8_lossy(&raw[..split]);
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad HTTP status line"))?;
        let body = &raw[split + 4..];
        let v = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(body).unwrap_or(Value::Null)
        };
        Ok((status, v))
    }

    /// Engine version, e.g. `(29, 9)`.
    pub fn version(&self) -> io::Result<(u32, u32)> {
        let (_, v) = self.get("/version")?;
        let s = v["Version"].as_str().unwrap_or("");
        let mut it = s
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u32>().unwrap_or(0));
        Ok((it.next().unwrap_or(0), it.next().unwrap_or(0)))
    }

    /// Global IPv6 of a container (first network that has one). `Ok(None)` = not running /
    /// no IPv6 / unknown container.
    pub fn container_ipv6(&self, name: &str) -> io::Result<Option<Ipv6Addr>> {
        let (status, v) = self.get(&format!("/containers/{name}/json"))?;
        if status != 200 {
            return Ok(None);
        }
        if v["State"]["Running"].as_bool() != Some(true) {
            return Ok(None);
        }
        let nets = v["NetworkSettings"]["Networks"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        Ok(nets
            .values()
            .filter_map(|n| n["GlobalIPv6Address"].as_str())
            .find_map(|a| a.parse().ok()))
    }

    /// Names of bridge networks without IPv6 (created before IPv6 was enabled).
    pub fn bridge_networks_without_ipv6(&self) -> io::Result<Vec<String>> {
        let (_, v) = self.get("/networks")?;
        let mut out: Vec<String> = v
            .as_array()
            .map(|a| a.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|n| n["Driver"] == "bridge" && n["EnableIPv6"] != true)
            .filter_map(|n| n["Name"].as_str().map(String::from))
            .collect();
        out.sort();
        Ok(out)
    }

    /// Does the default bridge (`docker0`) have IPv6 — i.e. is the IPv6 config active?
    pub fn default_bridge_ipv6(&self) -> io::Result<bool> {
        let (_, v) = self.get("/networks/bridge")?;
        Ok(v["EnableIPv6"] == true)
    }
}

// ---- daemon.json -------------------------------------------------------------------------

const IPV6_OPT: &str = "com.docker.network.enable_ipv6";

/// Merge the keys docker-nat66 needs into an existing daemon.json value; everything else is
/// kept. `random_ula` is only used when Docker < 28 needs a `fixed-cidr-v6` and none is set.
pub fn merge_daemon_json(
    current: &Value,
    mode: Mode,
    version: (u32, u32),
    random_ula: impl FnOnce() -> String,
) -> Value {
    let mut obj: Map<String, Value> = current.as_object().cloned().unwrap_or_default();
    obj.insert("ipv6".into(), json!(true));
    obj.insert("ip6tables".into(), json!(mode == Mode::Docker));

    let dno = obj
        .entry("default-network-opts")
        .or_insert_with(|| json!({}));
    if !dno.is_object() {
        *dno = json!({});
    }
    let bridge = dno
        .as_object_mut()
        .unwrap()
        .entry("bridge")
        .or_insert_with(|| json!({}));
    if !bridge.is_object() {
        *bridge = json!({});
    }
    bridge
        .as_object_mut()
        .unwrap()
        .insert(IPV6_OPT.into(), json!("true"));

    // Docker < 28 refuses to start with ipv6=true unless the default bridge has a subnet.
    if version.0 < 28
        && obj
            .get("fixed-cidr-v6")
            .is_none_or(|v| v.as_str().is_none_or(|s| s.is_empty()))
    {
        obj.insert("fixed-cidr-v6".into(), json!(random_ula()));
    }
    Value::Object(obj)
}

/// Random ULA /64 (RFC 4193: fd + 40-bit random global ID + subnet 0).
pub fn random_ula64() -> String {
    let mut b = [0u8; 5];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        b.copy_from_slice(&t.to_le_bytes()[..5]);
    }
    let a = Ipv6Addr::new(
        0xfd00 | u16::from(b[0]),
        u16::from_be_bytes([b[1], b[2]]),
        u16::from_be_bytes([b[3], b[4]]),
        0,
        0,
        0,
        0,
        0,
    );
    format!("{a}/64")
}

pub fn read_daemon_json(path: &Path) -> Result<Value, String> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(json!({})),
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| format!("{} is not valid JSON: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Write daemon.json (backup of the original once, then atomic rename).
pub fn write_daemon_json(path: &Path, v: &Value) -> io::Result<()> {
    let backup = path.with_extension("json.docker-nat66.bak");
    if path.exists() && !backup.exists() {
        std::fs::copy(path, &backup)?;
    }
    let tmp = path.with_extension("json.docker-nat66.tmp");
    let mut s = serde_json::to_string_pretty(v).map_err(io::Error::other)?;
    s.push('\n');
    std::fs::write(&tmp, s)?;
    std::fs::rename(&tmp, path)
}

// ---- restart on the host -----------------------------------------------------------------

/// Run `/bin/sh -c <cmd>` inside the host's mount namespace (needs `pid: host` +
/// `privileged`). With `--no-block` systemd performs the restart even though this container
/// gets stopped by it.
pub fn run_on_host(cmd: &str) -> io::Result<std::process::ExitStatus> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let host = std::fs::read_link("/proc/1/ns/mnt")?;
    let own = std::fs::read_link("/proc/self/ns/mnt")?;
    if host == own {
        return Err(io::Error::other(
            "PID 1 shares our mount namespace — is `pid: host` set?",
        ));
    }
    let ns = std::fs::File::open("/proc/1/ns/mnt")?;
    let fd = ns.as_raw_fd();
    let mut c = std::process::Command::new("/bin/sh");
    c.arg("-c").arg(cmd).env_clear().env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    // SAFETY: only async-signal-safe calls (setns, chdir) between fork and exec.
    unsafe {
        c.pre_exec(move || {
            if libc::setns(fd, libc::CLONE_NEWNS) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let st = c.status();
    drop(ns);
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_foreign_keys_and_sets_ours() {
        let cur = json!({"log-driver": "local", "default-network-opts": {"bridge": {"com.docker.network.driver.mtu": "1400"}}});
        let m = merge_daemon_json(&cur, Mode::Docker, (29, 0), || unreachable!());
        assert_eq!(m["log-driver"], "local");
        assert_eq!(m["ipv6"], true);
        assert_eq!(m["ip6tables"], true);
        assert_eq!(
            m["default-network-opts"]["bridge"]["com.docker.network.driver.mtu"],
            "1400"
        );
        assert_eq!(m["default-network-opts"]["bridge"][IPV6_OPT], "true");
        assert!(m.get("fixed-cidr-v6").is_none());
        // idempotent
        assert_eq!(
            merge_daemon_json(&m, Mode::Docker, (29, 0), || unreachable!()),
            m
        );
    }

    #[test]
    fn merge_nat66_and_old_docker() {
        let m = merge_daemon_json(&json!({}), Mode::Nat66, (27, 5), || {
            "fd12:3456:789a::/64".into()
        });
        assert_eq!(m["ip6tables"], false);
        assert_eq!(m["fixed-cidr-v6"], "fd12:3456:789a::/64");
        // existing fixed-cidr-v6 is kept
        let m2 = merge_daemon_json(&m, Mode::Nat66, (27, 5), || unreachable!());
        assert_eq!(m2, m);
    }

    #[test]
    fn random_ula_is_ula64() {
        let s = random_ula64();
        let p: crate::net::Prefix6 = s.parse().unwrap();
        assert_eq!(p.len, 64);
        assert!(crate::net::is_ula(&p.addr));
        assert_eq!(p.addr.segments()[0] & 0xff00, 0xfd00);
    }
}
