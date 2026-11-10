//! IPv6 forwarding / RA sysctls. With `all.forwarding=1` the kernel ignores Router
//! Advertisements unless `accept_ra=2` — the WAN would lose its SLAAC address and default
//! route (the exact failure seen on the LXC as soon as Docker enables forwarding).

use log::{info, warn};
use std::path::{Path, PathBuf};

const PERSIST_FILE: &str = "99-docker-nat66.conf";

fn path(key: &str) -> PathBuf {
    PathBuf::from("/proc/sys/net/ipv6/conf").join(key)
}

fn read(key: &str) -> Option<String> {
    std::fs::read_to_string(path(key))
        .ok()
        .map(|s| s.trim().to_string())
}

/// `(key, value)` in apply order — accept_ra first, so enabling forwarding never drops RAs.
fn wanted(wan: &str) -> [(String, &'static str); 3] {
    [
        (format!("{wan}/accept_ra"), "2"),
        (format!("{wan}/autoconf"), "1"),
        ("all/forwarding".to_string(), "1"),
    ]
}

/// Check and (with `manage`) fix the sysctls. Called every tick, so it also repairs values
/// that something else (a Docker restart, ifupdown, …) reset. `warned` suppresses repeats.
pub fn ensure(wan: &str, manage: bool, warned: &mut bool) {
    let mut bad = false;
    for (key, want) in wanted(wan) {
        let cur = read(&key);
        if cur.as_deref() == Some(want) {
            continue;
        }
        let name = format!("net.ipv6.conf.{}", key.replace('/', "."));
        let shown = cur.unwrap_or_else(|| "?".into());
        if manage {
            match std::fs::write(path(&key), want) {
                Ok(()) => info!("sysctl {name} = {want} (was {shown})"),
                Err(e) => {
                    bad = true;
                    if !*warned {
                        warn!("cannot set {name} = {want} (is {shown}): {e} — container needs `privileged: true`");
                    }
                }
            }
        } else {
            bad = true;
            if !*warned {
                warn!("{name} = {shown}, expected {want} (DOCKER_NAT66_SYSCTL=false: set it on the host)");
            }
        }
    }
    *warned = bad;
}

/// Persist the sysctls into the host's sysctl.d (if mounted), so they are right at boot —
/// before Docker and docker-nat66 start.
pub fn persist(dir: &Path, wan: &str) {
    if !dir.is_dir() {
        return;
    }
    let mut content = String::from(
        "# written by docker-nat66 — IPv6 forwarding without losing SLAAC on the WAN\n",
    );
    for (key, val) in wanted(wan) {
        content += &format!("net.ipv6.conf.{} = {val}\n", key.replace('/', "."));
    }
    let file = dir.join(PERSIST_FILE);
    if std::fs::read_to_string(&file).ok().as_deref() == Some(content.as_str()) {
        return;
    }
    match std::fs::write(&file, content) {
        Ok(()) => info!("persisted sysctls to host {}", PERSIST_FILE),
        Err(e) => warn!("cannot write {}: {e}", file.display()),
    }
}
