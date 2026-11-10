//! Interface/address discovery from `/proc/net/if_inet6` plus a tiny
//! IPv6 prefix type.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// An IPv6 prefix like `fd00:114::/64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix6 {
    pub addr: Ipv6Addr,
    pub len: u8,
}

impl Prefix6 {
    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        if self.len == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - u32::from(self.len));
        (u128::from(*ip) & mask) == (u128::from(self.addr) & mask)
    }
}

impl FromStr for Prefix6 {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, l) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/len' in prefix: {s}"))?;
        let addr: Ipv6Addr = a
            .trim()
            .parse()
            .map_err(|_| format!("invalid IPv6 address in prefix: {s}"))?;
        let len: u8 = l
            .trim()
            .parse()
            .map_err(|_| format!("invalid prefix length: {s}"))?;
        if len > 128 {
            return Err(format!("prefix length > 128: {s}"));
        }
        Ok(Self { addr, len })
    }
}

impl fmt::Display for Prefix6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// ULA range fc00::/7.
pub const ULA: Prefix6 = Prefix6 {
    addr: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
    len: 7,
};

pub fn is_ula(ip: &Ipv6Addr) -> bool {
    ULA.contains(ip)
}

pub fn is_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Global unicast: not link-local, not ULA, not loopback/unspecified/multicast.
pub fn is_global(ip: &Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_link_local(ip)
        || is_ula(ip))
}

/// One address row of `/proc/net/if_inet6`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub iface: String,
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

/// Parse `/proc/net/if_inet6` content:
/// `<32 hex addr> <ifindex> <prefixlen hex> <scope hex> <flags hex> <ifname>`.
pub fn parse_if_inet6(content: &str) -> Vec<IfAddr> {
    content
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || f[0].len() != 32 {
                return None;
            }
            let raw = u128::from_str_radix(f[0], 16).ok()?;
            let prefix_len = u8::from_str_radix(f[2], 16).ok()?;
            Some(IfAddr {
                iface: f[5].to_string(),
                addr: Ipv6Addr::from(raw),
                prefix_len,
            })
        })
        .collect()
}

/// All IPv6 addresses grouped by interface name.
pub fn read_addresses() -> std::io::Result<BTreeMap<String, Vec<IfAddr>>> {
    let content = std::fs::read_to_string("/proc/net/if_inet6")?;
    Ok(group(parse_if_inet6(&content)))
}

pub fn group(addrs: Vec<IfAddr>) -> BTreeMap<String, Vec<IfAddr>> {
    let mut map: BTreeMap<String, Vec<IfAddr>> = BTreeMap::new();
    for a in addrs {
        map.entry(a.iface.clone()).or_default().push(a);
    }
    map
}

/// Interfaces with an IPv6 default route, lowest metric first:
/// `/proc/net/ipv6_route` = dst dstlen src srclen nexthop metric refcnt use flags dev
pub fn parse_default_routes(content: &str) -> Vec<String> {
    let mut v: Vec<(u32, String)> = content
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10
                || f[0] != "00000000000000000000000000000000"
                || f[1] != "00"
                || f[9] == "lo"
            {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).ok()?;
            if flags & 0x0200 != 0 {
                return None; // RTF_REJECT (unreachable default)
            }
            Some((u32::from_str_radix(f[5], 16).ok()?, f[9].to_string()))
        })
        .collect();
    v.sort();
    let mut out: Vec<String> = Vec::new();
    for (_, d) in v {
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// Auto-detect the WAN: the default-route interface (lowest metric) that has a global IPv6.
pub fn detect_wan(addrs: &BTreeMap<String, Vec<IfAddr>>) -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
    parse_default_routes(&routes).into_iter().find(|d| {
        addrs
            .get(d)
            .is_some_and(|l| l.iter().any(|a| is_global(&a.addr)))
    })
}

/// Does the interface exist in this network namespace (even without IPv6 addresses)?
pub fn iface_exists(name: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: valid NUL-terminated string; if_nametoindex only reads it.
    unsafe { libc::if_nametoindex(c.as_ptr()) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
200109e8fa4844fdbe2411fffe098711 03 40 00 00     eth1
fe80000000000000be2411fffe098711 03 40 20 80     eth1
fd000114000000000000000000000001 05 40 00 80 br-7d7ffdf182c2
00000000000000000000000000000001 01 80 10 80       lo
";

    #[test]
    fn parses_if_inet6() {
        let a = parse_if_inet6(SAMPLE);
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].iface, "eth1");
        assert_eq!(
            a[0].addr,
            "2001:9e8:fa48:44fd:be24:11ff:fe09:8711"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(a[0].prefix_len, 64);
        assert_eq!(a[2].iface, "br-7d7ffdf182c2");
        assert_eq!(a[2].addr, "fd00:114::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(a[3].prefix_len, 128);
    }

    #[test]
    fn default_routes() {
        let r = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000ca0e14fffede1d3e 00000400 00000001 00000000 00450003     eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000ca0e14fffede1d3e 00000300 00000001 00000000 00450003     eth0
200109e8fa4844fd0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
";
        assert_eq!(parse_default_routes(r), vec!["eth0", "eth1"]);
    }

    #[test]
    fn classifies_addresses() {
        let g: Ipv6Addr = "2001:9e8:fa48:44fd::1".parse().unwrap();
        let u: Ipv6Addr = "fd00:114::1".parse().unwrap();
        let l: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_global(&g) && !is_ula(&g));
        assert!(is_ula(&u) && !is_global(&u));
        assert!(is_link_local(&l) && !is_global(&l));
    }

    #[test]
    fn prefix_contains() {
        let p: Prefix6 = "fd00:114::/64".parse().unwrap();
        assert!(p.contains(&"fd00:114::10".parse().unwrap()));
        assert!(!p.contains(&"fd00:115::10".parse().unwrap()));
        assert!("::/0"
            .parse::<Prefix6>()
            .unwrap()
            .contains(&"2001::1".parse().unwrap()));
        assert!("fd00::".parse::<Prefix6>().is_err());
        assert!("fd00::/129".parse::<Prefix6>().is_err());
    }
}
