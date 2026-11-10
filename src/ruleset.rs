//! nat66 mode: desired state and the nftables batch for docker-nat66's own `ip6` table.
//!
//! ```text
//! table ip6 docker-nat66 {
//!   chain postrouting { type nat hook postrouting priority srcnat;
//!     iifname "<bridge>" oifname "<wan>" masquerade                 # per bridge
//!   }
//!   chain prerouting { type nat hook prerouting priority dstnat;    # per forward
//!     iifname "<wan>" tcp dport 443 dnat to [<container>]:8443
//!   }
//!   chain forward { type filter hook forward priority filter;
//!     iifname "<wan>" ct state established,related accept
//!     iifname "<wan>" ip6 daddr <container> tcp dport 8443 accept   # per forward
//!     iifname "<wan>" oifname "<bridge>" drop                        # per bridge
//!   }
//! }
//! ```
//!
//! Every apply replaces the table atomically (delete-if-exists + add in one transaction).
//! An empty `Desired` (docker mode, or nothing to do) just removes the table.

use crate::config::Config;
use crate::net::{self, IfAddr};
use crate::nfnl::{Batch, NFPROTO_IPV6};
use crate::nft::{
    add_filter_chain, add_nat_chain, add_rule, Rule, CT_ESTABLISHED, CT_RELATED, IPPROTO_TCP,
    IPPROTO_UDP, NF_INET_FORWARD, NF_INET_POST_ROUTING, NF_INET_PRE_ROUTING, PRIO_DSTNAT,
    PRIO_FILTER, PRIO_SRCNAT,
};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// A forward with its target resolved to an address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Forward {
    pub proto: String,
    pub port: u16,
    pub port_end: Option<u16>,
    pub host: Ipv6Addr,
    /// Destination port after DNAT (= `port` unless remapped; ignored for ranges).
    pub host_port: u16,
}

impl Forward {
    fn proto_num(&self) -> u8 {
        if self.proto == "udp" {
            IPPROTO_UDP
        } else {
            IPPROTO_TCP
        }
    }
    fn range_end(&self) -> Option<u16> {
        self.port_end.filter(|e| *e > self.port)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Desired {
    pub wan: String,
    /// Sorted, de-duplicated bridge interface names.
    pub bridges: Vec<String>,
    pub forwards: Vec<Forward>,
}

impl Desired {
    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty() && self.forwards.is_empty()
    }
}

/// Docker bridges to NAT: explicit ones + auto-detected `br-*`/`docker0` carrying a ULA
/// (or an address inside `subnets`, if given).
pub fn select_bridges(
    cfg: &Config,
    wan: &str,
    addrs: &BTreeMap<String, Vec<IfAddr>>,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut out: Vec<String> = cfg
        .bridges
        .iter()
        .filter(|i| exists(i) && *i != wan)
        .cloned()
        .collect();
    if cfg.auto_bridges {
        for (iface, list) in addrs {
            if iface == wan
                || !cfg
                    .bridge_prefixes
                    .iter()
                    .any(|p| iface.starts_with(p.as_str()))
            {
                continue;
            }
            let hit = list.iter().any(|a| {
                if cfg.subnets.is_empty() {
                    net::is_ula(&a.addr)
                } else {
                    cfg.subnets.iter().any(|s| s.contains(&a.addr))
                }
            });
            if hit {
                out.push(iface.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn chain(b: &mut Batch, table: &str, name: &str, r: &Rule) {
    add_rule(b, NFPROTO_IPV6, table, name, r);
}

/// Build the transaction. `table_exists` → delete the old table first (atomic replace).
pub fn build_batch(table: &str, d: &Desired, table_exists: bool) -> Batch {
    let mut b = Batch::new();
    if table_exists {
        b.del_table(NFPROTO_IPV6, table);
    }
    if d.is_empty() {
        return b;
    }
    b.add_table(NFPROTO_IPV6, table);

    // outbound: masquerade bridges -> WAN
    add_nat_chain(
        &mut b,
        NFPROTO_IPV6,
        table,
        "postrouting",
        NF_INET_POST_ROUTING,
        PRIO_SRCNAT,
    );
    for br in &d.bridges {
        let mut r = Rule::new();
        r.iifname(br).oifname(&d.wan).masquerade();
        chain(&mut b, table, "postrouting", &r);
    }

    // inbound: DNAT forwards
    if !d.forwards.is_empty() {
        add_nat_chain(
            &mut b,
            NFPROTO_IPV6,
            table,
            "prerouting",
            NF_INET_PRE_ROUTING,
            PRIO_DSTNAT,
        );
        for f in &d.forwards {
            let mut r = Rule::new();
            r.iifname(&d.wan);
            match f.range_end() {
                Some(end) => r.dport_range(f.proto_num(), f.port, end).dnat(
                    NFPROTO_IPV6,
                    &f.host.octets(),
                    None,
                ),
                None => r.dport(f.proto_num(), f.port).dnat(
                    NFPROTO_IPV6,
                    &f.host.octets(),
                    Some(f.host_port),
                ),
            };
            chain(&mut b, table, "prerouting", &r);
        }
    }

    // firewall: nothing new from the WAN into the bridges except the forwards
    add_filter_chain(
        &mut b,
        NFPROTO_IPV6,
        table,
        "forward",
        NF_INET_FORWARD,
        PRIO_FILTER,
    );
    let mut r = Rule::new();
    r.iifname(&d.wan)
        .ct_state(CT_ESTABLISHED | CT_RELATED)
        .accept();
    chain(&mut b, table, "forward", &r);
    for f in &d.forwards {
        let mut r = Rule::new();
        r.iifname(&d.wan).daddr6(f.host);
        match f.range_end() {
            Some(end) => r.dport_range(f.proto_num(), f.port, end),
            None => r.dport(f.proto_num(), f.host_port),
        };
        r.accept();
        chain(&mut b, table, "forward", &r);
    }
    for br in &d.bridges {
        let mut r = Rule::new();
        r.iifname(&d.wan).oifname(br).drop();
        chain(&mut b, table, "forward", &r);
    }
    b
}

/// Human-readable form of what `build_batch` encodes (for `--dry-run` and debug logs).
pub fn render(table: &str, d: &Desired) -> String {
    if d.is_empty() {
        return format!("# table ip6 {table}: not needed -> removed\n");
    }
    let w = &d.wan;
    let mut s =
        format!("table ip6 {table} {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n");
    for br in &d.bridges {
        s += &format!("    iifname \"{br}\" oifname \"{w}\" masquerade\n");
    }
    s += "  }\n";
    if !d.forwards.is_empty() {
        s += "  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n";
        for f in &d.forwards {
            s += &match f.range_end() {
                Some(e) => format!(
                    "    iifname \"{w}\" {} dport {}-{e} dnat to {}\n",
                    f.proto, f.port, f.host
                ),
                None => format!(
                    "    iifname \"{w}\" {} dport {} dnat to [{}]:{}\n",
                    f.proto, f.port, f.host, f.host_port
                ),
            };
        }
        s += "  }\n";
    }
    s += "  chain forward {\n    type filter hook forward priority filter; policy accept;\n";
    s += &format!("    iifname \"{w}\" ct state established,related accept\n");
    for f in &d.forwards {
        s += &match f.range_end() {
            Some(e) => format!(
                "    iifname \"{w}\" ip6 daddr {} {} dport {}-{e} accept\n",
                f.host, f.proto, f.port
            ),
            None => format!(
                "    iifname \"{w}\" ip6 daddr {} {} dport {} accept\n",
                f.host, f.proto, f.host_port
            ),
        };
    }
    for br in &d.bridges {
        s += &format!("    iifname \"{w}\" oifname \"{br}\" drop\n");
    }
    s += "  }\n}\n";
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{group, parse_if_inet6};

    fn addrs() -> BTreeMap<String, Vec<IfAddr>> {
        group(parse_if_inet6(
            "\
200109e8fa4844fdbe2411fffe098711 03 40 00 00     eth1
fd000114000000000000000000000001 05 40 00 80 br-7d7ffdf182c2
fd000115000000000000000000000001 06 40 00 80 br-other
20010db8000000000000000000000001 07 40 00 80 br-global
fd000116000000000000000000000001 08 40 00 80 veth1234
",
        ))
    }

    fn cfg(pairs: &[(&str, &str)]) -> Config {
        Config::from_getter(|k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        })
        .unwrap()
    }

    #[test]
    fn auto_selects_ula_bridges_only() {
        let b = select_bridges(&cfg(&[]), "eth1", &addrs(), |_| true);
        assert_eq!(b, vec!["br-7d7ffdf182c2", "br-other"]);
    }

    #[test]
    fn subnet_filter_and_explicit() {
        let c = cfg(&[
            ("DOCKER_NAT66_SUBNETS", "fd00:114::/64"),
            ("DOCKER_NAT66_BRIDGES", "docker0,missing0"),
        ]);
        let b = select_bridges(&c, "eth1", &addrs(), |i| i != "missing0");
        assert_eq!(b, vec!["br-7d7ffdf182c2", "docker0"]);
        let c = cfg(&[("DOCKER_NAT66_AUTO", "false")]);
        assert!(select_bridges(&c, "eth1", &addrs(), |_| true).is_empty());
    }

    #[test]
    fn batch_sizes() {
        let empty = Desired::default();
        assert!(build_batch("t", &empty, false).is_empty());
        assert_eq!(
            build_batch("t", &empty, true).last_seq(),
            2,
            "only DELTABLE"
        );

        let d = Desired {
            wan: "eth1".into(),
            bridges: vec!["br-a".into(), "br-b".into()],
            forwards: vec![Forward {
                proto: "tcp".into(),
                port: 443,
                port_end: None,
                host: "fd00::10".parse().unwrap(),
                host_port: 8443,
            }],
        };
        // BEGIN(1) + table + 3 chains + 2 masq + 1 dnat + ct + 1 fwd accept + 2 drops
        assert_eq!(
            build_batch("t", &d, false).last_seq(),
            1 + 1 + 3 + 2 + 1 + 1 + 1 + 2
        );
        let s = render("t", &d);
        assert!(s.contains("iifname \"eth1\" tcp dport 443 dnat to [fd00::10]:8443"));
        assert!(s.contains("ip6 daddr fd00::10 tcp dport 8443 accept"));
        assert!(s.contains("oifname \"br-b\" drop"));
    }
}
