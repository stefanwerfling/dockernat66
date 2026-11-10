//! nf_tables chains, rules and the handful of expressions docker-nat66 needs:
//! `iifname`/`oifname`, `meta l4proto`, `th dport` (single / range), `masquerade`, `dnat`.

use crate::nfnl::{AttrBuf, Batch, NFT_MSG_NEWCHAIN, NFT_MSG_NEWRULE, NLM_F_APPEND, NLM_F_CREATE};

// chain
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// rule
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

// expression envelope / data
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;

// meta
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_L4PROTO: u32 = 16;

// cmp
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_LTE: u32 = 3;
const NFT_CMP_GTE: u32 = 5;

// payload
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// immediate
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

// ct + bitwise
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFT_CMP_NEQ: u32 = 1;
/// conntrack state bits (`ct state`): established, related.
pub const CT_ESTABLISHED: u32 = 1 << 1;
pub const CT_RELATED: u32 = 1 << 2;

// verdicts
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NF_DROP: u32 = 0;

const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
pub const NF_INET_FORWARD: u32 = 2;
pub const PRIO_FILTER: i32 = 0;

// nat
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFT_NAT_DNAT: u32 = 1;

// registers (16-byte legacy registers; an IPv6 address fits one)
const REG1: u32 = 1;
const REG2: u32 = 2;

pub const NF_INET_PRE_ROUTING: u32 = 0;
pub const NF_INET_POST_ROUTING: u32 = 4;
pub const PRIO_DSTNAT: i32 = -100;
pub const PRIO_SRCNAT: i32 = 100;
const NF_ACCEPT: u32 = 1;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

const IFNAMSIZ: usize = 16;

/// `add chain <family> <table> <name> { type nat hook <hook> priority <prio>; policy accept; }`
pub fn add_nat_chain(b: &mut Batch, family: u8, table: &str, name: &str, hook: u32, prio: i32) {
    add_base_chain(b, family, table, name, "nat", hook, prio)
}

/// `add chain ... { type filter hook <hook> priority <prio>; policy accept; }`
pub fn add_filter_chain(b: &mut Batch, family: u8, table: &str, name: &str, hook: u32, prio: i32) {
    add_base_chain(b, family, table, name, "filter", hook, prio)
}

fn add_base_chain(
    b: &mut Batch,
    family: u8,
    table: &str,
    name: &str,
    kind: &str,
    hook: u32,
    prio: i32,
) {
    let mut a = AttrBuf::new();
    a.put_str(NFTA_CHAIN_TABLE, table)
        .put_str(NFTA_CHAIN_NAME, name);
    let h = a.begin(NFTA_CHAIN_HOOK);
    a.put_u32be(NFTA_HOOK_HOOKNUM, hook)
        .put_u32be(NFTA_HOOK_PRIORITY, prio as u32);
    a.end(h);
    a.put_u32be(NFTA_CHAIN_POLICY, NF_ACCEPT)
        .put_str(NFTA_CHAIN_TYPE, kind);
    b.add(NFT_MSG_NEWCHAIN, NLM_F_CREATE, family, &a);
}

/// Append `rule` at the end of `chain`.
pub fn add_rule(b: &mut Batch, family: u8, table: &str, chain: &str, rule: &Rule) {
    let mut a = AttrBuf::new();
    a.put_str(NFTA_RULE_TABLE, table)
        .put_str(NFTA_RULE_CHAIN, chain);
    let e = a.begin(NFTA_RULE_EXPRESSIONS);
    a.extend(&rule.exprs);
    a.end(e);
    b.add(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, family, &a);
}

/// A rule: an ordered list of nf_tables expressions.
#[derive(Default)]
pub struct Rule {
    exprs: AttrBuf,
}

impl Rule {
    pub fn new() -> Self {
        Self::default()
    }

    fn expr(&mut self, name: &str, build: impl FnOnce(&mut AttrBuf)) -> &mut Self {
        let x = &mut self.exprs;
        let elem = x.begin(NFTA_LIST_ELEM);
        x.put_str(NFTA_EXPR_NAME, name);
        let mut data = AttrBuf::new();
        build(&mut data);
        if !data.buf.is_empty() {
            let d = x.begin(NFTA_EXPR_DATA);
            x.extend(&data);
            x.end(d);
        }
        x.end(elem);
        self
    }

    fn meta(&mut self, key: u32) -> &mut Self {
        self.expr("meta", |a| {
            a.put_u32be(NFTA_META_KEY, key)
                .put_u32be(NFTA_META_DREG, REG1);
        })
    }

    fn cmp(&mut self, op: u32, value: &[u8]) -> &mut Self {
        self.expr("cmp", |a| {
            a.put_u32be(NFTA_CMP_SREG, REG1).put_u32be(NFTA_CMP_OP, op);
            let d = a.begin(NFTA_CMP_DATA);
            a.put(NFTA_DATA_VALUE, value);
            a.end(d);
        })
    }

    fn th_dport(&mut self) -> &mut Self {
        self.expr("payload", |a| {
            a.put_u32be(NFTA_PAYLOAD_DREG, REG1)
                .put_u32be(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER)
                .put_u32be(NFTA_PAYLOAD_OFFSET, 2)
                .put_u32be(NFTA_PAYLOAD_LEN, 2);
        })
    }

    fn immediate(&mut self, reg: u32, value: &[u8]) -> &mut Self {
        self.expr("immediate", |a| {
            a.put_u32be(NFTA_IMMEDIATE_DREG, reg);
            let d = a.begin(NFTA_IMMEDIATE_DATA);
            a.put(NFTA_DATA_VALUE, value);
            a.end(d);
        })
    }

    /// `iifname "<name>"`
    pub fn iifname(&mut self, name: &str) -> &mut Self {
        self.meta(NFT_META_IIFNAME).cmp(NFT_CMP_EQ, &ifname(name))
    }

    /// `oifname "<name>"`
    pub fn oifname(&mut self, name: &str) -> &mut Self {
        self.meta(NFT_META_OIFNAME).cmp(NFT_CMP_EQ, &ifname(name))
    }

    /// `meta l4proto <proto> th dport <port>`
    pub fn dport(&mut self, proto: u8, port: u16) -> &mut Self {
        self.meta(NFT_META_L4PROTO).cmp(NFT_CMP_EQ, &[proto]);
        self.th_dport().cmp(NFT_CMP_EQ, &port.to_be_bytes())
    }

    /// `meta l4proto <proto> th dport <from>-<to>`
    pub fn dport_range(&mut self, proto: u8, from: u16, to: u16) -> &mut Self {
        self.meta(NFT_META_L4PROTO).cmp(NFT_CMP_EQ, &[proto]);
        self.th_dport().cmp(NFT_CMP_GTE, &from.to_be_bytes());
        self.th_dport().cmp(NFT_CMP_LTE, &to.to_be_bytes())
    }

    /// `ip6 daddr <addr>`
    pub fn daddr6(&mut self, addr: std::net::Ipv6Addr) -> &mut Self {
        self.expr("payload", |a| {
            a.put_u32be(NFTA_PAYLOAD_DREG, REG1)
                .put_u32be(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER)
                .put_u32be(NFTA_PAYLOAD_OFFSET, 24)
                .put_u32be(NFTA_PAYLOAD_LEN, 16);
        });
        self.cmp(NFT_CMP_EQ, &addr.octets())
    }

    /// `ct state <bits>` (any of the given bits set). ct state is a host-endian u32.
    pub fn ct_state(&mut self, bits: u32) -> &mut Self {
        self.expr("ct", |a| {
            a.put_u32be(NFTA_CT_KEY, NFT_CT_STATE)
                .put_u32be(NFTA_CT_DREG, REG1);
        });
        self.expr("bitwise", |a| {
            a.put_u32be(NFTA_BITWISE_SREG, REG1)
                .put_u32be(NFTA_BITWISE_DREG, REG1)
                .put_u32be(NFTA_BITWISE_LEN, 4);
            let m = a.begin(NFTA_BITWISE_MASK);
            a.put(NFTA_DATA_VALUE, &bits.to_ne_bytes());
            a.end(m);
            let x = a.begin(NFTA_BITWISE_XOR);
            a.put(NFTA_DATA_VALUE, &0u32.to_ne_bytes());
            a.end(x);
        });
        self.cmp(NFT_CMP_NEQ, &0u32.to_ne_bytes())
    }

    fn verdict(&mut self, code: u32) -> &mut Self {
        self.expr("immediate", |a| {
            a.put_u32be(NFTA_IMMEDIATE_DREG, 0); // verdict register
            let d = a.begin(NFTA_IMMEDIATE_DATA);
            let v = a.begin(NFTA_DATA_VERDICT);
            a.put_u32be(NFTA_VERDICT_CODE, code);
            a.end(v);
            a.end(d);
        })
    }

    /// `accept`
    pub fn accept(&mut self) -> &mut Self {
        self.verdict(NF_ACCEPT)
    }

    /// `drop`
    pub fn drop(&mut self) -> &mut Self {
        self.verdict(NF_DROP)
    }

    /// `masquerade`
    pub fn masquerade(&mut self) -> &mut Self {
        self.expr("masq", |_| {})
    }

    /// `dnat to [<addr>]` or `dnat to [<addr>]:<port>` (family = nfproto of the address).
    pub fn dnat(&mut self, family: u8, addr: &[u8], port: Option<u16>) -> &mut Self {
        self.immediate(REG1, addr);
        if let Some(p) = port {
            self.immediate(REG2, &p.to_be_bytes());
        }
        self.expr("nat", |a| {
            a.put_u32be(NFTA_NAT_TYPE, NFT_NAT_DNAT)
                .put_u32be(NFTA_NAT_FAMILY, u32::from(family))
                .put_u32be(NFTA_NAT_REG_ADDR_MIN, REG1);
            if port.is_some() {
                a.put_u32be(NFTA_NAT_REG_PROTO_MIN, REG2);
            }
        })
    }
}

/// Interface names compare as a NUL-padded IFNAMSIZ field (exact match).
fn ifname(name: &str) -> [u8; IFNAMSIZ] {
    let mut v = [0u8; IFNAMSIZ];
    let n = name.len().min(IFNAMSIZ - 1);
    v[..n].copy_from_slice(&name.as_bytes()[..n]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_is_padded() {
        let v = ifname("eth1");
        assert_eq!(&v[..4], b"eth1");
        assert!(v[4..].iter().all(|b| *b == 0));
    }

    #[test]
    fn masq_has_no_data_attr() {
        let mut r = Rule::new();
        r.masquerade();
        // LIST_ELEM(4) + NAME "masq\0"(4+5 -> 12) = 16
        assert_eq!(r.exprs.buf.len(), 16);
    }

    /// Needs CAP_NET_ADMIN: `unshare -rn cargo test -- --ignored`
    #[test]
    #[ignore]
    fn kernel_reports_errors_and_acks() {
        use crate::nfnl::{Socket, NFPROTO_IPV6};
        let sock = Socket::open().unwrap();
        // rule into a missing table: whole batch must fail with ENOENT
        let mut b = Batch::new();
        let mut r = Rule::new();
        r.masquerade();
        add_rule(&mut b, NFPROTO_IPV6, "dn66-missing", "c", &r);
        let e = sock.commit(&b).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
        // a valid batch commits and is visible
        let mut b = Batch::new();
        b.add_table(NFPROTO_IPV6, "dn66-test");
        add_nat_chain(
            &mut b,
            NFPROTO_IPV6,
            "dn66-test",
            "post",
            NF_INET_POST_ROUTING,
            PRIO_SRCNAT,
        );
        add_rule(&mut b, NFPROTO_IPV6, "dn66-test", "post", &r);
        sock.commit(&b).unwrap();
        assert!(sock.table_exists(NFPROTO_IPV6, "dn66-test").unwrap());
        let mut b = Batch::new();
        b.del_table(NFPROTO_IPV6, "dn66-test");
        sock.commit(&b).unwrap();
        assert!(!sock.table_exists(NFPROTO_IPV6, "dn66-test").unwrap());
    }
}
