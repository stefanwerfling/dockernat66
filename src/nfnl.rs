//! Minimal nfnetlink / nf_tables client: message framing, a transaction (batch) builder and
//! a blocking `NETLINK_NETFILTER` socket.
//!
//! Wire format (linux/netlink.h, linux/netfilter/nfnetlink.h, linux/netfilter/nf_tables.h):
//! every message is `nlmsghdr` (16 bytes, host byte order) + `nfgenmsg` (4 bytes) + a stream
//! of 4-byte aligned TLV attributes (`nlattr`, header in host order). nf_tables integer
//! attribute *values* are big endian. Object changes are sent as one batch
//! (`BATCH_BEGIN` … `BATCH_END`) which the kernel commits atomically.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ---- netlink core ----------------------------------------------------------------------

const NETLINK_NETFILTER: libc::c_int = 12;

const NLMSG_HDR: usize = 16;
const NFGEN_HDR: usize = 4;
const NLA_HDR: usize = 4;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

pub const NLA_F_NESTED: u16 = 0x8000;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// ---- nf_tables message types + table attributes ----------------------------------------

pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;

/// `nfgenmsg.nfgen_family` for the `ip6` table family.
pub const NFPROTO_IPV6: u8 = 10;

const fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

const fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

// ---- attribute buffer ------------------------------------------------------------------

/// A growable attribute stream with support for nesting (start/end back-patching).
#[derive(Default, Clone)]
pub struct AttrBuf {
    pub(crate) buf: Vec<u8>,
}

/// Open nested attribute; close it with [`AttrBuf::end`].
#[must_use]
pub struct Nest(usize);

impl AttrBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = NLA_HDR + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(self.buf.len() + pad4(len) - len, 0);
        self
    }

    pub fn put_u32be(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_be_bytes())
    }

    /// NUL-terminated string (the NUL counts in `nla_len`).
    pub fn put_str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.put(ty, &v)
    }

    pub fn begin(&mut self, ty: u16) -> Nest {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        Nest(at)
    }

    pub fn end(&mut self, n: Nest) -> &mut Self {
        let len = (self.buf.len() - n.0) as u16;
        self.buf[n.0..n.0 + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    /// Append another attribute stream verbatim (already aligned).
    pub fn extend(&mut self, other: &AttrBuf) -> &mut Self {
        self.buf.extend_from_slice(&other.buf);
        self
    }
}

// ---- messages / batch ------------------------------------------------------------------

fn push_msg(
    out: &mut Vec<u8>,
    ty: u16,
    flags: u16,
    seq: u32,
    family: u8,
    res_id: u16,
    attrs: &[u8],
) {
    let len = (NLMSG_HDR + NFGEN_HDR + attrs.len()) as u32;
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    out.push(family);
    out.push(0); // NFNETLINK_V0
    out.extend_from_slice(&res_id.to_be_bytes());
    out.extend_from_slice(attrs);
}

/// One atomic nf_tables transaction.
pub struct Batch {
    body: Vec<u8>,
    seq: u32,
    msgs: usize,
}

impl Batch {
    pub fn new() -> Self {
        Self {
            body: Vec::new(),
            seq: 1,
            msgs: 0,
        } // seq 1 is BATCH_BEGIN
    }

    /// Append an nf_tables object message (ACK requested, so failures are reported).
    pub fn add(&mut self, msg: u16, extra_flags: u16, family: u8, attrs: &AttrBuf) {
        self.seq += 1;
        self.msgs += 1;
        push_msg(
            &mut self.body,
            nft_type(msg),
            NLM_F_REQUEST | NLM_F_ACK | extra_flags,
            self.seq,
            family,
            0,
            &attrs.buf,
        );
    }

    pub fn add_table(&mut self, family: u8, name: &str) {
        let mut a = AttrBuf::new();
        a.put_str(NFTA_TABLE_NAME, name)
            .put_u32be(NFTA_TABLE_FLAGS, 0);
        self.add(NFT_MSG_NEWTABLE, NLM_F_CREATE, family, &a);
    }

    pub fn del_table(&mut self, family: u8, name: &str) {
        let mut a = AttrBuf::new();
        a.put_str(NFTA_TABLE_NAME, name);
        self.add(NFT_MSG_DELTABLE, 0, family, &a);
    }

    pub fn is_empty(&self) -> bool {
        self.msgs == 0
    }

    /// Sequence number of the last object message (its ACK means the batch committed).
    pub fn last_seq(&self) -> u32 {
        self.seq
    }

    /// Wire bytes: BATCH_BEGIN + messages + BATCH_END.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 2 * (NLMSG_HDR + NFGEN_HDR));
        push_msg(
            &mut out,
            NFNL_MSG_BATCH_BEGIN,
            NLM_F_REQUEST,
            1,
            0,
            NFNL_SUBSYS_NFTABLES,
            &[],
        );
        out.extend_from_slice(&self.body);
        push_msg(
            &mut out,
            NFNL_MSG_BATCH_END,
            NLM_F_REQUEST,
            self.seq + 1,
            0,
            NFNL_SUBSYS_NFTABLES,
            &[],
        );
        out
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

// ---- socket ----------------------------------------------------------------------------

/// A reply message as seen by [`Socket::recv_each`].
struct Reply<'a> {
    ty: u16,
    seq: u32,
    payload: &'a [u8],
}

pub struct Socket {
    fd: OwnedFd,
}

impl Socket {
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain socket(2) call; the result is checked and owned below.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a valid fd we exclusively own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: zeroed sockaddr_nl is a valid "kernel assigns pid" address.
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Never block forever on a missing reply.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tv) as libc::socklen_t,
            );
        }
        Ok(Self { fd })
    }

    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != bytes.len() {
            return Err(io::Error::other("short netlink send"));
        }
        Ok(())
    }

    /// Feed every received message to `f` until it returns `Some(result)`.
    fn recv_each<T>(&self, mut f: impl FnMut(Reply<'_>) -> Option<io::Result<T>>) -> io::Result<T> {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let data = &buf[..n as usize];
            let mut off = 0;
            while off + NLMSG_HDR <= data.len() {
                let len = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                if len < NLMSG_HDR || off + len > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink reply",
                    ));
                }
                let reply = Reply {
                    ty: u16::from_ne_bytes(data[off + 4..off + 6].try_into().unwrap()),
                    seq: u32::from_ne_bytes(data[off + 8..off + 12].try_into().unwrap()),
                    payload: &data[off + NLMSG_HDR..off + len],
                };
                if let Some(r) = f(reply) {
                    return r;
                }
                off += pad4(len);
            }
        }
    }

    /// Commit a batch. Success = the ACK of the last object message; the first non-zero
    /// error (the kernel aborts the whole transaction) is returned.
    pub fn commit(&self, batch: &Batch) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        self.send(&batch.encode())?;
        let last = batch.last_seq();
        self.recv_each(|r| match r.ty {
            NLMSG_ERROR => match nlmsgerr(r.payload) {
                0 if r.seq == last => Some(Ok(())),
                0 => None,
                e => Some(Err(io::Error::from_raw_os_error(-e))),
            },
            _ => None,
        })
    }

    /// Does `table` exist in `family`? (non-dump GETTABLE: reply is the table, or -ENOENT)
    pub fn table_exists(&self, family: u8, name: &str) -> io::Result<bool> {
        let mut a = AttrBuf::new();
        a.put_str(NFTA_TABLE_NAME, name);
        let mut req = Vec::new();
        push_msg(
            &mut req,
            nft_type(NFT_MSG_GETTABLE),
            NLM_F_REQUEST | NLM_F_ACK,
            1,
            family,
            0,
            &a.buf,
        );
        self.send(&req)?;
        let mut seen = false;
        self.recv_each(|r| match r.ty {
            t if t == nft_type(NFT_MSG_NEWTABLE) => {
                seen = true;
                None
            }
            NLMSG_ERROR => match nlmsgerr(r.payload) {
                0 => Some(Ok(seen)),
                e if -e == libc::ENOENT => Some(Ok(false)),
                e => Some(Err(io::Error::from_raw_os_error(-e))),
            },
            NLMSG_DONE => Some(Ok(seen)),
            _ => None,
        })
    }
}

/// `struct nlmsgerr { int error; ... }`
fn nlmsgerr(payload: &[u8]) -> i32 {
    payload
        .get(..4)
        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
        .unwrap_or(-libc::EBADMSG)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(b: &[u8]) -> Vec<(u16, u16, u32, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < b.len() {
            let len = u32::from_ne_bytes(b[off..off + 4].try_into().unwrap()) as usize;
            assert!(len >= NLMSG_HDR + NFGEN_HDR && off + len <= b.len());
            out.push((
                u16::from_ne_bytes(b[off + 4..off + 6].try_into().unwrap()),
                u16::from_ne_bytes(b[off + 6..off + 8].try_into().unwrap()),
                u32::from_ne_bytes(b[off + 8..off + 12].try_into().unwrap()),
                b[off + 16],
                b[off + 20..off + len].to_vec(),
            ));
            off += pad4(len);
        }
        assert_eq!(off, b.len());
        out
    }

    #[test]
    fn attr_padding_and_nesting() {
        let mut a = AttrBuf::new();
        a.put(1, &[0xaa]); // 5 -> padded to 8
        assert_eq!(a.buf.len(), 8);
        assert_eq!(u16::from_ne_bytes([a.buf[0], a.buf[1]]), 5);
        let n = a.begin(2);
        a.put_u32be(1, 7);
        a.end(n);
        assert_eq!(a.buf.len(), 8 + 4 + 8);
        assert_eq!(u16::from_ne_bytes([a.buf[8], a.buf[9]]), 12);
        assert_eq!(u16::from_ne_bytes([a.buf[10], a.buf[11]]), 2 | NLA_F_NESTED);
        assert_eq!(&a.buf[16..20], &7u32.to_be_bytes());
    }

    #[test]
    fn batch_layout() {
        let mut b = Batch::new();
        b.del_table(NFPROTO_IPV6, "t");
        b.add_table(NFPROTO_IPV6, "t");
        let m = msgs(&b.encode());
        assert_eq!(m.len(), 4);
        assert_eq!(m[0].0, NFNL_MSG_BATCH_BEGIN);
        assert_eq!(
            (m[1].0, m[1].2, m[1].3),
            (nft_type(NFT_MSG_DELTABLE), 2, NFPROTO_IPV6)
        );
        assert_eq!(m[1].1 & NLM_F_CREATE, 0);
        assert_eq!((m[2].0, m[2].2), (nft_type(NFT_MSG_NEWTABLE), 3));
        assert_ne!(m[2].1 & NLM_F_CREATE, 0);
        assert_eq!((m[3].0, m[3].2), (NFNL_MSG_BATCH_END, 4));
        assert_eq!(b.last_seq(), 3);
        // BATCH_BEGIN res_id selects the nftables subsystem (big endian)
        let enc = b.encode();
        assert_eq!(&enc[18..20], &NFNL_SUBSYS_NFTABLES.to_be_bytes());
    }

    #[test]
    fn empty_batch() {
        assert!(Batch::new().is_empty());
    }
}
