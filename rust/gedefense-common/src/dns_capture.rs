//! V6.3.0 AP-6 — bounded DNS query wire contract (`DNS_CAPTURE_EVENTS`).
//!
//! The kernel half (`rust/gedefense-ebpf/src/dns_capture.rs`) observes
//! `syscalls/sys_enter_sendto` and `syscalls/sys_enter_sendmsg`, resolves the
//! destination to UDP port 53 and captures a bounded, verifier-friendly view of
//! the user DNS query. The core (`rust/gedefense-core/src/dns_capture.rs`)
//! converts that view into the presentation QNAME, and the control plane
//! (`control/dns_tunnel.go`) runs the multi-signal tunnelling analysis. The
//! kernel never classifies, never drops and never rewrites a packet or buffer.
//!
//! # Wire layout (64 bytes, native endian, `#[repr(C)]`)
//!
//! ```text
//! offset  size  field
//!      0     8  ts_ns: u64          kernel monotonic timestamp (dedupe/order)
//!      8     4  pid: u32            querying thread id
//!     12     4  tgid: u32           querying process id
//!     16     4  uid: u32
//!     20     2  query_id: u16       DNS transaction id
//!     22     2  qtype: u16          raw IANA QTYPE (0 rejected, !0 preserved)
//!     24     1  flags: u8           FLAG_* subset (bits 5..7 must be zero)
//!     25     1  label_count: u8     0 = derived by the core, 1..=8 reserved
//!     26     1  fqdn_len: u8        full presentation length in chars (1..=62)
//!     27     1  sub_len: u8         stored first-label bytes (1..=12)
//!     28    12  subdomain: [u8;12]  first label prefix (hostname bytes)
//!     40    16  qname_tail: [u8;16] last <=15 QNAME **wire** bytes (len,data,..)
//!     56     8  comm: [u8;8]        printable NUL-padded task name (<=7 chars)
//!     64
//! ```
//!
//! ## Why this shape (verifier-driven)
//!
//! The first implementation of this contract did the whole QNAME parse in the
//! eBPF program (label walk, subdomain copy, label-aligned suffix assembly). It
//! passes `cargo check`, but a real-kernel load on
//! `6.18.33.2-microsoft-standard-WSL2` proved that program **cannot be
//! verified**: dynamic stack indices produced `invalid variable-offset read from
//! stack` / `bitwise operator |= on pointer`, and the nested dynamic loops blew
//! the 1,000,000-instruction verifier budget. The capture was therefore split:
//!
//! - the eBPF program finds the QNAME root with a fully unrolled constant-index
//!   scan and records the presentation length, the first-label prefix and the
//!   last 15 QNAME **wire** bytes. `label_count` is recorded as 0: walking every
//!   label would require a dynamic-position loop that the verifier rejects for
//!   state explosion, and the core derives the label structure from the stored
//!   wire view instead. All kernel buffer accesses use constant masks,
//! - the privileged core parses the wire bytes (phase-resolved label-aligned
//!   tail), converts them to presentation form and rejects every structure the
//!   kernel producer cannot have emitted.
//!
//! The bounded `qname_tail` is what lets the userspace analyser keep the
//! *registrable-domain suffix* (the trailing labels a tunnel keeps constant) even
//! for FQDNs far longer than the 64-byte record: the last 15 QNAME wire bytes
//! always end at the name's root label. When the name is shorter than 15 wire
//! bytes the slot holds the complete QNAME. `wire_len = fqdn_len + 2`, so the
//! stored content length is exactly `min(wire_len, 15)` — no terminator byte is
//! needed and a label byte with value 0 can never truncate the tail.
//!
//! `comm` keeps 7 visible characters (`dnscat2`, `nslookup`, `systemd`, `resolv`)
//! for operator attribution. No reserved byte exists: all 64 bytes are named
//! fields, so a stored record can never leak uninitialised stack bytes.
//!
//! ## Closed-set policy
//!
//! - `qtype` is the raw 16-bit IANA type: `A=1, NS=2, CNAME=5, SOA=6, NULL=10,
//!   PTR=12, MX=15, TXT=16, AAAA=28, SRV=33, ANY=255, CAA=257` are the
//!   documented analysis-relevant types, but *every* non-zero 16-bit value is
//!   preserved instead of rejected (a tunnel can abuse any type; the raw u16
//!   already represents the full domain, so no separate `raw_qtype` is needed).
//!   `0` is invalid and rejected.
//! - The decoder rejects instead of repairing: wrong length, zero
//!   `ts_ns`/`pid`/`tgid`, unknown flag bits, QTYPE 0, impossible label counts
//!   or lengths, non-hostname first-label bytes, non-zero padding after
//!   `sub_len`, a `qname_tail` whose stored length does not match `fqdn_len`, or
//!   a truncation flag that contradicts those lengths. `label_count` is
//!   necessarily 0 here (the kernel producer cannot walk labels under the
//!   verifier budget); a non-zero value is accepted as a future producer form
//!   once the min-length cross-check holds.

mod helpers;

pub use self::helpers::*;

/// Wire size of one [`DnsCaptureEvent`].
pub const DNS_CAPTURE_EVENT_WIRE_BYTES: usize = 64;
/// `DNS_CAPTURE_EVENTS` ring size (64 KiB = 1024 queued 64-byte records).
pub const DNS_CAPTURE_EVENT_RING_BYTES: u32 = 64 * 1024;
/// Maximum records the core returns per drain (bounded control-plane response).
pub const DNS_CAPTURE_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload bytes the core returns per drain.
pub const DNS_CAPTURE_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;

/// Stored first-label bytes (explicit `sub_len`, no NUL required).
pub const DNS_CAPTURE_SUBDOMAIN_BYTES: usize = 12;
/// Stored QNAME wire-tail slot.
pub const DNS_CAPTURE_QNAME_TAIL_BYTES: usize = 16;
/// Maximum QNAME wire bytes the tail slot can hold.
pub const DNS_CAPTURE_MAX_QNAME_TAIL: usize = DNS_CAPTURE_QNAME_TAIL_BYTES - 1;
/// Stored task-name slot (NUL padded, at most 7 chars).
pub const DNS_CAPTURE_COMM_BYTES: usize = 8;
/// Maximum labels the kernel parser walks (fixed verifier loop bound).
pub const DNS_CAPTURE_MAX_LABELS: u8 = 8;
/// Maximum presentation FQDN length representable by the wire: a QNAME with
/// presentation length `n` needs `n + 2` wire bytes, and the kernel capture
/// window is 64 QNAME wire bytes.
pub const DNS_CAPTURE_MAX_FQDN_LEN: u8 = 62;
/// `FQDN length > 50` is one of the five documented tunnelling signals.
pub const DNS_CAPTURE_LONG_FQDN_THRESHOLD: u8 = 50;

// ---------------------------------------------------------------------------
// Event record
// ---------------------------------------------------------------------------

/// One bounded DNS query observation (see the module wire layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsCaptureEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub query_id: u16,
    pub qtype: u16,
    pub flags: u8,
    pub label_count: u8,
    pub fqdn_len: u8,
    pub sub_len: u8,
    pub subdomain: [u8; DNS_CAPTURE_SUBDOMAIN_BYTES],
    pub qname_tail: [u8; DNS_CAPTURE_QNAME_TAIL_BYTES],
    pub comm: [u8; DNS_CAPTURE_COMM_BYTES],
}

// Compile-time coupling to the wire contract: a layout drift must fail the
// eBPF and core builds instead of silently corrupting a ring record.
const _: () = assert!(core::mem::size_of::<DnsCaptureEvent>() == DNS_CAPTURE_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<DnsCaptureEvent>() == 8);

impl DnsCaptureEvent {
    /// Full QNAME wire length (`fqdn_len + 2`); already validated by the decoder.
    pub fn qname_wire_len(&self) -> usize {
        usize::from(self.fqdn_len) + 2
    }

    /// Stored tail bytes (the last `min(wire_len, 15)` QNAME wire bytes).
    pub fn qname_tail_bytes(&self) -> &[u8] {
        let length = dns_capture_tail_len(self.qname_wire_len());
        &self.qname_tail[..length]
    }

    /// Stored subdomain bytes (`sub_len` already validated by the decoder).
    pub fn subdomain_bytes(&self) -> &[u8] {
        let length = usize::from(self.sub_len).min(self.subdomain.len());
        &self.subdomain[..length]
    }

    /// Stored task name up to the first NUL.
    pub fn comm_bytes(&self) -> &[u8] {
        let mut end = 0usize;
        while end < self.comm.len() && self.comm[end] != 0 {
            end += 1;
        }
        &self.comm[..end]
    }
}

/// Encodes one record into its 64-byte wire form. The eBPF producer builds the
/// same bytes field-by-field; this encoder is the canonical form used by tests
/// so the two cannot drift apart.
pub fn encode_dns_capture_event(event: &DnsCaptureEvent) -> [u8; DNS_CAPTURE_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; DNS_CAPTURE_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[8..12].copy_from_slice(&event.pid.to_ne_bytes());
    raw[12..16].copy_from_slice(&event.tgid.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.uid.to_ne_bytes());
    raw[20..22].copy_from_slice(&event.query_id.to_ne_bytes());
    raw[22..24].copy_from_slice(&event.qtype.to_ne_bytes());
    raw[24] = event.flags;
    raw[25] = event.label_count;
    raw[26] = event.fqdn_len;
    raw[27] = event.sub_len;
    raw[28..40].copy_from_slice(&event.subdomain);
    raw[40..56].copy_from_slice(&event.qname_tail);
    raw[56..64].copy_from_slice(&event.comm);
    raw
}

/// True when the `comm` slot is non-empty, printable ASCII and NUL padded.
fn dns_comm_valid(comm: &[u8]) -> bool {
    let mut padded = false;
    let mut seen = 0usize;
    for &byte in comm {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        } else if dns_comm_byte_allowed(byte) {
            seen += 1;
        } else {
            return false;
        }
    }
    padded && seen > 0
}

/// Decodes one fixed-size record; `None` for every record the kernel producer
/// cannot have emitted (see the module-level "Closed-set policy").
///
/// The record is validated *structurally* here (identity, closed sets, lengths,
/// padding, truncation flags). Turning the wire tail into a presentation QNAME
/// and rejecting label-level garbage is done by the core consumer, which has
/// the allocating helpers for it, and a core-side rejection is counted.
pub fn decode_dns_capture_event(bytes: &[u8]) -> Option<DnsCaptureEvent> {
    if bytes.len() != DNS_CAPTURE_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let query_id = u16::from_ne_bytes(bytes[20..22].try_into().ok()?);
    let qtype = u16::from_ne_bytes(bytes[22..24].try_into().ok()?);
    let flags = bytes[24];
    let label_count = bytes[25];
    let fqdn_len = bytes[26];
    let sub_len = bytes[27];
    let subdomain: [u8; DNS_CAPTURE_SUBDOMAIN_BYTES] = bytes[28..40].try_into().ok()?;
    let qname_tail: [u8; DNS_CAPTURE_QNAME_TAIL_BYTES] = bytes[40..56].try_into().ok()?;
    let comm: [u8; DNS_CAPTURE_COMM_BYTES] = bytes[56..64].try_into().ok()?;

    if ts_ns == 0
        || pid == 0
        || tgid == 0
        || qtype == 0
        || flags & !DNS_CAPTURE_FLAGS_ALL != 0
        || !dns_comm_valid(&comm)
    {
        return None;
    }
    if label_count > DNS_CAPTURE_MAX_LABELS || fqdn_len == 0 {
        return None;
    }
    if fqdn_len > DNS_CAPTURE_MAX_FQDN_LEN {
        return None;
    }
    // `label_count == 0` is the shipped producer form (derived by the core);
    // a non-zero future producer form must still satisfy the minimum
    // presentation length for that many labels.
    if label_count > 0 {
        let min_len = 2u16.checked_mul(u16::from(label_count))?.checked_sub(1)?;
        if u16::from(fqdn_len) < min_len {
            return None;
        }
    }

    // Subdomain slot: explicit length, hostname bytes, zero padding after it.
    if sub_len == 0 || usize::from(sub_len) > DNS_CAPTURE_SUBDOMAIN_BYTES {
        return None;
    }
    let sub_len_usize = usize::from(sub_len);
    for (index, &byte) in subdomain.iter().enumerate() {
        if index < sub_len_usize {
            if !dns_label_byte_allowed(byte) {
                return None;
            }
        } else if byte != 0 {
            return None;
        }
    }

    // QNAME tail: exactly `min(wire_len, 15)` stored bytes, zero padded, and the
    // truncation flag must agree with the derived wire length.
    let wire_len = usize::from(fqdn_len) + 2;
    if wire_len > 64 {
        return None;
    }
    let stored_tail = dns_capture_tail_len(wire_len);
    for (index, &byte) in qname_tail.iter().enumerate() {
        if index >= stored_tail && byte != 0 {
            return None;
        }
    }
    let suffix_truncated = flags & DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED != 0;
    if suffix_truncated != (wire_len > DNS_CAPTURE_MAX_QNAME_TAIL) {
        return None;
    }
    let subdomain_truncated = flags & DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED != 0;
    if subdomain_truncated && sub_len_usize != DNS_CAPTURE_SUBDOMAIN_BYTES {
        return None;
    }
    // A fully stored name has exactly `wire_len <= 15` bytes in the tail.
    if !suffix_truncated && stored_tail != wire_len {
        return None;
    }
    let long_fqdn = flags & DNS_CAPTURE_FLAG_LONG_FQDN != 0;
    if long_fqdn != (fqdn_len > DNS_CAPTURE_LONG_FQDN_THRESHOLD) {
        return None;
    }

    Some(DnsCaptureEvent {
        ts_ns,
        pid,
        tgid,
        uid,
        query_id,
        qtype,
        flags,
        label_count,
        fqdn_len,
        sub_len,
        subdomain,
        qname_tail,
        comm,
    })
}

#[cfg(test)]
mod tests;
