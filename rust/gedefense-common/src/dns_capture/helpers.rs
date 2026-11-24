//! `DNS_CAPTURE_STATE` word ABI, flag/QTYPE constants and the bounded
//! QNAME/task-name character helpers of the AP-6 contract.

use super::*;

/// `DNS_CAPTURE_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic
/// 40..47, ABI 48..55. An absent/zero word means "not armed".
pub const DNS_CAPTURE_STATE_MAGIC: u8 = 0x44;
pub const DNS_CAPTURE_STATE_ABI: u8 = 1;
pub const DNS_CAPTURE_STATE_ARMED_SHIFT: u64 = 32;
pub const DNS_CAPTURE_STATE_MAGIC_SHIFT: u64 = 40;
pub const DNS_CAPTURE_STATE_ABI_SHIFT: u64 = 48;
pub const DNS_CAPTURE_STATE_BYTE_MASK: u64 = 0xff;

/// `DNS_CAPTURE_COUNTERS` lane indices (`PerCpuArray<u64>`, 4 lanes).
///
/// 0. records submitted to `DNS_CAPTURE_EVENTS`,
/// 1. ring reservations that failed (ring full / closed),
/// 2. kernel-side read/parse failures (user buffer faults, unknown port,
///    malformed DNS header, QNAME longer than the capture window, ...),
/// 3. UDP/53 probes observed while armed (denominator for layer 2).
pub const DNS_CAPTURE_COUNTER_LANES: u32 = 4;
pub const DNS_CAPTURE_COUNTER_EMITTED: u32 = 0;
pub const DNS_CAPTURE_COUNTER_RING_DROPS: u32 = 1;
pub const DNS_CAPTURE_COUNTER_READ_FAILURES: u32 = 2;
pub const DNS_CAPTURE_COUNTER_PROBES: u32 = 3;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// DNS header `RD` (recursion desired) bit as observed on the query.
pub const DNS_CAPTURE_FLAG_RD: u8 = 1 << 0;
/// Captured through `sendmsg` (clear: `sendto`).
pub const DNS_CAPTURE_FLAG_VIA_SENDMSG: u8 = 1 << 1;
/// The *full* FQDN presentation length exceeds
/// [`DNS_CAPTURE_LONG_FQDN_THRESHOLD`]; cross-checked against `fqdn_len`.
pub const DNS_CAPTURE_FLAG_LONG_FQDN: u8 = 1 << 2;
/// The first label was longer than [`DNS_CAPTURE_SUBDOMAIN_BYTES`].
pub const DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED: u8 = 1 << 3;
/// The QNAME is longer than the 15-byte tail slot (`wire_len > 15`); the tail
/// then starts inside a label and the core resolves the label phase.
pub const DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED: u8 = 1 << 4;
/// Every flag bit the ABI defines; bits 5..7 must stay zero.
pub const DNS_CAPTURE_FLAGS_ALL: u8 = DNS_CAPTURE_FLAG_RD
    | DNS_CAPTURE_FLAG_VIA_SENDMSG
    | DNS_CAPTURE_FLAG_LONG_FQDN
    | DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED
    | DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED;

// ---------------------------------------------------------------------------
// QTYPEs
// ---------------------------------------------------------------------------

pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QTYPE_NS: u16 = 2;
pub const DNS_QTYPE_CNAME: u16 = 5;
pub const DNS_QTYPE_SOA: u16 = 6;
/// `NULL` records: classic covert-channel container, one of the two
/// `TXT/NULL`-share types.
pub const DNS_QTYPE_NULL: u16 = 10;
pub const DNS_QTYPE_PTR: u16 = 12;
pub const DNS_QTYPE_MX: u16 = 15;
/// `TXT` records: the dominant covert-channel container.
pub const DNS_QTYPE_TXT: u16 = 16;
pub const DNS_QTYPE_AAAA: u16 = 28;
pub const DNS_QTYPE_SRV: u16 = 33;
pub const DNS_QTYPE_ANY: u16 = 255;
pub const DNS_QTYPE_CAA: u16 = 257;

/// True for the documented analysis-relevant QTYPE set. This is a
/// *classification* helper only: the decoder preserves every non-zero raw
/// QTYPE instead of rejecting types outside the set.
#[inline(always)]
pub const fn dns_qtype_known(qtype: u16) -> bool {
    matches!(
        qtype,
        1 | 2 | 5 | 6 | 10 | 12 | 15 | 16 | 28 | 33 | 255 | 257
    )
}

/// True for the two covert-channel container types counted by the
/// `TXT/NULL share > 10 %` signal.
#[inline(always)]
pub const fn dns_qtype_is_txt_or_null(qtype: u16) -> bool {
    qtype == DNS_QTYPE_TXT || qtype == DNS_QTYPE_NULL
}

// ---------------------------------------------------------------------------
// State word
// ---------------------------------------------------------------------------

/// Packs the `DNS_CAPTURE_STATE` word (epoch | armed | magic | ABI).
#[inline(always)]
pub const fn dns_capture_state_word(epoch: u32, armed: bool) -> u64 {
    (epoch as u64)
        | ((armed as u64) << DNS_CAPTURE_STATE_ARMED_SHIFT)
        | ((DNS_CAPTURE_STATE_MAGIC as u64) << DNS_CAPTURE_STATE_MAGIC_SHIFT)
        | ((DNS_CAPTURE_STATE_ABI as u64) << DNS_CAPTURE_STATE_ABI_SHIFT)
}

/// True only for an armed, magic/ABI-valid state word. Both tracepoints check
/// this before reading any user memory.
#[inline(always)]
pub const fn dns_capture_state_armed(word: u64) -> bool {
    let magic = ((word >> DNS_CAPTURE_STATE_MAGIC_SHIFT) & DNS_CAPTURE_STATE_BYTE_MASK) as u8;
    let abi = ((word >> DNS_CAPTURE_STATE_ABI_SHIFT) & DNS_CAPTURE_STATE_BYTE_MASK) as u8;
    let armed = (word >> DNS_CAPTURE_STATE_ARMED_SHIFT) & 1;
    magic == DNS_CAPTURE_STATE_MAGIC && abi == DNS_CAPTURE_STATE_ABI && armed == 1
}

// ---------------------------------------------------------------------------
// Character classes
// ---------------------------------------------------------------------------

/// One byte of a DNS label as the capture accepts it: letters, digits, hyphen
/// and underscore (underscore covers service/SRV labels; no dot, no escape).
#[inline(always)]
pub const fn dns_label_byte_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// One printable task-name byte (the producer normalises everything else to
/// `?` before writing, so a control byte cannot have been emitted).
#[inline(always)]
pub(super) const fn dns_comm_byte_allowed(byte: u8) -> bool {
    byte >= 0x20 && byte <= 0x7e
}

/// Number of QNAME wire bytes stored in `qname_tail` for one record:
/// `min(wire_len, DNS_CAPTURE_MAX_QNAME_TAIL)`.
#[inline(always)]
pub const fn dns_capture_tail_len(wire_len: usize) -> usize {
    if wire_len < DNS_CAPTURE_MAX_QNAME_TAIL {
        wire_len
    } else {
        DNS_CAPTURE_MAX_QNAME_TAIL
    }
}
