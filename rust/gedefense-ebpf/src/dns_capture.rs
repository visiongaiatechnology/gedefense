//! V6.3.0 AP-6 — bounded DNS query capture (eBPF half).
//!
//! Programs:
//! - [`gedefense_dns_sendto`] on `syscalls/sys_enter_sendto`,
//! - [`gedefense_dns_sendmsg`] on `syscalls/sys_enter_sendmsg`.
//!
//! Both are observe-only: they never rewrite or drop a packet, never touch the
//! syscall's return value and emit at most one 64-byte record per UDP/53
//! `sendto`/`sendmsg`. A record is emitted only while [`DNS_CAPTURE_STATE`] is
//! magic/ABI-valid and armed; a disarmed (or absent) word makes both programs
//! return after the state read.
//!
//! # Tracepoint offsets (verified against the real WSL2 kernel)
//!
//! Read from `/sys/kernel/tracing/events/syscalls/sys_enter_sendto/format` and
//! `.../sys_enter_sendmsg/format` on Ubuntu-24.04 / kernel
//! `6.18.33.2-microsoft-standard-WSL2` (WSL2):
//!
//! ```text
//! sys_enter_sendto:  fd@16  buff@24  len@32  flags@40  addr@48  addr_len@56
//! sys_enter_sendmsg: fd@16  msg@24   flags@32
//! ```
//!
//! (`__syscall_nr` sits at offset 8 and is not read; every argument occupies an
//! 8-byte slot, exactly like the established `xdr_kernel.rs` readers.) The
//! syscall argument is the *userspace* address, so all payload reads go through
//! `bpf_probe_read_user`.
//!
//! # Userspace structures (x86_64 UAPI layout, never trusted blindly)
//!
//! `sendto` hands over a `struct sockaddr *`: `sa_family_t` (`u16`, native) at
//! offset 0 and the network-order port at offset 2 in both `sockaddr_in` and
//! `sockaddr_in6`; only the 16-byte head is read. `sendmsg` hands over a
//! `struct user_msghdr *` (`msg_name` at 0, `msg_namelen` at 8, `msg_iov` at 16,
//! `msg_iovlen` at 24) and the first `iovec` (`iov_base` at 0, `iov_len` at 8).
//!
//! **Documented fallback:** a connected UDP socket has `msg_name == NULL` and no
//! destination in the syscall; the port cannot be determined, so nothing is
//! emitted and [`DNS_CAPTURE_COUNTER_READ_FAILURES`] is incremented. Multi-iovec
//! messages are not stitched: only `iov[0]` is inspected and a message whose DNS
//! header does not fit is a counted read failure (no partial record is emitted).
//!
//! # Verifier-driven capture shape
//!
//! A real-kernel load (`6.18.33.2-microsoft-standard-WSL2`) proved that a full
//! in-kernel QNAME parse (per-label walks, label-aligned suffix assembly) cannot
//! be verified: dynamic stack indices are rejected
//! (`invalid variable-offset read from stack`, `bitwise operator |= on pointer`)
//! and the nested dynamic loops exhaust the 1,000,000-instruction verifier
//! budget. This program therefore captures a **bounded split view** without any
//! dynamic-position loop and records:
//!
//! - the QNAME wire length (`fqdn_len = wire_len - 2`) found by a fully unrolled,
//!   constant-index scan for the root label byte,
//! - the first-label prefix (hostname bytes only, unrolled constant-index copy),
//! - the last `min(wire_len, 15)` QNAME **wire** bytes.
//!
//! `label_count` is recorded as 0 ("derived by the core"): walking every label
//! needs a dynamic-position loop that the verifier rejects for state explosion.
//! All variable-order buffer accesses go through one per-CPU map value
//! ([`DNS_CAPTURE_SCRATCH`]); there is no dynamic BPF-stack indexing at all. The
//! privileged core turns the wire tail into the presentation, label-aligned
//! registrable suffix (see `gedefense_common::dns_capture`), which is what the
//! multi-signal analysis needs for long tunnel FQDNs.
//!
//! Bounded DNS parsing: `QDCOUNT >= 1`, `QR == 0`, `OPCODE == 0`, a first label
//! of `1..=63` bytes with hostname bytes only, the first zero byte (root) inside
//! the 64-byte window, and `QTYPE != 0`. No allocation, no static tables, no
//! unbounded loops.
//!
//! Maps:
//! - `DNS_CAPTURE_STATE`: `Array<u64>` (epoch | armed | magic `0x44` | ABI 1),
//! - `DNS_CAPTURE_EVENTS`: `RingBuf` 64 KiB = 1024 queued records,
//! - `DNS_CAPTURE_COUNTERS`: `PerCpuArray<u64>` with the four documented lanes
//!   (`emitted`, `ring drops`, `read failures`, `probes`),
//! - `DNS_CAPTURE_SCRATCH`: `PerCpuArray<DnsParseScratch>` parse scratch (QNAME
//!   window, first-label prefix and wire tail).


use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use gedefense_common::{
    dns_capture_tail_len, dns_label_byte_allowed, DnsCaptureEvent, DNS_CAPTURE_COMM_BYTES,
    DNS_CAPTURE_COUNTER_LANES, DNS_CAPTURE_COUNTER_READ_FAILURES, DNS_CAPTURE_EVENT_RING_BYTES,
    DNS_CAPTURE_EVENT_WIRE_BYTES, DNS_CAPTURE_FLAG_LONG_FQDN,
    DNS_CAPTURE_FLAG_RD, DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED, DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED,
    DNS_CAPTURE_FLAG_VIA_SENDMSG, DNS_CAPTURE_LONG_FQDN_THRESHOLD, DNS_CAPTURE_MAX_FQDN_LEN,
    DNS_CAPTURE_MAX_QNAME_TAIL, DNS_CAPTURE_QNAME_TAIL_BYTES, DNS_CAPTURE_SUBDOMAIN_BYTES,
    SEC_CRIT_BUCKET_DNS,
};
use crate::sec_crit::{
    telemetry_budget_allow, telemetry_current_cgroup_id, telemetry_note_suppressed,
};

use emit::{bump, comm_slot, submit};
use parse::find_qname_root;
use syscall::{try_sendmsg, try_sendto};

mod emit;
mod parse;
mod syscall;

/// DNS header bytes copied before the QNAME window.
const DNS_HEADER_BYTES: usize = 12;
/// Maximum QNAME wire bytes captured (presentation length + 2).
const DNS_QNAME_WINDOW_BYTES: usize = 64;
/// `QR` / opcode / recursion-desired bits of the DNS header flags field.
const DNS_HEADER_QR: u16 = 0x8000;
const DNS_HEADER_OPCODE_MASK: u16 = 0x7800;
const DNS_HEADER_RD: u16 = 0x0100;

/// Constant array-bound masks (the only bounds the verifier must prove).
const WINDOW_MASK: usize = DNS_QNAME_WINDOW_BYTES - 1;
const TAIL_MASK: usize = DNS_CAPTURE_QNAME_TAIL_BYTES - 1;

/// Per-CPU parse scratch. Variable-order buffer reads live in a map value
/// instead of the BPF stack on purpose: the eBPF verifier rejects variable
/// stack offsets it cannot see and LLVM turns fixed-frame + masked-index stack
/// accesses into pointer bitwise-ORs ("bitwise operator |= on pointer
/// prohibited"). A map value base is opaque to LLVM, so a masked index stays a
/// plain pointer add while the verifier still proves the offset range against
/// the constant value size.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DnsParseScratch {
    window: [u8; DNS_QNAME_WINDOW_BYTES],
    subdomain: [u8; DNS_CAPTURE_SUBDOMAIN_BYTES],
    qname_tail: [u8; DNS_CAPTURE_QNAME_TAIL_BYTES],
}

const _: () = assert!(
    DNS_CAPTURE_SUBDOMAIN_BYTES + DNS_CAPTURE_QNAME_TAIL_BYTES + DNS_CAPTURE_COMM_BYTES + 28 == 64
);

#[map]
pub(crate) static DNS_CAPTURE_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static DNS_CAPTURE_EVENTS: RingBuf =
    RingBuf::with_byte_size(DNS_CAPTURE_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static DNS_CAPTURE_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(DNS_CAPTURE_COUNTER_LANES, 0);
#[map]
pub(crate) static DNS_CAPTURE_SCRATCH: PerCpuArray<DnsParseScratch> =
    PerCpuArray::with_max_entries(1, 0);

const _: () = assert!(core::mem::size_of::<DnsCaptureEvent>() == DNS_CAPTURE_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<DnsCaptureEvent>() <= 8);

/// Copies and parses one DNS query from a userspace buffer and emits one
/// bounded record. `None` (after counting a read failure) for anything the
/// capture cannot prove, so no partial or guessed record enters the ring.
#[inline(always)]
fn capture_user_query(buf_ptr: u64, length: u64, via_sendmsg: bool) -> Option<()> {
    if buf_ptr == 0 || length < (DNS_HEADER_BYTES + 2) as u64 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let mut header = [0u8; DNS_HEADER_BYTES];
    if unsafe { bpf_probe_read_user_buf(buf_ptr as *const u8, &mut header) }.is_err() {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let query_id = u16::from_be_bytes([header[0], header[1]]);
    let dns_flags = u16::from_be_bytes([header[2], header[3]]);
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    // Queries only; the opcode is bounded to standard QUERY because the QNAME
    // position/semantics differ for UPDATE, NOTIFY, etc.
    if dns_flags & DNS_HEADER_QR != 0 || dns_flags & DNS_HEADER_OPCODE_MASK != 0 || qdcount < 1 {
        return None;
    }
    // Bytes after the 12-byte header that the syscall actually supplied, clamped
    // to the fixed capture window.
    let supplied = length - DNS_HEADER_BYTES as u64;
    let clamped = if supplied > DNS_QNAME_WINDOW_BYTES as u64 {
        DNS_QNAME_WINDOW_BYTES
    } else {
        supplied as usize
    };
    if clamped < 2 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }

    let Some(scratch_ptr) = DNS_CAPTURE_SCRATCH.get_ptr_mut(0) else {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    };
    // SAFETY: per-CPU scratch index 0 is owned by the current CPU for this hook.
    let scratch = unsafe { &mut *scratch_ptr };
    scratch.window = [0u8; DNS_QNAME_WINDOW_BYTES];
    scratch.subdomain = [0u8; DNS_CAPTURE_SUBDOMAIN_BYTES];
    scratch.qname_tail = [0u8; DNS_CAPTURE_QNAME_TAIL_BYTES];
    if unsafe {
        bpf_probe_read_user_buf(
            buf_ptr.wrapping_add(DNS_HEADER_BYTES as u64) as *const u8,
            &mut scratch.window,
        )
    }
    .is_err()
    {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let wire_len = match find_qname_root(scratch, clamped) {
        Some(value) => value,
        None => {
            bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
            return None;
        }
    };
    // The first QNAME byte is the first label's length byte (constant offset 0);
    // following a QNAME label walk is not needed for the split capture, and
    // `label_count` is therefore recorded as 0 ("derived by the core") — see the
    // ABI note in `gedefense_common::dns_capture`.
    let first_len = usize::from(scratch.window[0]);
    if wire_len < 3 || first_len == 0 || first_len > 63 || 1 + first_len > wire_len - 1 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    if wire_len + 2 > clamped || wire_len < 3 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    if wire_len - 2 > usize::from(DNS_CAPTURE_MAX_FQDN_LEN) {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }

    // QTYPE follows the QNAME; read it straight from user memory so no
    // variable-offset stack access is needed.
    let qtype_raw: [u8; 2] = match unsafe {
        bpf_probe_read_user(
            buf_ptr
                .wrapping_add(DNS_HEADER_BYTES as u64)
                .wrapping_add(wire_len as u64) as *const [u8; 2],
        )
    } {
        Ok(bytes) => bytes,
        Err(_) => {
            bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
            return None;
        }
    };
    let qtype = u16::from_be_bytes(qtype_raw);
    if qtype == 0 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }

    // First label prefix (hostname bytes only; bounded constant loop).
    let stored_subdomain = if first_len > DNS_CAPTURE_SUBDOMAIN_BYTES {
        DNS_CAPTURE_SUBDOMAIN_BYTES
    } else {
        first_len
    };
    // First-label prefix: copied from the captured window with **fully
    // unrolled constant indices** (window byte `1 + i`, subdomain slot `i`).
    // Constant indices keep both the verifier and the optimiser simple; every
    // retained byte is validated as a hostname byte and the slot is zero padded
    // past the stored length.
    macro_rules! copy_subdomain_byte {
        ($index:expr) => {{
            if $index < stored_subdomain {
                let byte = scratch.window[(1 + $index) & WINDOW_MASK];
                if !dns_label_byte_allowed(byte) {
                    bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
                    return None;
                }
                scratch.subdomain[$index] = byte;
            } else {
                scratch.subdomain[$index] = 0;
            }
        }};
    }
    copy_subdomain_byte!(0);
    copy_subdomain_byte!(1);
    copy_subdomain_byte!(2);
    copy_subdomain_byte!(3);
    copy_subdomain_byte!(4);
    copy_subdomain_byte!(5);
    copy_subdomain_byte!(6);
    copy_subdomain_byte!(7);
    copy_subdomain_byte!(8);
    copy_subdomain_byte!(9);
    copy_subdomain_byte!(10);
    copy_subdomain_byte!(11);

    // QNAME tail: the last `min(wire_len, 15)` wire bytes, zero padded. The
    // fixed 15/16-byte helper copy may over-read into the rest of the DNS
    // message (still user memory) and the padding is restored from `tail_len`,
    // so the record contains exactly the documented content.
    let tail_len = dns_capture_tail_len(wire_len);
    let tail_start = wire_len - tail_len;
    if unsafe {
        bpf_probe_read_user_buf(
            buf_ptr
                .wrapping_add(DNS_HEADER_BYTES as u64)
                .wrapping_add(tail_start as u64) as *const u8,
            &mut scratch.qname_tail,
        )
    }
    .is_err()
    {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let mut pad_index = 0usize;
    while pad_index < DNS_CAPTURE_QNAME_TAIL_BYTES {
        if pad_index >= tail_len {
            scratch.qname_tail[pad_index & TAIL_MASK] = 0;
        }
        pad_index += 1;
    }

    let fqdn_len = wire_len - 2;
    let mut flags = 0u8;
    if dns_flags & DNS_HEADER_RD != 0 {
        flags |= DNS_CAPTURE_FLAG_RD;
    }
    if via_sendmsg {
        flags |= DNS_CAPTURE_FLAG_VIA_SENDMSG;
    }
    if fqdn_len > usize::from(DNS_CAPTURE_LONG_FQDN_THRESHOLD) {
        flags |= DNS_CAPTURE_FLAG_LONG_FQDN;
    }
    if first_len > DNS_CAPTURE_SUBDOMAIN_BYTES {
        flags |= DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED;
    }
    if wire_len > DNS_CAPTURE_MAX_QNAME_TAIL {
        flags |= DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED;
    }

    let ts_ns = unsafe { bpf_ktime_get_ns() };
    if ts_ns == 0 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if pid == 0 || tgid == 0 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    // V6.3.0 AP-9 (S12): bounded DNS capture is bulk telemetry; a flooding
    // cgroup/uid is throttled per class before the record is submitted, and the
    // refusal is counted in both suppression counters (never silent).
    if !telemetry_budget_allow(
        SEC_CRIT_BUCKET_DNS,
        telemetry_current_cgroup_id(),
        uid,
    ) {
        telemetry_note_suppressed(SEC_CRIT_BUCKET_DNS);
        return None;
    }
    submit(DnsCaptureEvent {
        ts_ns,
        pid,
        tgid,
        uid,
        query_id,
        qtype,
        flags,
        label_count: 0,
        fqdn_len: fqdn_len as u8,
        sub_len: stored_subdomain as u8,
        subdomain: scratch.subdomain,
        qname_tail: scratch.qname_tail,
        comm: comm_slot(),
    });
    Some(())
}

#[tracepoint]
pub fn gedefense_dns_sendto(ctx: TracePointContext) -> u32 {
    let _ = try_sendto(&ctx);
    0
}

#[tracepoint]
pub fn gedefense_dns_sendmsg(ctx: TracePointContext) -> u32 {
    let _ = try_sendmsg(&ctx);
    0
}
