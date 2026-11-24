//! Bounded record/state helpers of the AP-6 DNS capture (child module of
//! `dns_capture`): armed-state gate, terminal-safe `comm` slot, ring submission
//! and the per-CPU counter lanes.

use aya_ebpf::helpers::bpf_get_current_comm;
use gedefense_common::{
    dns_capture_state_armed, DnsCaptureEvent, DNS_CAPTURE_COMM_BYTES, DNS_CAPTURE_COUNTER_EMITTED,
    DNS_CAPTURE_COUNTER_RING_DROPS, DNS_CAPTURE_STATE_ABI, DNS_CAPTURE_STATE_ABI_SHIFT,
    DNS_CAPTURE_STATE_ARMED_SHIFT, DNS_CAPTURE_STATE_BYTE_MASK, DNS_CAPTURE_STATE_MAGIC,
    DNS_CAPTURE_STATE_MAGIC_SHIFT,
};

use super::{DNS_CAPTURE_COUNTERS, DNS_CAPTURE_EVENTS, DNS_CAPTURE_STATE};

/// Index of the single `DNS_CAPTURE_STATE` word.
const DNS_CAPTURE_STATE_INDEX: u32 = 0;

#[inline(always)]
pub(crate) fn bump(lane: u32) {
    if let Some(counter) = DNS_CAPTURE_COUNTERS.get_ptr_mut(lane) {
        // SAFETY: per-CPU array lane is owned by this CPU for this update.
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}

/// Reads and validates the capture state word. Absent/foreign/stale = disarmed.
#[inline(always)]
pub(crate) fn capture_armed() -> bool {
    match DNS_CAPTURE_STATE.get(DNS_CAPTURE_STATE_INDEX) {
        Some(word) => dns_capture_state_armed(*word),
        None => false,
    }
}

/// Bounded, printable task name for the record. Non-printable bytes become
/// `?` (terminal-injection guard on every operator surface) and the slot is
/// always NUL padded; an unreadable comm still emits `?` instead of dropping a
/// successfully captured query.
#[inline(always)]
pub(crate) fn comm_slot() -> [u8; DNS_CAPTURE_COMM_BYTES] {
    let mut out = [0u8; DNS_CAPTURE_COMM_BYTES];
    match bpf_get_current_comm() {
        Ok(raw) => {
            let mut index = 0usize;
            while index < DNS_CAPTURE_COMM_BYTES - 1 && index < raw.len() {
                let byte = raw[index];
                if byte == 0 {
                    break;
                }
                out[index] = if byte < 0x20 || byte == 0x7f || byte >= 0x80 {
                    b'?'
                } else {
                    byte
                };
                index += 1;
            }
            if index == 0 {
                out[0] = b'?';
            }
        }
        Err(_) => {
            out[0] = b'?';
        }
    }
    out
}

#[inline(always)]
pub(crate) fn submit(event: DnsCaptureEvent) {
    if let Some(mut entry) = DNS_CAPTURE_EVENTS.reserve::<DnsCaptureEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<DnsCaptureEvent>()
        // bytes, 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        bump(DNS_CAPTURE_COUNTER_EMITTED);
    } else {
        // Ring full or closed: the query is lost and the loss is counted, never
        // silently hidden.
        bump(DNS_CAPTURE_COUNTER_RING_DROPS);
    }
}

/// Compile-time coupling: the state-word ABI constants used by the core are the
/// ones this module reads. A drift fails the eBPF build instead of silently
/// disabling the capture.
const _: () = assert!(DNS_CAPTURE_STATE_MAGIC == 0x44);
const _: () = assert!(DNS_CAPTURE_STATE_ABI == 1);
const _: () = assert!(DNS_CAPTURE_STATE_ARMED_SHIFT == 32);
const _: () = assert!(DNS_CAPTURE_STATE_MAGIC_SHIFT == 40);
const _: () = assert!(DNS_CAPTURE_STATE_ABI_SHIFT == 48);
const _: () = assert!(DNS_CAPTURE_STATE_BYTE_MASK == 0xff);
