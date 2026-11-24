//! Bounded record helpers for the AP-5 persistence ring (child module of
//! `persistence`): per-CPU counter increments, the terminal-safe `comm` slot and
//! the small decimal detail encoder. No allocation, no unbounded loop.

use aya_ebpf::maps::PerCpuArray;

#[inline(always)]
pub(crate) fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for the duration of
        // the update; the per-CPU split resolves cross-CPU races.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Normalises a kernel task name into the wire contract: printable ASCII,
/// non-empty, NUL-padded. Anything else cannot be emitted (the decoder rejects
/// it) and would hide the whole record, so it is replaced by `?`.
#[inline(always)]
pub(crate) fn normalize_comm(comm: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0usize;
    let mut ended = false;
    while index < comm.len() {
        let byte = comm[index];
        if byte == 0 {
            ended = true;
            break;
        }
        out[index] = if (0x20..=0x7e).contains(&byte) { byte } else { b'?' };
        index += 1;
    }
    if !ended {
        // A full 16-byte name has no room for the required terminator.
        out[15] = 0;
    }
    if out[0] == 0 {
        out[0] = b'?';
        out[1] = 0;
    }
    out
}

/// Writes a small decimal (`< 1000`) into the detail slot, NUL-padded.
#[inline(always)]
pub(crate) fn write_small_decimal(value: u32, detail: &mut [u8; 8]) {
    if value < 10 {
        detail[0] = b'0' + value as u8;
        detail[1] = 0;
    } else if value < 100 {
        detail[0] = b'0' + (value / 10) as u8;
        detail[1] = b'0' + (value % 10) as u8;
        detail[2] = 0;
    } else if value < 1000 {
        detail[0] = b'0' + (value / 100) as u8;
        detail[1] = b'0' + ((value / 10) % 10) as u8;
        detail[2] = b'0' + (value % 10) as u8;
        detail[3] = 0;
    } else {
        // The wire contract cannot represent this value: leave the detail empty
        // rather than write a truncated/wrong mode.
        detail[0] = 0;
    }
}
