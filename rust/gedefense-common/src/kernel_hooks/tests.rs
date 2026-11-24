use super::*;
use core::mem::{align_of, offset_of, size_of};

fn encode(event: &KernelHookEvent) -> [u8; KERNEL_HOOK_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; KERNEL_HOOK_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[8..12].copy_from_slice(&event.pid.to_ne_bytes());
    raw[12..16].copy_from_slice(&event.tgid.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.uid.to_ne_bytes());
    raw[20] = event.kind;
    raw[21] = event.action;
    raw[22] = event.detail_len;
    raw[23] = event.reserved;
    raw[24..28].copy_from_slice(&event.detail_code.to_ne_bytes());
    raw[28..48].copy_from_slice(&event.detail);
    raw[48..64].copy_from_slice(&event.comm);
    raw
}

fn sample_create() -> KernelHookEvent {
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    detail[0..4].copy_from_slice(&0x0000_8020u32.to_ne_bytes());
    KernelHookEvent {
        ts_ns: 1_700_000_000_000_000_000,
        pid: 4242,
        tgid: 4241,
        uid: 1000,
        kind: KERNEL_HOOK_KIND_IO_URING_CREATE,
        action: KERNEL_HOOK_ACTION_AUDIT,
        detail_len: 4,
        reserved: 0,
        detail_code: 7,
        detail,
        comm: *b"fio\0\0\0\0\0\0\0\0\0\0\0\0\0",
    }
}

fn sample_module_load() -> KernelHookEvent {
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let name = b"evil_lkm";
    detail[..name.len()].copy_from_slice(name);
    KernelHookEvent {
        ts_ns: 1_700_000_000_000_000_001,
        pid: 500,
        tgid: 500,
        uid: 0,
        kind: KERNEL_HOOK_KIND_MODULE_LOAD,
        action: KERNEL_HOOK_ACTION_AUDIT,
        detail_len: name.len() as u8,
        reserved: 0,
        detail_code: 0,
        detail,
        comm: *b"insmod\0\0\0\0\0\0\0\0\0\0",
    }
}

fn identity_only(kind: u8) -> KernelHookEvent {
    KernelHookEvent {
        ts_ns: 1_700_000_000_000_000_002,
        pid: 91,
        tgid: 91,
        uid: 0,
        kind,
        action: KERNEL_HOOK_ACTION_AUDIT,
        detail_len: 0,
        reserved: 0,
        detail_code: 0,
        detail: [0u8; KERNEL_HOOK_DETAIL_BYTES],
        comm: *b"kworker\0\0\0\0\0\0\0\0\0",
    }
}

#[test]
fn wire_layout_matches_the_64_byte_contract() {
    assert_eq!(size_of::<KernelHookEvent>(), KERNEL_HOOK_EVENT_WIRE_BYTES);
    assert_eq!(align_of::<KernelHookEvent>(), 8);
    assert_eq!(offset_of!(KernelHookEvent, ts_ns), 0);
    assert_eq!(offset_of!(KernelHookEvent, pid), 8);
    assert_eq!(offset_of!(KernelHookEvent, tgid), 12);
    assert_eq!(offset_of!(KernelHookEvent, uid), 16);
    assert_eq!(offset_of!(KernelHookEvent, kind), 20);
    assert_eq!(offset_of!(KernelHookEvent, action), 21);
    assert_eq!(offset_of!(KernelHookEvent, detail_len), 22);
    assert_eq!(offset_of!(KernelHookEvent, reserved), 23);
    assert_eq!(offset_of!(KernelHookEvent, detail_code), 24);
    assert_eq!(offset_of!(KernelHookEvent, detail), 28);
    assert_eq!(offset_of!(KernelHookEvent, comm), 48);
    // No implicit padding: the named fields cover every one of the 64 bytes,
    // so a stored record cannot leak uninitialised stack bytes.
    assert_eq!(
        offset_of!(KernelHookEvent, comm) + KERNEL_HOOK_COMM_BYTES,
        KERNEL_HOOK_EVENT_WIRE_BYTES
    );
    assert_eq!(KERNEL_HOOK_EVENT_RING_BYTES as usize / KERNEL_HOOK_EVENT_WIRE_BYTES, 1024);
    assert_eq!(KERNEL_HOOK_DETAIL_BYTES, 20);
    assert_eq!(KERNEL_HOOK_COMM_BYTES, 16);
    assert_eq!(KERNEL_HOOK_MAX_EVENTS_PER_DRAIN, 16);
    assert_eq!(KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES, 4096);
}

#[test]
fn decoder_roundtrips_every_kind() {
    for event in [sample_create(), sample_module_load()] {
        assert_eq!(decode_kernel_hook_event(&encode(&event)), Some(event));
    }
    for kind in 1..=KERNEL_HOOK_MAX_KIND {
        let event = identity_only(kind);
        assert_eq!(
            decode_kernel_hook_event(&encode(&event)),
            Some(event),
            "kind {kind}"
        );
    }
}

#[test]
fn decoder_rejects_records_the_kernel_cannot_have_emitted() {
    let good = encode(&sample_create());
    for length in [0usize, 1, 32, 63] {
        assert!(decode_kernel_hook_event(&good[..length]).is_none(), "{length}");
    }
    let mut extra = [0u8; KERNEL_HOOK_EVENT_WIRE_BYTES + 1];
    extra[..KERNEL_HOOK_EVENT_WIRE_BYTES].copy_from_slice(&good);
    assert!(decode_kernel_hook_event(&extra).is_none());

    let mut bad = sample_create();
    bad.ts_ns = 0;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.pid = 0;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.tgid = 0;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.reserved = 1;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.kind = 0;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.kind = KERNEL_HOOK_MAX_KIND + 1;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.action = 0;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.action = 3;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    bad = sample_create();
    bad.detail_len = (KERNEL_HOOK_DETAIL_BYTES + 1) as u8;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    // A non-zero byte behind the declared detail length is a producer bug
    // (the sample create flags are 0x0000_8020, so LE byte 1 is non-zero).
    bad = sample_create();
    bad.detail_len = 1;
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    // A comm without a NUL terminator cannot be produced.
    bad = sample_create();
    bad.comm = [b'x'; KERNEL_HOOK_COMM_BYTES];
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
    // Bytes after the NUL must all be zero.
    bad = sample_create();
    bad.comm[4] = b'x';
    assert!(decode_kernel_hook_event(&encode(&bad)).is_none());
}

#[test]
fn decoder_accepts_the_closed_deny_token_the_producer_never_emits() {
    let mut event = identity_only(KERNEL_HOOK_KIND_LSM_URING_CMD);
    event.action = KERNEL_HOOK_ACTION_DENY;
    assert_eq!(decode_kernel_hook_event(&encode(&event)), Some(event));
}

#[test]
fn kinds_are_the_specified_closed_set() {
    assert_eq!(KERNEL_HOOK_KIND_IO_URING_CREATE, 1);
    assert_eq!(KERNEL_HOOK_KIND_IO_URING_REGISTER, 2);
    assert_eq!(KERNEL_HOOK_KIND_IO_URING_SUBMIT, 3);
    assert_eq!(KERNEL_HOOK_KIND_MODULE_LOAD, 4);
    assert_eq!(KERNEL_HOOK_KIND_MODULE_FINIT, 5);
    assert_eq!(KERNEL_HOOK_KIND_MODULE_DELETE, 6);
    assert_eq!(KERNEL_HOOK_KIND_LSM_URING_OVERRIDE_CREDS, 7);
    assert_eq!(KERNEL_HOOK_KIND_LSM_URING_SQPOLL, 8);
    assert_eq!(KERNEL_HOOK_KIND_LSM_URING_CMD, 9);
    assert_eq!(KERNEL_HOOK_KIND_LKM_TAINT, 10);
    assert_eq!(KERNEL_HOOK_MAX_KIND, KERNEL_HOOK_KIND_LKM_TAINT);
    assert_eq!(KERNEL_HOOK_ACTION_AUDIT, 1);
    assert_eq!(KERNEL_HOOK_ACTION_DENY, 2);
    // The kind set is contiguous: no gap can be produced or accepted.
    let mut kind = 1u8;
    while kind <= KERNEL_HOOK_MAX_KIND {
        let event = identity_only(kind);
        assert!(decode_kernel_hook_event(&encode(&event)).is_some());
        kind += 1;
    }
}

#[test]
fn offset_slots_are_distinct_and_bounded() {
    let slots = [
        KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD,
        KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS,
        KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE,
        KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES,
        KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE,
        KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS,
        KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME,
    ];
    for (index, slot) in slots.iter().enumerate() {
        assert_eq!(*slot as usize, index);
        assert!(*slot < KERNEL_HOOK_OFFSET_SLOTS);
    }
    // Slot 7 is reserved for a future field and must stay unassigned.
    assert!(!slots.contains(&7));
    assert_eq!(KERNEL_HOOK_OFFSET_SLOTS, 8);
    assert!(KERNEL_HOOK_MAX_RECORD_OFFSET <= u32::from(u16::MAX));
    assert_eq!(KERNEL_HOOK_WINDOW_ENTRIES, 4096);
    assert_eq!(KERNEL_HOOK_WINDOW_NS, 1_000_000_000);
}

#[test]
fn state_word_is_armed_only_for_the_current_magic_abi_and_armed_bit() {
    let word = kernel_hook_state_word(0xdead_beef, true, KERNEL_HOOK_FLAG_ALL);
    assert!(kernel_hook_state_armed(word));
    assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
    assert_eq!(kernel_hook_state_flags(word), KERNEL_HOOK_FLAG_ALL);
    assert_eq!(
        (word >> KERNEL_HOOK_STATE_MAGIC_SHIFT) & KERNEL_HOOK_STATE_BYTE_MASK,
        u64::from(KERNEL_HOOK_STATE_MAGIC)
    );
    assert_eq!(
        (word >> KERNEL_HOOK_STATE_ABI_SHIFT) & KERNEL_HOOK_STATE_BYTE_MASK,
        u64::from(KERNEL_HOOK_STATE_ABI)
    );
    assert!(!kernel_hook_state_armed(kernel_hook_state_word(1, false, 0)));
    assert!(!kernel_hook_state_armed(0));
    assert!(!kernel_hook_state_armed(u64::MAX));
    assert!(!kernel_hook_state_armed(0));
    assert_eq!(kernel_hook_state_flags(0), 0);
    // The armed check ignores producer flags: they are metadata, not a gate.
    assert!(kernel_hook_state_armed(kernel_hook_state_word(7, true, 0)));
    assert!(kernel_hook_state_armed(kernel_hook_state_word(
        7,
        true,
        KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS
    )));
    let mut foreign = word;
    foreign &= !(0xff << KERNEL_HOOK_STATE_ABI_SHIFT);
    foreign |= 2 << KERNEL_HOOK_STATE_ABI_SHIFT;
    assert!(!kernel_hook_state_armed(foreign));
    assert_eq!(kernel_hook_state_flags(foreign), 0);
    // A disarmed word never exposes flags even if the bits are set.
    let stale = kernel_hook_state_word(0x1122_3344, false, KERNEL_HOOK_FLAG_ALL);
    assert_eq!(
        (stale >> KERNEL_HOOK_STATE_FLAGS_SHIFT) & KERNEL_HOOK_STATE_FLAGS_MASK,
        u64::from(KERNEL_HOOK_FLAG_ALL)
    );
    assert_eq!(kernel_hook_state_flags(stale), 0);
    assert_eq!(KERNEL_HOOK_STATE_MAGIC, b'K');
    assert_eq!(KERNEL_HOOK_STATE_ABI, 1);
}
