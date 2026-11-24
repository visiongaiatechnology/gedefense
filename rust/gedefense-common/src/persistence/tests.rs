use super::*;
use core::mem::{align_of, offset_of, size_of};

fn sample(kind: u8, class: u8) -> PersistenceEvent {
    PersistenceEvent {
        ts_ns: 1_700_000_000_000_000_000,
        ino: 0xdead_beef_1234_5678,
        dev: 0x0801,
        pid: 4242,
        tgid: 4241,
        uid: 1000,
        detail_code: 0,
        class,
        kind,
        action: PERSIST_ACTION_AUDIT,
        reserved: 0,
        comm: *b"gedefense\0\0\0\0\0\0\0",
        detail: [0; 8],
    }
}

#[test]
fn wire_layout_matches_the_64_byte_contract() {
    assert_eq!(size_of::<PersistenceEvent>(), PERSIST_EVENT_WIRE_BYTES);
    assert_eq!(align_of::<PersistenceEvent>(), 8);
    assert_eq!(offset_of!(PersistenceEvent, ts_ns), 0);
    assert_eq!(offset_of!(PersistenceEvent, ino), 8);
    assert_eq!(offset_of!(PersistenceEvent, dev), 16);
    assert_eq!(offset_of!(PersistenceEvent, pid), 20);
    assert_eq!(offset_of!(PersistenceEvent, tgid), 24);
    assert_eq!(offset_of!(PersistenceEvent, uid), 28);
    assert_eq!(offset_of!(PersistenceEvent, detail_code), 32);
    assert_eq!(offset_of!(PersistenceEvent, class), 36);
    assert_eq!(offset_of!(PersistenceEvent, kind), 37);
    assert_eq!(offset_of!(PersistenceEvent, action), 38);
    assert_eq!(offset_of!(PersistenceEvent, reserved), 39);
    assert_eq!(offset_of!(PersistenceEvent, comm), 40);
    assert_eq!(offset_of!(PersistenceEvent, detail), 56);
    // Every byte is covered by a named field: a stored record cannot leak
    // uninitialised stack bytes into the ring.
    assert_eq!(offset_of!(PersistenceEvent, detail) + 8, PERSIST_EVENT_WIRE_BYTES);
}

#[test]
fn every_kind_roundtrips_with_its_documented_class() {
    let cases = [
        (PERSIST_KIND_INTEGRITY_WRITE, PERSIST_CLASS_LD_PRELOAD),
        (PERSIST_KIND_INTEGRITY_WRITE, PERSIST_CLASS_SHELL_PROFILE),
        (PERSIST_KIND_LIBRARY_MMAP, PERSIST_CLASS_LD_SO),
        (PERSIST_KIND_PERIPHERAL_OPEN, PERSIST_CLASS_DEVICE_CAMERA),
        (PERSIST_KIND_PERIPHERAL_OPEN, PERSIST_CLASS_DEVICE_MIC),
        (PERSIST_KIND_PERIPHERAL_OPEN, PERSIST_CLASS_DEVICE_EVDEV),
        (PERSIST_KIND_PERIPHERAL_OPEN, PERSIST_CLASS_DEVICE_CAPTURE_SOCKET),
        (PERSIST_KIND_SECRET_OPEN, PERSIST_CLASS_SECRET_SSH),
        (PERSIST_KIND_SECRET_OPEN, PERSIST_CLASS_SECRET_KEYRING),
        (PERSIST_KIND_MEMORY_SCRAPE, PERSIST_CLASS_UNSPECIFIED),
        (PERSIST_KIND_PTRACE_ACCESS, PERSIST_CLASS_UNSPECIFIED),
        (PERSIST_KIND_DRIFT, PERSIST_CLASS_SYSTEMD_GENERATOR),
        (PERSIST_KIND_BASELINE, PERSIST_CLASS_UNSPECIFIED),
    ];
    for (kind, class) in cases {
        let mut event = sample(kind, class);
        if class == PERSIST_CLASS_UNSPECIFIED {
            event.dev = 0;
            event.ino = 0;
        }
        if kind == PERSIST_KIND_DRIFT {
            event.detail_code = PERSIST_DRIFT_CONTENT;
        }
        assert_eq!(
            decode_persistence_event(&encode_persistence_event(&event)),
            Some(event),
            "kind {kind} class {class}"
        );
    }
    let scrape = PersistenceEvent {
        detail: *b"1234\0\0\0\0",
        ..sample(PERSIST_KIND_MEMORY_SCRAPE, PERSIST_CLASS_UNSPECIFIED)
    };
    let mut scrape = scrape;
    scrape.dev = 0;
    scrape.ino = 0;
    assert_eq!(
        decode_persistence_event(&encode_persistence_event(&scrape)),
        Some(scrape)
    );
    assert_eq!(scrape.detail_bytes(), b"1234");
}

#[test]
fn rejects_records_the_producer_cannot_have_emitted() {
    let base = sample(PERSIST_KIND_INTEGRITY_WRITE, PERSIST_CLASS_LD_PRELOAD);
    let raw = encode_persistence_event(&base);
    for length in [0usize, 1, 32, 63] {
        assert!(decode_persistence_event(&raw[..length]).is_none(), "{length}");
    }
    assert!(decode_persistence_event(&[0u8; 65][..65]).is_none());

    let mutations: &[(fn(&mut PersistenceEvent), &str)] = &[
        (|event| event.action = 0, "action 0"),
        (|event| event.action = 4, "action 4"),
        (|event| event.kind = 0, "kind 0"),
        (|event| event.kind = 9, "kind 9"),
        (|event| event.class = 12, "class 12"),
        (|event| event.class = 24, "class 24"),
        (|event| event.class = 40, "class 40"),
        (|event| event.ts_ns = 0, "ts 0"),
        (|event| event.pid = 0, "pid 0"),
        (|event| event.tgid = 0, "tgid 0"),
        (|event| event.reserved = 1, "reserved"),
        (|event| event.dev = 0, "dev 0"),
        (|event| event.ino = 0, "ino 0"),
        (|event| event.comm = [0u8; 16], "empty comm"),
        (|event| event.comm = [b'x'; 16], "unpadded comm"),
        (|event| event.comm[14] = 0x01, "control comm"),
        (|event| event.detail = [1; 8], "unpadded detail"),
        (|event| event.class = PERSIST_CLASS_DEVICE_CAMERA, "kind/class mismatch"),
        (|event| event.kind = PERSIST_KIND_SECRET_OPEN, "secret with integrity class"),
        (|event| event.kind = PERSIST_KIND_LIBRARY_MMAP, "mmap with integrity class"),
        (|event| event.kind = PERSIST_KIND_MEMORY_SCRAPE, "scrape with path class"),
        (|event| event.kind = PERSIST_KIND_PTRACE_ACCESS, "ptrace with path class"),
        (|event| event.kind = PERSIST_KIND_DRIFT, "drift reason 0"),
        (|event| event.kind = PERSIST_KIND_BASELINE, "baseline with path class"),
    ];
    for (mutate, label) in mutations {
        let mut event = base;
        mutate(&mut event);
        assert!(
            decode_persistence_event(&encode_persistence_event(&event)).is_none(),
            "{label}"
        );
    }

    // Identity-less kinds must not carry a file identity.
    for kind in [
        PERSIST_KIND_MEMORY_SCRAPE,
        PERSIST_KIND_PTRACE_ACCESS,
        PERSIST_KIND_BASELINE,
    ] {
        let mut event = sample(kind, PERSIST_CLASS_UNSPECIFIED);
        assert!(decode_persistence_event(&encode_persistence_event(&event)).is_none(), "{kind} with identity");
        event.dev = 0;
        assert!(decode_persistence_event(&encode_persistence_event(&event)).is_none(), "{kind} half identity");
    }
    // A half-null identity is never representable.
    let mut half = base;
    half.dev = 0;
    assert!(decode_persistence_event(&encode_persistence_event(&half)).is_none());
    let mut half = base;
    half.ino = 0;
    assert!(decode_persistence_event(&encode_persistence_event(&half)).is_none());
    // Closed drift reasons.
    let mut drift = sample(PERSIST_KIND_DRIFT, PERSIST_CLASS_LD_CONF);
    for reason in [
        PERSIST_DRIFT_CONTENT,
        PERSIST_DRIFT_MISSING,
        PERSIST_DRIFT_APPEARED,
        PERSIST_DRIFT_REPLACED,
    ] {
        drift.detail_code = reason;
        assert!(decode_persistence_event(&encode_persistence_event(&drift)).is_some());
    }
    drift.detail_code = 5;
    assert!(decode_persistence_event(&encode_persistence_event(&drift)).is_none());
}

#[test]
fn comm_and_detail_slots_are_printable_nul_padded() {
    let mut good = [0u8; 16];
    good[0..4].copy_from_slice(b"sshd");
    assert!(persistence_comm_is_valid(&good));
    let mut unpadded = *b"0123456789abcdef";
    assert!(!persistence_comm_is_valid(&unpadded));
    unpadded[15] = 0;
    assert!(persistence_comm_is_valid(&unpadded));
    let empty = [0u8; 16];
    assert!(!persistence_comm_is_valid(&empty));
    let mut control = [0u8; 16];
    control[0] = b'a';
    control[1] = 0x7f;
    control[2] = 0;
    assert!(!persistence_comm_is_valid(&control));

    assert!(persistence_detail_is_valid(&[0u8; 8]));
    let mut detail = [0u8; 8];
    detail[0..6].copy_from_slice(b"writev");
    assert!(persistence_detail_is_valid(&detail));
    let mut after_pad = [0u8; 8];
    after_pad[0] = b'1';
    after_pad[2] = b'2';
    assert!(!persistence_detail_is_valid(&after_pad));
    assert!(!persistence_detail_is_valid(&[1u8; 8]));
}

#[test]
fn path_map_values_are_closed_and_roundtrip_the_documented_layout() {
    let value = persistence_path_value(PERSIST_CLASS_SECRET_SSH, 1000, false).expect("value");
    assert_eq!(persistence_path_class(value), PERSIST_CLASS_SECRET_SSH);
    assert_eq!(persistence_path_owner_uid(value), 1000);
    assert!(!persistence_path_is_directory(value));
    let directory =
        persistence_path_value(PERSIST_CLASS_PAM, 0, true).expect("directory value");
    assert_eq!(persistence_path_class(directory), PERSIST_CLASS_PAM);
    assert_eq!(persistence_path_owner_uid(directory), 0);
    assert!(persistence_path_is_directory(directory));
    assert_eq!(directory >> 63, 1);
    assert!(persistence_path_value(0, 0, false).is_none());
    assert!(persistence_path_value(12, 0, false).is_none());
    assert!(persistence_path_value(PERSIST_CLASS_SECRET_KEYRING, u32::MAX, false).is_some());

    // Reserved bits (40..62) never come out of the encoder and are rejected
    // by the validator a foreign map writer could not satisfy.
    assert!(persistence_path_value_valid(value));
    assert!(persistence_path_value_valid(directory));
    let mut stray = value | (1u64 << 41);
    assert!(!persistence_path_value_valid(stray));
    stray = value | (1u64 << 62);
    assert!(!persistence_path_value_valid(stray));
    assert!(!persistence_path_value_valid(0));
    assert!(!persistence_path_value_valid(12 | (5 << 8)));
    // The directory flag is metadata, not a class: still valid.
    assert!(persistence_path_value_valid(value | (1u64 << 63)));
}

#[test]
fn identity_keys_roundtrip_and_reject_reserved_or_zero_fields() {
    let key = persistence_identity_key(0x0801, 0xdead_beef_1234_5678);
    assert_eq!(
        decode_persistence_identity_key(&key),
        Some((0x0801, 0xdead_beef_1234_5678))
    );
    let mut bad = key;
    bad[12] = 1;
    assert_eq!(decode_persistence_identity_key(&bad), None);
    assert_eq!(decode_persistence_identity_key(&persistence_identity_key(0, 5)), None);
    assert_eq!(decode_persistence_identity_key(&persistence_identity_key(5, 0)), None);
    assert_eq!(decode_persistence_identity_key(&[0u8; 15]), None);
    assert_eq!(decode_persistence_identity_key(&[0u8; 17]), None);
}

#[test]
fn constants_match_the_enumerated_ap5_contract() {
    assert_eq!(PERSIST_CLASS_LD_PRELOAD, 1);
    assert_eq!(PERSIST_CLASS_LD_CONF, 2);
    assert_eq!(PERSIST_CLASS_LD_SO, 3);
    assert_eq!(PERSIST_CLASS_TLS, 4);
    assert_eq!(PERSIST_CLASS_PAM, 5);
    assert_eq!(PERSIST_CLASS_SYSTEMD_GENERATOR, 6);
    assert_eq!(PERSIST_CLASS_SYSTEMD_DROPIN, 7);
    assert_eq!(PERSIST_CLASS_UDEV, 8);
    assert_eq!(PERSIST_CLASS_AUTHORIZED_KEYS, 9);
    assert_eq!(PERSIST_CLASS_SSHRC, 10);
    assert_eq!(PERSIST_CLASS_SHELL_PROFILE, 11);
    assert_eq!(PERSIST_CLASS_DEVICE_CAMERA, 20);
    assert_eq!(PERSIST_CLASS_DEVICE_MIC, 21);
    assert_eq!(PERSIST_CLASS_DEVICE_EVDEV, 22);
    assert_eq!(PERSIST_CLASS_DEVICE_CAPTURE_SOCKET, 23);
    assert_eq!(PERSIST_CLASS_SECRET_SSH, 30);
    assert_eq!(PERSIST_CLASS_SECRET_GNUPG, 31);
    assert_eq!(PERSIST_CLASS_SECRET_CLOUD, 32);
    assert_eq!(PERSIST_CLASS_SECRET_BROWSER, 33);
    assert_eq!(PERSIST_CLASS_SECRET_KEYRING, 34);
    assert_eq!(PERSIST_KIND_INTEGRITY_WRITE, 1);
    assert_eq!(PERSIST_KIND_LIBRARY_MMAP, 2);
    assert_eq!(PERSIST_KIND_PERIPHERAL_OPEN, 3);
    assert_eq!(PERSIST_KIND_SECRET_OPEN, 4);
    assert_eq!(PERSIST_KIND_MEMORY_SCRAPE, 5);
    assert_eq!(PERSIST_KIND_PTRACE_ACCESS, 6);
    assert_eq!(PERSIST_KIND_DRIFT, 7);
    assert_eq!(PERSIST_KIND_BASELINE, 8);
    assert_eq!(PERSIST_ACTION_AUDIT, 1);
    assert_eq!(PERSIST_ACTION_DENY, 2);
    assert_eq!(PERSIST_ACTION_OBSERVE, 3);
    assert_eq!(PERSIST_EVENT_RING_BYTES as usize / PERSIST_EVENT_WIRE_BYTES, 2048);
    assert_eq!(PERSIST_PATH_MAP_ENTRIES, 4096);
    assert_eq!(PERSIST_EXEC_MAP_ENTRIES, 256);
    assert_eq!(PERSIST_OFFSETS_TABLE_LEN, 48);
    assert!(PERSIST_OFF_RESERVED_FIRST < PERSIST_OFFSETS_TABLE_LEN as u32);
    assert_eq!(PERSIST_FILE_OPEN_NARGS_EXPECTED, 1);
    assert_eq!(PERSIST_PTRACE_NARGS_EXPECTED, 2);
    assert_eq!(PERSIST_PTRACE_CHILD_ARG, 0);
    assert_eq!(PERSIST_PTRACE_MODE_ARG, 1);
    assert_eq!(PERSIST_MMAP_FILE_ARG, 0);
    assert_eq!(PERSIST_MAX_TRACEPOINT_BYTES, 512);
    for class in 0u8..=255 {
        let known = persistence_class_known(class);
        assert_eq!(
            known,
            persistence_class_is_integrity(class)
                || persistence_class_is_device(class)
                || persistence_class_is_secret(class)
        );
    }
    for kind in 0u8..=255 {
        assert_eq!(persistence_kind_known(kind), (1..=8).contains(&kind));
    }
    for action in 0u8..=255 {
        assert_eq!(persistence_action_known(action), (1..=3).contains(&action));
    }
}

#[test]
fn state_word_is_armed_only_for_the_current_magic_abi_and_armed_bit() {
    let word = persistence_state_word(0xdead_beef, true);
    assert!(persistence_state_armed(word));
    assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
    assert_eq!(
        (word >> PERSIST_STATE_MAGIC_SHIFT) & PERSIST_STATE_BYTE_MASK,
        u64::from(PERSIST_STATE_MAGIC)
    );
    assert_eq!(PERSIST_STATE_MAGIC, b'P');
    assert_eq!(PERSIST_STATE_ABI, 1);
    assert!(!persistence_state_armed(persistence_state_word(1, false)));
    assert!(!persistence_state_armed(0));
    assert!(!persistence_state_armed(u64::MAX));
    let mut foreign = word;
    foreign &= !(0xff << PERSIST_STATE_ABI_SHIFT);
    foreign |= 2 << PERSIST_STATE_ABI_SHIFT;
    assert!(!persistence_state_armed(foreign));
}
