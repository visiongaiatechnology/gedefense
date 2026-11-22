//! Point 1 (Phase 1): ABI-1 wire-contract tests for the Titan exec gate.
//!
//! Split out of `titan_exec.rs` (module size cap); the tests only use the public
//! constant/encoder/decoder surface, so they live in their own module.

use crate::titan_exec::*;

    
    const BPRM: u8 = TITAN_EXEC_HOOK_BPRM;
    const MMAP: u8 = TITAN_EXEC_HOOK_MMAP;
    const AUDIT: u8 = TITAN_EXEC_ACTION_AUDIT;
    const DENY: u8 = TITAN_EXEC_ACTION_DENY;
    const BIN_COMM: [u8; 16] = *b"untrusted-bin\0\0\0";

    /// Canonical event; `hook` picks the variant/prot convention (bprm: 0, mmap: PROT_EXEC).
    fn sample(hook: u8) -> TitanExecEvent {
        TitanExecEvent {
            cgroup_id: 0x0000_0102_0304_0506, ts_ns: 987_654_321,
            dev: 0x0801_0002, inode_mode: 0o100_755, ino: 0x1122_3344_5566_7788,
            generation: 7, pid: 4242, tgid: 4241, uid: 1000, gid: 1001,
            prot: if hook == MMAP { 0x4 } else { 0 }, f_flags: 0x8000, hook,
            action: AUDIT, reason: TITAN_EXEC_REASON_NOT_ALLOWLISTED,
            flags: 0b11, comm: BIN_COMM, reserved: [0; 8],
        }
    }

    fn decoded(event: &TitanExecEvent) -> Option<TitanExecEvent> {
        decode_titan_exec_event(&encode_titan_exec_event(event))
    }

    fn assert_rejected(event: &TitanExecEvent) {
        assert_eq!(decoded(event), None, "must be rejected: {event:?}");
    }

    #[test]
    fn constants_match_abi() {
        assert_eq!(TITAN_EXEC_EVENT_WIRE_BYTES, 88);
        assert_eq!((BPRM, MMAP), (1u8, 2));
        assert_eq!((AUDIT, DENY), (1u8, 2));
        assert_eq!(
            [TITAN_EXEC_REASON_NONE, TITAN_EXEC_REASON_UNLINKED, TITAN_EXEC_REASON_TMPFS,
             TITAN_EXEC_REASON_MEMFD, TITAN_EXEC_REASON_NOT_ALLOWLISTED, TITAN_EXEC_REASON_WX,
             TITAN_EXEC_REASON_ANON_NO_JIT, TITAN_EXEC_REASON_READ_FAILURE,
             TITAN_EXEC_REASON_STATE_NOT_READY, TITAN_EXEC_REASON_CTIME_MISMATCH,
             TITAN_EXEC_REASON_FS_HARD, TITAN_EXEC_REASON_UNTRUSTED_PATH,
             TITAN_EXEC_REASON_NON_ROOT_OWNER, TITAN_EXEC_REASON_WORLD_WRITABLE_PATH],
            [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        );
        assert_eq!(TITAN_EXEC_REASON_MAX, 13);
        let modes = [TITAN_EXEC_MODE_OFF, TITAN_EXEC_MODE_OBSERVE,
                     TITAN_EXEC_MODE_CONTAIN, TITAN_EXEC_MODE_STRICT,
                     TITAN_EXEC_MODE_UNTRUSTED];
        assert_eq!(modes, [0u8, 1, 2, 3, 4]);
        // A per-cgroup scope value only has two mode bits (bits 2..=3).
        assert_eq!(TITAN_EXEC_SCOPE_MODE_MAX, 3);
        assert_eq!(TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW, 1);
        assert_eq!(TITAN_EXEC_STATE_MAGIC, 0x54);
        assert_eq!(TITAN_EXEC_STATE_MAGIC, b'T');
        assert_eq!(TITAN_EXEC_STATE_ABI, 1);
        assert_eq!(TITAN_EXEC_OFFSETS_MAGIC, 0x5449_544f);
        assert_eq!(TITAN_I_CTIME_QUERIED, 1u32 << 31);
        assert_eq!(strip_ctime_queried_flag(422_743_564 | TITAN_I_CTIME_QUERIED), 422_743_564);
        assert_eq!(strip_ctime_queried_flag(422_743_564), 422_743_564);
        assert_eq!(TITAN_EXEC_OFFSETS_ABI, 2);
    }

    #[test]
    fn event_layout_and_encoder_match_the_abi_table() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<TitanExecEvent>(), TITAN_EXEC_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<TitanExecEvent>(), 8);
        let offsets = [
            (offset_of!(TitanExecEvent, cgroup_id), 0), (offset_of!(TitanExecEvent, ts_ns), 8), (offset_of!(TitanExecEvent, dev), 16),
            (offset_of!(TitanExecEvent, inode_mode), 20), (offset_of!(TitanExecEvent, ino), 24), (offset_of!(TitanExecEvent, generation), 32),
            (offset_of!(TitanExecEvent, pid), 36), (offset_of!(TitanExecEvent, tgid), 40), (offset_of!(TitanExecEvent, uid), 44),
            (offset_of!(TitanExecEvent, gid), 48), (offset_of!(TitanExecEvent, prot), 52), (offset_of!(TitanExecEvent, f_flags), 56),
            (offset_of!(TitanExecEvent, hook), 60), (offset_of!(TitanExecEvent, action), 61), (offset_of!(TitanExecEvent, reason), 62),
            (offset_of!(TitanExecEvent, flags), 63), (offset_of!(TitanExecEvent, comm), 64), (offset_of!(TitanExecEvent, reserved), 80),
        ];
        for (actual, expected) in offsets {
            assert_eq!(actual, expected);
        }
        assert_eq!(offset_of!(TitanExecEvent, reserved) + size_of::<[u8; 8]>(), 88);

        // The encoder writes the same hard-coded offsets, so neither side can
        // silently follow a drifted `repr(C)` layout.
        let event = sample(MMAP);
        let raw = encode_titan_exec_event(&event);
        let at = |off: usize, bytes: &[u8]| assert_eq!(&raw[off..off + bytes.len()], bytes);
        at(0, &event.cgroup_id.to_ne_bytes()); at(8, &event.ts_ns.to_ne_bytes()); at(16, &event.dev.to_ne_bytes());
        at(20, &event.inode_mode.to_ne_bytes()); at(24, &event.ino.to_ne_bytes()); at(32, &event.generation.to_ne_bytes());
        at(36, &event.pid.to_ne_bytes()); at(40, &event.tgid.to_ne_bytes()); at(44, &event.uid.to_ne_bytes());
        at(48, &event.gid.to_ne_bytes()); at(52, &event.prot.to_ne_bytes()); at(56, &event.f_flags.to_ne_bytes());
        at(60, &[MMAP]); at(61, &[event.action]); at(62, &[event.reason]); at(63, &[event.flags]); at(64, &event.comm); at(80, &event.reserved);
    }

    #[test]
    fn round_trips_every_field_for_both_hooks_and_extreme_values() {
        for hook in [BPRM, MMAP] {
            let event = sample(hook);
            assert_eq!(decoded(&event), Some(event));
        }
        let mut event = sample(MMAP);
        event.cgroup_id = u64::MAX;
        event.ts_ns = u64::MAX;
        event.dev = u32::MAX;
        event.ino = u64::MAX;
        event.generation = u32::MAX;
        event.pid = u32::MAX;
        event.prot = u32::MAX;
        event.action = DENY;
        event.reason = TITAN_EXEC_REASON_FS_HARD;
        event.flags = 0xff;
        let mut comm = [0u8; 16];
        comm[..15].copy_from_slice(b"fifteen-chars-x");
        event.comm = comm;
        assert_eq!(decoded(&event), Some(event));
    }

    #[test]
    fn decodes_every_representable_hook_action_reason_combination() {
        for hook in [BPRM, MMAP] {
            for action in [AUDIT, DENY] {
                for reason in 0..=TITAN_EXEC_REASON_MAX {
                    let mut event = sample(hook);
                    event.action = action; event.reason = reason;
                    // A deny needs a ground; everything else is representable.
                    let valid = action == AUDIT
                        || !matches!(
                            reason,
                            TITAN_EXEC_REASON_NONE | TITAN_EXEC_REASON_READ_FAILURE
                        );
                    let expected = if valid { Some(event) } else { None };
                    assert_eq!(decoded(&event), expected,
                        "hook={hook} action={action} reason={reason}");
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_lengths_and_unknown_enum_bytes() {
        let raw = encode_titan_exec_event(&sample(BPRM));
        for len in [0usize, 1, 8, 64, 87] {
            assert!(decode_titan_exec_event(&raw[..len]).is_none(), "len {len}");
        }
        // 88 is the only accepted length; longer buffers are not truncated.
        let mut longer = [0u8; 176];
        longer[..TITAN_EXEC_EVENT_WIRE_BYTES].copy_from_slice(&raw);
        for len in [89usize, 90, 104, 176] {
            assert!(decode_titan_exec_event(&longer[..len]).is_none(), "len {len}");
        }

        // An mmap record with valid prot isolates the hook byte from the prot rule.
        fn check_byte(raw: &[u8; TITAN_EXEC_EVENT_WIRE_BYTES], at: usize, valid: fn(u8) -> bool) {
            for byte in 0u8..=u8::MAX {
                let mut patched = *raw;
                patched[at] = byte;
                assert_eq!(decode_titan_exec_event(&patched).is_some(), valid(byte), "byte {at} = {byte}");
            }
        }
        let mmap_raw = encode_titan_exec_event(&sample(MMAP));
        check_byte(&mmap_raw, 60, |b| matches!(b, TITAN_EXEC_HOOK_BPRM | TITAN_EXEC_HOOK_MMAP));
        check_byte(&mmap_raw, 61, |b| matches!(b, TITAN_EXEC_ACTION_AUDIT | TITAN_EXEC_ACTION_DENY));
        check_byte(&mmap_raw, 62, |b| b <= TITAN_EXEC_REASON_MAX);
    }

    #[test]
    fn rejects_structurally_impossible_events() {
        // pid 0 and timestamp 0: no executable task / no kernel second.
        for hook in [BPRM, MMAP] {
            let mut event = sample(hook);
            event.pid = 0;
            assert_rejected(&event);
            event = sample(hook);
            event.ts_ns = 0;
            assert_rejected(&event);
            // Early-boot-like values are representable.
            event = sample(hook);
            event.pid = 1;
            event.ts_ns = 1;
            assert_eq!(decoded(&event), Some(event));
        }
        // mmap without a requested protection; bprm carries none by design.
        for action in [AUDIT, DENY] {
            let mut event = sample(MMAP);
            event.prot = 0;
            event.action = action;
            assert_rejected(&event);
        }
        let mut bprm = sample(BPRM); bprm.prot = 0;
        assert_eq!(decoded(&bprm), Some(bprm));
        // A deny needs a valid ground; a zero identity does not create one.
        for hook in [BPRM, MMAP] {
            for reason in [TITAN_EXEC_REASON_NONE, TITAN_EXEC_REASON_READ_FAILURE] {
                let mut event = sample(hook);
                event.action = DENY;
                event.reason = reason;
                assert_rejected(&event);
                event.dev = 0;
                event.ino = 0;
                assert_rejected(&event);
            }
        }
    }

    #[test]
    fn null_identity_only_permitted_for_the_abi_exceptions() {
        for hook in [BPRM, MMAP] {
            let mut event = sample(hook);
            event.action = AUDIT;
            event.reason = TITAN_EXEC_REASON_READ_FAILURE;
            // A read-failure audit names no inode: dev=ino=0 is the §3.2
            // exception; a half-null identity is corruption.
            event.dev = 0;
            event.ino = 0;
            assert_eq!(decoded(&event), Some(event), "hook {hook}");
            event.dev = sample(hook).dev;
            assert_rejected(&event);
            event.dev = 0;
            event.ino = sample(hook).ino;
            assert_rejected(&event);
            event.ino = 0; event.action = DENY;
            assert_rejected(&event);
            // Other reasons reject a zero identity in either field (anon below).
            let base = sample(hook);
            for reason in 0..=TITAN_EXEC_REASON_MAX {
                if matches!(reason, TITAN_EXEC_REASON_READ_FAILURE | TITAN_EXEC_REASON_ANON_NO_JIT) {
                    continue;
                }
                for (dev, ino) in [(0, base.ino), (base.dev, 0), (0, 0)] {
                    let mut event = base;
                    event.reason = reason;
                    event.dev = dev;
                    event.ino = ino;
                    assert_rejected(&event);
                }
            }
        }
        // Anonymous exec mmap (file==NULL): null identity only with ANON_NO_JIT + PROT_EXEC.
        // It stays representable for audit and deny.
        for action in [AUDIT, DENY] {
            let mut event = sample(MMAP);
            event.action = action;
            event.reason = TITAN_EXEC_REASON_ANON_NO_JIT;
            event.dev = 0;
            event.ino = 0;
            assert_eq!(decoded(&event), Some(event), "action {action}");
            event.prot = 0x6; // PROT_WRITE|PROT_EXEC: PROT_EXEC is set
            assert_eq!(decoded(&event), Some(event));
            event.prot = 0x2; // PROT_WRITE only: not an executable mapping
            assert_rejected(&event);
            event.prot = 0x4;
            event.hook = BPRM; // bprm always has a file
            assert_rejected(&event);
            event.hook = MMAP;
            event.dev = 0x0801_0002; // half-null identity is corruption
            assert_rejected(&event);
            event.dev = 0;
            event.ino = 0x1122_3344_5566_7788;
            assert_rejected(&event);
        }
    }

    #[test]
    fn validates_comm_nul_padding() {
        let mut event = sample(BPRM);
        // 15 bytes plus the mandatory terminator (Linux TASK_COMM_LEN 16).
        let mut comm = [0u8; 16]; comm[..15].copy_from_slice(b"fifteen-chars-x");
        event.comm = comm;
        assert_eq!(decoded(&event), Some(event));
        event.comm = BIN_COMM;
        assert_eq!(decoded(&event), Some(event));
        event.comm = [0u8; 16];
        assert_eq!(decoded(&event), Some(event));
        // Opaque non-UTF-8 bytes before the terminator are carried through.
        event.comm = [0xff, 0xfe, b'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decoded(&event), Some(event));
        // Missing terminator: a full 16-byte name is not a producer record.
        event.comm = [b'x'; 16];
        assert_rejected(&event);
        // Garbage behind the terminator.
        let mut comm = [0u8; 16]; comm[0] = b'x'; comm[2] = 1;
        event.comm = comm;
        assert_rejected(&event);
        event.comm = *b"ok\0garbage-garba";
        assert_rejected(&event);
    }