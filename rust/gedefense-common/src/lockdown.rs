//! Point 5 (Phase 1): shared ABI-1 contract for the Emergency Lockdown.
//!
//! Rust half of ABI-1 in `docs/POINT5-LOCKDOWN.md` §3: the single
//! `LOCKDOWN_STATE` word (consumed by eBPF) and the `LockdownEvent` lifecycle
//! record (produced/consumed by the core). Same host, native endian,
//! `repr(C)`, never portable.
//!
//! State word: bits 0..31 epoch, 32..39 mode, 40..47 flags, 48..55 ABI,
//! 56..63 magic. [`decode_lockdown_word`] rejects a foreign magic/ABI or an
//! out-of-range mode; eBPF then stays on the byte-identical 5.2.0 path
//! (fail-safe, no drop). Unknown *flag* bits are carried through unchanged: a
//! future phase bit must not silently disarm an armed lockdown.
//!
//! `LockdownEvent` is exactly 64 bytes. §3 lists `reserved[16]`, but the fields
//! before it already total 40 bytes and §3/§10 mandate `size_of == 64`, so the
//! reserved tail is 24 bytes (offsets 40..64). [`decode_lockdown_event`]
//! rejects only the documented matrix (wire length, closed enums, `seq == 0`,
//! `ts_ms == 0`); everything else is carried unchanged, never repaired.

// ---------------------------------------------------------------------------
// ABI-1: LOCKDOWN_STATE word (§3).
// ---------------------------------------------------------------------------

/// Magic of the state word: `0x4C` (`'L'`) in bits 56..63 (§3).
pub const LOCKDOWN_STATE_MAGIC: u8 = 0x4C;
/// ABI version of the state word in bits 48..55 (§3).
pub const LOCKDOWN_STATE_ABI: u8 = 1;
/// Bit positions of the packed state word (§3).
pub const LOCKDOWN_STATE_MODE_SHIFT: u32 = 32;
pub const LOCKDOWN_STATE_FLAGS_SHIFT: u32 = 40;
pub const LOCKDOWN_STATE_ABI_SHIFT: u32 = 48;
pub const LOCKDOWN_STATE_MAGIC_SHIFT: u32 = 56;
/// Mask of one packed byte field of the state word.
pub const LOCKDOWN_STATE_BYTE_MASK: u64 = 0xff;

/// Modes (§3): `OFF` is the default after upgrade; only `ARMED` can carry a
/// policy.
pub const LOCKDOWN_MODE_OFF: u8 = 0;
pub const LOCKDOWN_MODE_ARMED: u8 = 1;

/// Flags of the state word (§3). `WITNESS_ALLOW` is Phase 2 and always 0 here.
pub const LOCKDOWN_FLAG_DROP_ALL: u8 = 1 << 0;
pub const LOCKDOWN_FLAG_ALLOW_LOOPBACK: u8 = 1 << 1;
pub const LOCKDOWN_FLAG_WITNESS_ALLOW: u8 = 1 << 2;
pub const LOCKDOWN_FLAG_HARDENING_APPLIED: u8 = 1 << 3;
pub const LOCKDOWN_FLAG_USB_LOCKED: u8 = 1 << 4;
pub const LOCKDOWN_FLAG_TB_LOCKED: u8 = 1 << 5;
/// Bits above these are reserved for later phases and never a reject reason.
pub const LOCKDOWN_FLAGS_KNOWN: u8 = 0b0011_1111;

/// Decoded `LOCKDOWN_STATE` word (§3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockdownWord {
    /// New epoch per core start/trigger (§5), cleared with compare-set.
    pub epoch: u32,
    /// [`LOCKDOWN_MODE_OFF`] or [`LOCKDOWN_MODE_ARMED`].
    pub mode: u8,
    /// OR of the `LOCKDOWN_FLAG_*` bits.
    pub flags: u8,
}

impl LockdownWord {
    /// §4 eBPF fastpath condition: armed and `DROP_ALL` requested.
    pub const fn drops_network(&self) -> bool {
        self.mode == LOCKDOWN_MODE_ARMED && (self.flags & LOCKDOWN_FLAG_DROP_ALL) != 0
    }

    /// §4 egress exception: loopback stays reachable (default on).
    pub const fn allows_loopback(&self) -> bool {
        (self.flags & LOCKDOWN_FLAG_ALLOW_LOOPBACK) != 0
    }
}

/// Packs the §3 state word. ABI and magic are always written by this encoder;
/// the caller supplies the already-validated mode/flags.
pub const fn encode_lockdown_word(epoch: u32, mode: u8, flags: u8) -> u64 {
    (epoch as u64)
        | ((mode as u64) << LOCKDOWN_STATE_MODE_SHIFT)
        | ((flags as u64) << LOCKDOWN_STATE_FLAGS_SHIFT)
        | ((LOCKDOWN_STATE_ABI as u64) << LOCKDOWN_STATE_ABI_SHIFT)
        | ((LOCKDOWN_STATE_MAGIC as u64) << LOCKDOWN_STATE_MAGIC_SHIFT)
}

/// Decodes the §3 state word. `None` = no word (map default zero), foreign
/// magic/ABI or out-of-range mode: eBPF must then behave exactly like 5.2.0.
pub const fn decode_lockdown_word(word: u64) -> Option<LockdownWord> {
    let magic = ((word >> LOCKDOWN_STATE_MAGIC_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let abi = ((word >> LOCKDOWN_STATE_ABI_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let mode = ((word >> LOCKDOWN_STATE_MODE_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    if magic != LOCKDOWN_STATE_MAGIC || abi != LOCKDOWN_STATE_ABI || mode > LOCKDOWN_MODE_ARMED {
        return None;
    }
    let flags = ((word >> LOCKDOWN_STATE_FLAGS_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    Some(LockdownWord { epoch: (word & 0xffff_ffff) as u32, mode, flags })
}

// ---------------------------------------------------------------------------
// ABI-1: LockdownEvent (§3).
// ---------------------------------------------------------------------------

/// Wire size of one [`LockdownEvent`] (`sizeof(LockdownEvent) == 64`).
pub const LOCKDOWN_EVENT_WIRE_BYTES: usize = 64;

/// Reason tokens (§3), closed set, no free text or paths on the wire.
pub const LOCKDOWN_REASON_MANUAL: u8 = 1;
pub const LOCKDOWN_REASON_USB_UNKNOWN: u8 = 2;
pub const LOCKDOWN_REASON_TB_UNKNOWN: u8 = 3;
pub const LOCKDOWN_REASON_SCREEN_LOCK: u8 = 4;
pub const LOCKDOWN_REASON_TAMPER: u8 = 5;
pub const LOCKDOWN_REASON_XDR_CRITICAL: u8 = 6;
pub const LOCKDOWN_REASON_BOOT_TRUST_DRIFT: u8 = 7;
pub const LOCKDOWN_REASON_POLICY: u8 = 8;
pub const LOCKDOWN_REASON_MAX: u8 = LOCKDOWN_REASON_POLICY;

/// Source tokens (§3).
pub const LOCKDOWN_SOURCE_MANUAL: u8 = 1;
pub const LOCKDOWN_SOURCE_UEVENT: u8 = 2;
pub const LOCKDOWN_SOURCE_POLICY: u8 = 3;
pub const LOCKDOWN_SOURCE_TIMER: u8 = 4;
pub const LOCKDOWN_SOURCE_MAX: u8 = LOCKDOWN_SOURCE_TIMER;

/// Phase tokens (§3): `INTENT=0` precedes the active phases; `SESSIONS`/`DM`
/// are honestly `unsupported` in Phase 1.
pub const LOCKDOWN_PHASE_INTENT: u8 = 0;
pub const LOCKDOWN_PHASE_NET: u8 = 1;
pub const LOCKDOWN_PHASE_USB: u8 = 2;
pub const LOCKDOWN_PHASE_TB: u8 = 3;
pub const LOCKDOWN_PHASE_HARDENING: u8 = 4;
pub const LOCKDOWN_PHASE_BROKERS: u8 = 5;
pub const LOCKDOWN_PHASE_CELLS: u8 = 6;
pub const LOCKDOWN_PHASE_SESSIONS: u8 = 7;
pub const LOCKDOWN_PHASE_DM: u8 = 8;
pub const LOCKDOWN_PHASE_MAX: u8 = LOCKDOWN_PHASE_DM;

/// Outcome tokens (§3): every value is explicit, 0 is not an outcome.
pub const LOCKDOWN_OUTCOME_APPLIED: u8 = 1;
pub const LOCKDOWN_OUTCOME_SKIPPED: u8 = 2;
pub const LOCKDOWN_OUTCOME_UNSUPPORTED: u8 = 3;
pub const LOCKDOWN_OUTCOME_FAILED: u8 = 4;
pub const LOCKDOWN_OUTCOME_PARTIAL: u8 = 5;
pub const LOCKDOWN_OUTCOME_MAX: u8 = LOCKDOWN_OUTCOME_PARTIAL;

/// Trigger reason (§3); discriminants are the ABI constants above.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownReason {
    Manual = LOCKDOWN_REASON_MANUAL,
    UsbUnknown = LOCKDOWN_REASON_USB_UNKNOWN,
    TbUnknown = LOCKDOWN_REASON_TB_UNKNOWN,
    ScreenLock = LOCKDOWN_REASON_SCREEN_LOCK,
    Tamper = LOCKDOWN_REASON_TAMPER,
    XdrCritical = LOCKDOWN_REASON_XDR_CRITICAL,
    BootTrustDrift = LOCKDOWN_REASON_BOOT_TRUST_DRIFT,
    Policy = LOCKDOWN_REASON_POLICY,
}

/// Trigger source (§3).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownSource {
    Manual = LOCKDOWN_SOURCE_MANUAL,
    Uevent = LOCKDOWN_SOURCE_UEVENT,
    Policy = LOCKDOWN_SOURCE_POLICY,
    Timer = LOCKDOWN_SOURCE_TIMER,
}

/// Lockdown phase (§3/§6).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownPhase {
    Intent = LOCKDOWN_PHASE_INTENT,
    Net = LOCKDOWN_PHASE_NET,
    Usb = LOCKDOWN_PHASE_USB,
    Tb = LOCKDOWN_PHASE_TB,
    Hardening = LOCKDOWN_PHASE_HARDENING,
    Brokers = LOCKDOWN_PHASE_BROKERS,
    Cells = LOCKDOWN_PHASE_CELLS,
    Sessions = LOCKDOWN_PHASE_SESSIONS,
    Dm = LOCKDOWN_PHASE_DM,
}

/// Per-phase outcome (§3/§6): unsupported is never reported as applied.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownOutcome {
    Applied = LOCKDOWN_OUTCOME_APPLIED,
    Skipped = LOCKDOWN_OUTCOME_SKIPPED,
    Unsupported = LOCKDOWN_OUTCOME_UNSUPPORTED,
    Failed = LOCKDOWN_OUTCOME_FAILED,
    Partial = LOCKDOWN_OUTCOME_PARTIAL,
}

/// Defines the closed-token decoders for the four §3 enums.
macro_rules! lockdown_token_enum {
    ($name:ident { $($constant:ident => $variant:ident),+ $(,)? }) => {
        impl $name {
            /// Decodes the closed token set; `None` for every value §3 cannot emit.
            pub const fn from_u8(value: u8) -> Option<Self> {
                Some(match value {
                    $($constant => Self::$variant,)+
                    _ => return None,
                })
            }

            /// The ABI byte of this token.
            pub const fn as_u8(self) -> u8 {
                self as u8
            }
        }
    };
}

lockdown_token_enum!(LockdownReason {
    LOCKDOWN_REASON_MANUAL => Manual,
    LOCKDOWN_REASON_USB_UNKNOWN => UsbUnknown,
    LOCKDOWN_REASON_TB_UNKNOWN => TbUnknown,
    LOCKDOWN_REASON_SCREEN_LOCK => ScreenLock,
    LOCKDOWN_REASON_TAMPER => Tamper,
    LOCKDOWN_REASON_XDR_CRITICAL => XdrCritical,
    LOCKDOWN_REASON_BOOT_TRUST_DRIFT => BootTrustDrift,
    LOCKDOWN_REASON_POLICY => Policy,
});
lockdown_token_enum!(LockdownSource {
    LOCKDOWN_SOURCE_MANUAL => Manual,
    LOCKDOWN_SOURCE_UEVENT => Uevent,
    LOCKDOWN_SOURCE_POLICY => Policy,
    LOCKDOWN_SOURCE_TIMER => Timer,
});
lockdown_token_enum!(LockdownPhase {
    LOCKDOWN_PHASE_INTENT => Intent,
    LOCKDOWN_PHASE_NET => Net,
    LOCKDOWN_PHASE_USB => Usb,
    LOCKDOWN_PHASE_TB => Tb,
    LOCKDOWN_PHASE_HARDENING => Hardening,
    LOCKDOWN_PHASE_BROKERS => Brokers,
    LOCKDOWN_PHASE_CELLS => Cells,
    LOCKDOWN_PHASE_SESSIONS => Sessions,
    LOCKDOWN_PHASE_DM => Dm,
});
lockdown_token_enum!(LockdownOutcome {
    LOCKDOWN_OUTCOME_APPLIED => Applied,
    LOCKDOWN_OUTCOME_SKIPPED => Skipped,
    LOCKDOWN_OUTCOME_UNSUPPORTED => Unsupported,
    LOCKDOWN_OUTCOME_FAILED => Failed,
    LOCKDOWN_OUTCOME_PARTIAL => Partial,
});

/// One lockdown lifecycle record (§3): 64 bytes, native endian, `repr(C)`.
///
/// Byte layout (no implicit padding): `seq` 0, `ts_ms` 8, `epoch` 16,
/// `source` 20, `reason` 21, `phase` 22, `outcome` 23, `cgroup_id` 24,
/// `detail_u64` 32, `reserved` 40..64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockdownEvent {
    /// Monotonic per-core sequence number; 0 is reserved for "none" (§3).
    pub seq: u64,
    /// Wall-clock milliseconds at emission; 0 is reserved ("unknown", §3).
    pub ts_ms: u64,
    /// Epoch of the lockdown state word this record belongs to.
    pub epoch: u32,
    /// [`LockdownSource`] value.
    pub source: u8,
    /// [`LockdownReason`] value.
    pub reason: u8,
    /// [`LockdownPhase`] value.
    pub phase: u8,
    /// [`LockdownOutcome`] value.
    pub outcome: u8,
    /// Cell/scope the record belongs to; 0 = not bound to a cgroup.
    pub cgroup_id: u64,
    /// Phase-specific detail bits (§6); carried unchanged, no paths/IPs/secret.
    pub detail_u64: u64,
    /// Reserved tail (24 bytes, see the module note); producer writes zeros.
    pub reserved: [u8; 24],
}

/// Encodes one [`LockdownEvent`] into its native-endian wire form. Pure
/// serialisation: every field including `reserved` is written unchanged.
pub fn encode_lockdown_event(event: &LockdownEvent) -> [u8; LOCKDOWN_EVENT_WIRE_BYTES] {
    let mut bytes = [0u8; LOCKDOWN_EVENT_WIRE_BYTES];
    bytes[0..8].copy_from_slice(&event.seq.to_ne_bytes());
    bytes[8..16].copy_from_slice(&event.ts_ms.to_ne_bytes());
    bytes[16..20].copy_from_slice(&event.epoch.to_ne_bytes());
    bytes[20] = event.source;
    bytes[21] = event.reason;
    bytes[22] = event.phase;
    bytes[23] = event.outcome;
    bytes[24..32].copy_from_slice(&event.cgroup_id.to_ne_bytes());
    bytes[32..40].copy_from_slice(&event.detail_u64.to_ne_bytes());
    bytes[40..64].copy_from_slice(&event.reserved);
    bytes
}

/// Decodes one fixed-size lockdown-event wire record.
///
/// Returns `None` for every record the producer cannot have emitted: wrong
/// wire length, an out-of-range closed enum, `seq == 0` or `ts_ms == 0`. The
/// record is never repaired or neutralised.
pub fn decode_lockdown_event(bytes: &[u8]) -> Option<LockdownEvent> {
    if bytes.len() != LOCKDOWN_EVENT_WIRE_BYTES {
        return None;
    }

    let seq = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let ts_ms = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let epoch = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let source = bytes[20];
    let reason = bytes[21];
    let phase = bytes[22];
    let outcome = bytes[23];
    let cgroup_id = u64::from_ne_bytes(bytes[24..32].try_into().ok()?);
    let detail_u64 = u64::from_ne_bytes(bytes[32..40].try_into().ok()?);
    let reserved: [u8; 24] = bytes[40..64].try_into().ok()?;

    if LockdownSource::from_u8(source).is_none()
        || LockdownReason::from_u8(reason).is_none()
        || LockdownPhase::from_u8(phase).is_none()
        || LockdownOutcome::from_u8(outcome).is_none()
        || seq == 0
        || ts_ms == 0
    {
        return None;
    }

    Some(LockdownEvent { seq, ts_ms, epoch, source, reason, phase, outcome, cgroup_id, detail_u64, reserved })
}

// ---------------------------------------------------------------------------
// Compile-time ABI evidence (§3/§10).
// ---------------------------------------------------------------------------

const _: () = {
    assert!(core::mem::size_of::<LockdownEvent>() == LOCKDOWN_EVENT_WIRE_BYTES);
    assert!(core::mem::offset_of!(LockdownEvent, seq) == 0);
    assert!(core::mem::offset_of!(LockdownEvent, ts_ms) == 8);
    assert!(core::mem::offset_of!(LockdownEvent, epoch) == 16);
    assert!(core::mem::offset_of!(LockdownEvent, source) == 20);
    assert!(core::mem::offset_of!(LockdownEvent, reason) == 21);
    assert!(core::mem::offset_of!(LockdownEvent, phase) == 22);
    assert!(core::mem::offset_of!(LockdownEvent, outcome) == 23);
    assert!(core::mem::offset_of!(LockdownEvent, cgroup_id) == 24);
    assert!(core::mem::offset_of!(LockdownEvent, detail_u64) == 32);
    assert!(core::mem::offset_of!(LockdownEvent, reserved) == 40);
    assert!(LOCKDOWN_FLAGS_KNOWN == LOCKDOWN_FLAG_DROP_ALL | LOCKDOWN_FLAG_ALLOW_LOOPBACK
        | LOCKDOWN_FLAG_WITNESS_ALLOW | LOCKDOWN_FLAG_HARDENING_APPLIED
        | LOCKDOWN_FLAG_USB_LOCKED | LOCKDOWN_FLAG_TB_LOCKED);
};

const _: () = {
    assert!(LockdownReason::Policy as u8 == LOCKDOWN_REASON_MAX);
    assert!(LockdownSource::Timer as u8 == LOCKDOWN_SOURCE_MAX);
    assert!(LockdownPhase::Dm as u8 == LOCKDOWN_PHASE_MAX);
    assert!(LockdownOutcome::Partial as u8 == LOCKDOWN_OUTCOME_MAX);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> LockdownEvent {
        LockdownEvent {
            seq: 7,
            ts_ms: 1_700_000_000_000,
            epoch: 0xDEAD_BEEF,
            source: LockdownSource::Uevent.as_u8(),
            reason: LockdownReason::UsbUnknown.as_u8(),
            phase: LockdownPhase::Usb.as_u8(),
            outcome: LockdownOutcome::Applied.as_u8(),
            cgroup_id: 42,
            detail_u64: 0x0123_4567_89AB_CDEF,
            reserved: [0xAAu8; 24],
        }
    }

    #[test]
    fn enums_match_the_abi_token_tables() {
        assert_eq!(LockdownReason::Manual.as_u8(), 1);
        assert_eq!(LockdownReason::Policy.as_u8(), 8);
        assert_eq!(LockdownSource::Timer.as_u8(), 4);
        assert_eq!(LockdownPhase::Intent.as_u8(), 0);
        assert_eq!(LockdownPhase::Dm.as_u8(), 8);
        assert_eq!(LockdownOutcome::Applied.as_u8(), 1);
        assert_eq!(LockdownOutcome::Partial.as_u8(), 5);
        for value in 1..=LOCKDOWN_REASON_MAX {
            assert_eq!(LockdownReason::from_u8(value).map(|v| v.as_u8()), Some(value));
        }
        for value in 1..=LOCKDOWN_SOURCE_MAX {
            assert_eq!(LockdownSource::from_u8(value).map(|v| v.as_u8()), Some(value));
        }
        for value in 0..=LOCKDOWN_PHASE_MAX {
            assert_eq!(LockdownPhase::from_u8(value).map(|v| v.as_u8()), Some(value));
        }
        for value in 1..=LOCKDOWN_OUTCOME_MAX {
            assert_eq!(LockdownOutcome::from_u8(value).map(|v| v.as_u8()), Some(value));
        }
    }

    #[test]
    fn word_roundtrip_carries_epoch_mode_and_flags() {
        let flags =
            LOCKDOWN_FLAG_DROP_ALL | LOCKDOWN_FLAG_ALLOW_LOOPBACK | LOCKDOWN_FLAG_USB_LOCKED;
        let word = encode_lockdown_word(0x1234_5678, LOCKDOWN_MODE_ARMED, flags);
        // §3 byte evidence: magic 56..63 = 0x4C, ABI 48..55 = 1, mode, flags.
        assert_eq!((word >> LOCKDOWN_STATE_MAGIC_SHIFT) as u8, 0x4C);
        assert_eq!(((word >> LOCKDOWN_STATE_ABI_SHIFT) & 0xff) as u8, LOCKDOWN_STATE_ABI);
        assert_eq!(((word >> LOCKDOWN_STATE_MODE_SHIFT) & 0xff) as u8, LOCKDOWN_MODE_ARMED);
        assert_eq!(((word >> LOCKDOWN_STATE_FLAGS_SHIFT) & 0xff) as u8, flags);
        let decoded = decode_lockdown_word(word).expect("valid word");
        assert_eq!(decoded, LockdownWord { epoch: 0x1234_5678, mode: LOCKDOWN_MODE_ARMED, flags });
        assert!(decoded.drops_network());
        assert!(decoded.allows_loopback());

        // OFF and armed-without-DROP_ALL are valid words, but inert.
        let off = decode_lockdown_word(encode_lockdown_word(9, LOCKDOWN_MODE_OFF, 0)).unwrap();
        assert!(!off.drops_network() && !off.allows_loopback());
        let armed =
            decode_lockdown_word(encode_lockdown_word(9, LOCKDOWN_MODE_ARMED, LOCKDOWN_FLAG_USB_LOCKED))
                .unwrap();
        assert!(!armed.drops_network());
    }

    #[test]
    fn word_decoder_rejects_absent_and_corrupt_words() {
        // Kernel array-map default: all zero is not a lockdown word.
        assert!(decode_lockdown_word(0).is_none());

        let word = encode_lockdown_word(1, LOCKDOWN_MODE_ARMED, LOCKDOWN_FLAG_DROP_ALL);
        for magic in [0x00u8, 0x4B, 0x4D, 0xFF] {
            let corrupt = (word & !(0xffu64 << LOCKDOWN_STATE_MAGIC_SHIFT))
                | (u64::from(magic) << LOCKDOWN_STATE_MAGIC_SHIFT);
            assert!(decode_lockdown_word(corrupt).is_none(), "magic {magic:#04x}");
        }
        for abi in [0u8, 2, 0xFF] {
            let corrupt = (word & !(0xffu64 << LOCKDOWN_STATE_ABI_SHIFT))
                | (u64::from(abi) << LOCKDOWN_STATE_ABI_SHIFT);
            assert!(decode_lockdown_word(corrupt).is_none(), "abi {abi}");
        }
        for mode in 2..=u8::MAX {
            let corrupt = (word & !(0xffu64 << LOCKDOWN_STATE_MODE_SHIFT))
                | (u64::from(mode) << LOCKDOWN_STATE_MODE_SHIFT);
            assert!(decode_lockdown_word(corrupt).is_none(), "mode {mode}");
        }
    }

    #[test]
    fn reserved_flag_bits_are_carried_not_rejected() {
        // A future phase bit must not disarm an armed lockdown (no silent
        // fail-open); the decoder therefore only rejects magic/ABI/mode.
        let flags = LOCKDOWN_FLAGS_KNOWN | (1 << 7);
        let decoded = decode_lockdown_word(encode_lockdown_word(3, LOCKDOWN_MODE_ARMED, flags))
            .expect("unknown high flag bit is carried");
        assert_eq!(decoded.flags, flags);
        assert!(decoded.drops_network());
    }

    #[test]
    fn event_size_offsets_and_roundtrip_match_the_wire() {
        assert_eq!(core::mem::size_of::<LockdownEvent>(), LOCKDOWN_EVENT_WIRE_BYTES);
        assert_eq!(core::mem::offset_of!(LockdownEvent, epoch), 16);
        assert_eq!(core::mem::offset_of!(LockdownEvent, cgroup_id), 24);
        assert_eq!(core::mem::offset_of!(LockdownEvent, detail_u64), 32);
        assert_eq!(core::mem::offset_of!(LockdownEvent, reserved), 40);
        let event = sample_event();
        let bytes = encode_lockdown_event(&event);
        assert_eq!(bytes.len(), LOCKDOWN_EVENT_WIRE_BYTES);
        assert_eq!(decode_lockdown_event(&bytes), Some(event));
    }

    #[test]
    fn event_decoder_rejects_wrong_wire_length() {
        let bytes = encode_lockdown_event(&sample_event());
        assert!(decode_lockdown_event(&[]).is_none());
        assert!(decode_lockdown_event(&bytes[..63]).is_none());
        assert!(decode_lockdown_event(&[0u8; LOCKDOWN_EVENT_WIRE_BYTES + 1]).is_none());
    }

    #[test]
    fn event_decoder_rejects_the_documented_matrix() {
        let bytes = encode_lockdown_event(&sample_event());
        for zeroed in [0usize, 8] {
            let mut corrupt = bytes;
            corrupt[zeroed..zeroed + 8].copy_from_slice(&0u64.to_ne_bytes());
            assert!(decode_lockdown_event(&corrupt).is_none(), "zeroed at {zeroed}");
        }
        for (offset, invalid) in [
            (20usize, [0u8, 5, 0xFF].as_slice()), // source
            (21, [0u8, 9, 0xFF].as_slice()),      // reason
            (22, [9u8, 0xFF].as_slice()),         // phase (0 is valid)
            (23, [0u8, 6, 0xFF].as_slice()),      // outcome
        ] {
            for value in invalid {
                let mut corrupt = bytes;
                corrupt[offset] = *value;
                assert!(decode_lockdown_event(&corrupt).is_none(), "offset {offset} value {value}");
            }
        }
    }
}
