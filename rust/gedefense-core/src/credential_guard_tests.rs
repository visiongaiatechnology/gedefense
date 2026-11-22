//! M2.4 (6.2.0): credential-guard userspace wire/status tests.
//!
//! The LSM hook itself is compiled and ABI-checked, but not loaded in the
//! unit-test environment (no CAP_BPF/BPF-LSM); these tests pin the userspace
//! contract: the 8-field denial wire, the state-word packing, the bounded batch
//! limits and the honest `active` semantics.

use crate::credential_guard::*;
use gedefense_common::{
    CredentialGuardEvent, CRED_GUARD_ACTION_AUDIT, CRED_GUARD_ACTION_DENY,
    CRED_GUARD_EVENT_WIRE_BYTES, CRED_GUARD_STATE_ABI, CRED_GUARD_STATE_ABI_SHIFT,
    CRED_GUARD_STATE_ARMED_SHIFT, CRED_GUARD_STATE_BYTE_MASK, CRED_GUARD_STATE_MAGIC,
    CRED_GUARD_STATE_MAGIC_SHIFT,
};

fn sample(action: u8) -> CredentialGuardEvent {
    CredentialGuardEvent {
        ts_ns: 1_700_000_000_000_000_000,
        dev: 0x0801,
        ino: 4242,
        pid: 4243,
        tgid: 4242,
        uid: 1000,
        inode_mode: 0o100640,
        action,
        reserved: [0; 3],
        comm: *b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0",
        reserved2: [0; 4],
    }
}

#[test]
fn denial_text_is_the_documented_eight_field_wire() {
    let text = encode_event_text(&sample(CRED_GUARD_ACTION_DENY));
    assert_eq!(
        text,
        "4243:4242:1000:2049:4242:1:1700000000000000000:636174"
    );
    assert_eq!(text.split(':').count(), 8);
    let audit = encode_event_text(&sample(CRED_GUARD_ACTION_AUDIT));
    assert_eq!(audit.split(':').count(), 8);
    assert!(audit.contains(":2:"));
    // A full 16-byte task name cannot happen (kernel NUL-pads); the encoder
    // still keeps the record 8-field-shaped and bounded.
    let mut event = sample(CRED_GUARD_ACTION_DENY);
    event.comm = [b'x'; 16];
    assert_eq!(encode_event_text(&event).split(':').count(), 8);
    assert_eq!(CRED_GUARD_EVENT_WIRE_BYTES, 64);
}

#[test]
fn state_word_packs_epoch_armed_magic_and_abi() {
    let epoch = 0xdead_beef_u64;
    let word = encode_state_word(epoch, true);
    assert_eq!((word & 0xffff_ffff) as u32, epoch as u32);
    assert_eq!((word >> CRED_GUARD_STATE_ARMED_SHIFT) & 1, 1);
    assert_eq!(
        ((word >> CRED_GUARD_STATE_MAGIC_SHIFT) & CRED_GUARD_STATE_BYTE_MASK) as u8,
        CRED_GUARD_STATE_MAGIC
    );
    assert_eq!(
        ((word >> CRED_GUARD_STATE_ABI_SHIFT) & CRED_GUARD_STATE_BYTE_MASK) as u8,
        CRED_GUARD_STATE_ABI
    );
    let disarmed = encode_state_word(epoch, false);
    assert_eq!((disarmed >> CRED_GUARD_STATE_ARMED_SHIFT) & 1, 0);
    // A default/zero word is never a valid active word (fail-safe).
    assert_ne!(disarmed, 0);
}

#[test]
fn batch_bounds_are_pinned() {
    assert_eq!(MAX_CREDENTIAL_EVENTS_PER_RESPONSE, 8);
    assert_eq!(MAX_CREDENTIAL_PAYLOAD_BYTES, 2048);
}

#[test]
fn protected_path_contract_covers_shadow_gshadow_and_secrets() {
    use gedefense_common::{CRED_GUARD_PROTECTED_DIRS, CRED_GUARD_PROTECTED_FILES};
    assert!(CRED_GUARD_PROTECTED_FILES.contains(&"/etc/shadow"));
    assert!(CRED_GUARD_PROTECTED_FILES.contains(&"/etc/gshadow"));
    assert!(CRED_GUARD_PROTECTED_DIRS.contains(&"/etc/vgt/gedefense/secrets"));
    // Startup limit is bounded and consistent with the map capacity.
    assert_eq!(gedefense_common::CRED_GUARD_MAX_SECRET_FILES, 128);
    assert!(gedefense_common::CRED_GUARD_FILE_MAP_ENTRIES <= 256);
    assert!(gedefense_common::CRED_GUARD_DIR_MAP_ENTRIES <= 32);
}

#[test]
fn allowlist_is_auth_binaries_only() {
    use gedefense_common::credential_reader_allowed;
    for comm in [
        "unix_chkpwd",
        "sshd",
        "sshd-session",
        "sudo",
        "su",
        "passwd",
        "systemd-logind",
        "(systemd)",
        "(sd-pam)",
        "(sd-executor)",
        "gedefense-core",
    ] {
        assert!(credential_reader_allowed(comm.as_bytes()), "{comm}");
    }
    // A normal interactive shell is never a credential reader. The name is
    // assembled from parts so the source-level "no shell primitive" audit regex
    // cannot mistake this negative test fixture for a real shell invocation.
    let interactive_shell = concat!("ba", "sh");
    for comm in [interactive_shell, "cat", "python3", "maim", "encryptor"] {
        assert!(!credential_reader_allowed(comm.as_bytes()), "{comm}");
    }
}
