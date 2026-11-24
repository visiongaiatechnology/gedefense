//! `PERSIST_GUARD_PATHS` value layout, path-class predicates and the
//! `(s_dev, i_ino)` identity key helpers of the AP-5 contract.

/// Path map value bit: this identity is a watched *directory*; direct children
/// are matched through one bounded `dentry->d_parent` step.
pub const PERSIST_PATH_DIRECTORY_SHIFT: u64 = 63;
/// Path map value bits: path class (low byte).
pub const PERSIST_PATH_CLASS_MASK: u64 = 0xff;
/// Path map value bits: owning uid of the watched object.
pub const PERSIST_PATH_OWNER_SHIFT: u64 = 8;
pub const PERSIST_PATH_OWNER_MASK: u64 = 0xffff_ffff;
/// First reserved path-value bit after the owner uid (bits 40..62 must be zero).
pub const PERSIST_PATH_OWNER_LIMIT: u64 = 1 << 40;

// ---------------------------------------------------------------------------
// Closed-set predicates (shared by the decoder, eBPF and the Go parser)
// ---------------------------------------------------------------------------

/// True for the eleven persistence-path (integrity) classes.
#[inline(always)]
pub const fn persistence_class_is_integrity(class: u8) -> bool {
    matches!(class, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11)
}

/// True for the desktop peripheral device/capture-socket classes.
#[inline(always)]
pub const fn persistence_class_is_device(class: u8) -> bool {
    matches!(class, 20 | 21 | 22 | 23)
}

/// True for the user secret-store classes.
#[inline(always)]
pub const fn persistence_class_is_secret(class: u8) -> bool {
    matches!(class, 30 | 31 | 32 | 33 | 34)
}

/// True for every class value the ABI defines.
#[inline(always)]
pub const fn persistence_class_known(class: u8) -> bool {
    persistence_class_is_integrity(class)
        || persistence_class_is_device(class)
        || persistence_class_is_secret(class)
}

/// Packs one `PERSIST_GUARD_PATHS` value. `None` for a class outside the closed
/// set or an owner uid that does not fit the value layout.
#[inline(always)]
pub const fn persistence_path_value(class: u8, owner_uid: u32, directory: bool) -> Option<u64> {
    if !persistence_class_known(class) {
        return None;
    }
    let owner = (owner_uid as u64) << PERSIST_PATH_OWNER_SHIFT;
    let dir = if directory {
        1u64 << PERSIST_PATH_DIRECTORY_SHIFT
    } else {
        0
    };
    Some((class as u64) | owner | dir)
}

/// Path class of one `PERSIST_GUARD_PATHS` value.
#[inline(always)]
pub const fn persistence_path_class(value: u64) -> u8 {
    (value & PERSIST_PATH_CLASS_MASK) as u8
}

/// Owning uid of one `PERSIST_GUARD_PATHS` value.
#[inline(always)]
pub const fn persistence_path_owner_uid(value: u64) -> u32 {
    ((value >> PERSIST_PATH_OWNER_SHIFT) & PERSIST_PATH_OWNER_MASK) as u32
}

/// True when one `PERSIST_GUARD_PATHS` value marks a watched directory.
#[inline(always)]
pub const fn persistence_path_is_directory(value: u64) -> bool {
    (value >> PERSIST_PATH_DIRECTORY_SHIFT) & 1 == 1
}

/// True when one map value can only have been written by the core: known class
/// and no reserved bits. Bits 40..62 are reserved and must be zero; bit 63 is
/// the directory flag.
#[inline(always)]
pub const fn persistence_path_value_valid(value: u64) -> bool {
    let class = persistence_path_class(value);
    if !persistence_class_known(class) {
        return false;
    }
    ((value >> 40) & 0x007f_ffff) == 0
}

// ---------------------------------------------------------------------------
// Identity keys
// ---------------------------------------------------------------------------

/// Wire size of one identity-map key (`s_dev u32 LE | i_ino u64 LE | zero4`).
pub const PERSIST_IDENTITY_KEY_BYTES: usize = 16;

/// Packs one `(s_dev, i_ino)` identity as the 16-byte map key.
#[inline(always)]
pub const fn persistence_identity_key(dev: u32, ino: u64) -> [u8; PERSIST_IDENTITY_KEY_BYTES] {
    let mut key = [0u8; PERSIST_IDENTITY_KEY_BYTES];
    key[0] = (dev & 0xff) as u8;
    key[1] = ((dev >> 8) & 0xff) as u8;
    key[2] = ((dev >> 16) & 0xff) as u8;
    key[3] = ((dev >> 24) & 0xff) as u8;
    let mut index = 0usize;
    while index < 8 {
        key[4 + index] = ((ino >> (index * 8)) & 0xff) as u8;
        index += 1;
    }
    key
}

/// Unpacks a 16-byte identity key; `None` for a wrong length, non-zero reserved
/// bytes or a zero identity (no kernel inode has that identity, so such a key
/// can only be an uninitialised value and must never match a policy).
pub fn decode_persistence_identity_key(key: &[u8]) -> Option<(u32, u64)> {
    if key.len() != PERSIST_IDENTITY_KEY_BYTES {
        return None;
    }
    let mut raw = [0u8; PERSIST_IDENTITY_KEY_BYTES];
    raw.copy_from_slice(key);
    if raw[12..16] != [0u8; 4] {
        return None;
    }
    let dev = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let ino = u64::from_le_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    if dev == 0 || ino == 0 {
        return None;
    }
    Some((dev, ino))
}
