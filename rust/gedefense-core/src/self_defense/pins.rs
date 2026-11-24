use super::*;

/// Health of one expected pin.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PinState {
    Healthy,
    Missing,
    Replaced,
}

/// One expected pin: the file identity the manifest was created with.
pub(super) struct PinEntry {
    pub(super) name: &'static str,
    pub(super) path: PathBuf,
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) state: PinState,
}

// -------------------------------------------------------------------- helpers

pub(super) fn validate_pin_root(pin_root: &str) -> Option<PathBuf> {
    let path = PathBuf::from(pin_root);
    if !path.is_absolute() || path == Path::new("/") {
        return None;
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    if components.any(|component| !matches!(component, Component::Normal(_))) {
        return None;
    }
    Some(path)
}

/// Creates the pin root and proves it really is a BPF filesystem. A directory
/// on tmpfs/sysfs is not a valid pin target: reporting `pins=unavailable` is
/// honest, silently pinning somewhere else would be a lie.
pub(super) fn prepare_pin_root(root: &Path) -> Result<(), u32> {
    fs::create_dir_all(root).map_err(|_| CODE_PIN_ROOT_CREATE)?;
    let metadata = fs::symlink_metadata(root).map_err(|_| CODE_PIN_ROOT_CREATE)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CODE_PIN_ROOT_CREATE);
    }
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| CODE_PIN_ROOT_INVALID)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(CODE_PIN_ROOT_CREATE);
    }
    if stat.f_type as u64 != BPF_FS_MAGIC {
        return Err(CODE_PIN_ROOT_NOT_BPFFS);
    }
    Ok(())
}
