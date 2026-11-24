use super::*;

/// Resolved tracepoint payload offsets. `0` means "unknown on this kernel".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct KernelHookLayout {
    pub(super) slots: [u32; KERNEL_HOOK_OFFSET_SLOTS as usize],
}

impl KernelHookLayout {
    pub(super) const fn empty() -> Self {
        Self {
            slots: [0u32; KERNEL_HOOK_OFFSET_SLOTS as usize],
        }
    }

    pub(super) fn set(&mut self, slot: u32, value: u32) {
        if let Some(entry) = self.slots.get_mut(slot as usize) {
            *entry = value;
        }
    }

    pub(super) fn known_fields(&self) -> usize {
        self.slots.iter().filter(|value| **value != 0).count()
    }
}

/// Derives the payload offsets from the four tracepoint format files.
pub(super) fn derive_layout() -> KernelHookLayout {
    let create = read_format_file("io_uring", "io_uring_create");
    let register = read_format_file("io_uring", "io_uring_register");
    let submit = read_format_file("io_uring", "io_uring_submit_req");
    let module_load = read_format_file("module", "module_load");
    eprintln!(
        "kernel hooks tracepoint format availability: io_uring_create={} io_uring_register={} io_uring_submit_req={} module_load={}",
        u8::from(create.is_some()),
        u8::from(register.is_some()),
        u8::from(submit.is_some()),
        u8::from(module_load.is_some())
    );
    derive_layout_from_formats(
        create.as_deref(),
        register.as_deref(),
        submit.as_deref(),
        module_load.as_deref(),
    )
}

/// Pure layout derivation (unit-tested against real kernel format text).
pub(super) fn derive_layout_from_formats(
    create: Option<&str>,
    register: Option<&str>,
    submit: Option<&str>,
    module_load: Option<&str>,
) -> KernelHookLayout {
    let mut layout = KernelHookLayout::empty();
    if let Some(text) = create {
        if let Some(offset) = field_offset_in_format(text, &["fd"]) {
            layout.set(KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD, offset);
        }
        if let Some(offset) = field_offset_in_format(text, &["flags"]) {
            layout.set(KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS, offset);
        }
    }
    if let Some(text) = register {
        if let Some(offset) = field_offset_in_format(text, &["opcode"]) {
            layout.set(KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE, offset);
        }
        // `nr_files` since 6.12; older kernels named the same information
        // `nr_args`. Either name carries the bounded registration arity.
        if let Some(offset) = field_offset_in_format(text, &["nr_files", "nr_args"]) {
            layout.set(KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES, offset);
        }
    }
    if let Some(text) = submit {
        if let Some(offset) = field_offset_in_format(text, &["opcode"]) {
            layout.set(KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE, offset);
        }
    }
    if let Some(text) = module_load {
        if let Some(offset) = field_offset_in_format(text, &["taints", "tainted"]) {
            layout.set(KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS, offset);
        }
        if let Some(offset) = field_offset_in_format(text, &["name"]) {
            layout.set(KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME, offset);
        }
    }
    layout
}

/// Reads one tracepoint format file from the tracefs event roots. Every failure
/// (missing mount, unreadable file, oversized file, non-UTF8 content) is `None`.
pub(super) fn read_format_file(category: &str, event: &str) -> Option<String> {
    for root in TRACEFS_EVENT_ROOTS {
        let path = format!("{root}/{category}/{event}/format");
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let mut data = Vec::new();
        if file
            .take(MAX_FORMAT_BYTES + 1)
            .read_to_end(&mut data)
            .is_err()
        {
            eprintln!("kernel hooks: read {path} failed");
            continue;
        }
        if data.len() as u64 > MAX_FORMAT_BYTES {
            eprintln!("kernel hooks: {path} exceeds the {MAX_FORMAT_BYTES}-byte bound");
            continue;
        }
        match String::from_utf8(data) {
            Ok(text) => return Some(text),
            Err(_) => {
                eprintln!("kernel hooks: {path} is not valid UTF-8");
                continue;
            }
        }
    }
    eprintln!("kernel hooks: tracepoint format {category}/{event} unreadable; slot stays 0");
    None
}

/// Extracts the `offset:` byte position of one tracepoint format field. The
/// first matching name wins; an unknown field or a malformed offset is `None`.
pub(super) fn field_offset_in_format(text: &str, names: &[&str]) -> Option<u32> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        let mut parts = rest.split(';');
        let declaration = parts.next().unwrap_or("");
        let Some(field_name) = declaration.split_whitespace().last() else {
            continue;
        };
        if !names.contains(&field_name) {
            continue;
        }
        for attribute in parts {
            let attribute = attribute.trim();
            let Some(value) = attribute.strip_prefix("offset:") else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            return value.parse::<u32>().ok().filter(|offset| *offset < 4096);
        }
        return None;
    }
    None
}
