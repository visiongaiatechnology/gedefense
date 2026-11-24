#[cfg(test)]
mod tests {
    use super::super::*;
use super::super::attach::*;
    use gedefense_common::{
        kernel_hook_state_armed, kernel_hook_state_flags, KERNEL_HOOK_ACTION_AUDIT,
        KERNEL_HOOK_COMM_BYTES, KERNEL_HOOK_FLAG_ALL, KERNEL_HOOK_KIND_LSM_URING_CMD,
        KERNEL_HOOK_KIND_MODULE_LOAD, KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES,
        KERNEL_HOOK_MAX_EVENTS_PER_DRAIN, KERNEL_HOOK_STATE_ABI, KERNEL_HOOK_STATE_ABI_SHIFT,
        KERNEL_HOOK_STATE_ARMED_SHIFT, KERNEL_HOOK_STATE_MAGIC, KERNEL_HOOK_STATE_MAGIC_SHIFT,
    };

    /// Real `/sys/kernel/tracing/events/io_uring/io_uring_create/format` text
    /// from a 6.18 kernel (2026-11-24).
    const CREATE_FORMAT: &str = concat!(
        "name: io_uring_create\n",
        "ID: 2018\n",
        "format:\n",
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n",
        "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n",
        "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:int fd;\toffset:8;\tsize:4;\tsigned:1;\n",
        "\tfield:void * ctx;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:u32 sq_entries;\toffset:24;\tsize:4;\tsigned:0;\n",
        "\tfield:u32 cq_entries;\toffset:28;\tsize:4;\tsigned:0;\n",
        "\tfield:u32 flags;\toffset:32;\tsize:4;\tsigned:0;\n",
        "\n",
        "print fmt: \"ring %p, fd %d sq size %d, cq size %d, flags 0x%x\"\n",
    );

    /// Real `io_uring_register` format (6.18). The payload layout changed in
    /// 6.12 (`nr_args` -> `nr_files`/`nr_bufs`/`ret`), which is exactly why the
    /// offsets are derived at runtime instead of compiled in.
    const REGISTER_FORMAT: &str = concat!(
        "name: io_uring_register\n",
        "format:\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:void * ctx;\toffset:8;\tsize:8;\tsigned:0;\n",
        "\tfield:unsigned opcode;\toffset:16;\tsize:4;\tsigned:0;\n",
        "\tfield:unsigned nr_files;\toffset:20;\tsize:4;\tsigned:0;\n",
        "\tfield:unsigned nr_bufs;\toffset:24;\tsize:4;\tsigned:0;\n",
        "\tfield:long ret;\toffset:32;\tsize:8;\tsigned:1;\n",
    );

    const SUBMIT_FORMAT: &str = concat!(
        "name: io_uring_submit_req\n",
        "format:\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:void * ctx;\toffset:8;\tsize:8;\tsigned:0;\n",
        "\tfield:void * req;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:unsigned long long user_data;\toffset:24;\tsize:8;\tsigned:0;\n",
        "\tfield:u8 opcode;\toffset:32;\tsize:1;\tsigned:0;\n",
        "\tfield:unsigned long long flags;\toffset:40;\tsize:8;\tsigned:0;\n",
        "\tfield:bool sq_thread;\toffset:48;\tsize:1;\tsigned:0;\n",
        "\tfield:__data_loc char[] op_str;\toffset:52;\tsize:4;\tsigned:0;\n",
    );

    const MODULE_LOAD_FORMAT: &str = concat!(
        "name: module_load\n",
        "format:\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:unsigned int taints;\toffset:8;\tsize:4;\tsigned:0;\n",
        "\tfield:__data_loc char[] name;\toffset:12;\tsize:4;\tsigned:0;\n",
        "\n",
        "print fmt: \"%s %s\"\n",
    );

    fn sample_event(kind: u8, detail: &[u8]) -> KernelHookEvent {
        let mut bytes = [0u8; KERNEL_HOOK_DETAIL_BYTES];
        for (index, byte) in detail.iter().enumerate().take(KERNEL_HOOK_DETAIL_BYTES) {
            bytes[index] = *byte;
        }
        KernelHookEvent {
            ts_ns: 1_700_000_000_000_000_000,
            pid: 4242,
            tgid: 4241,
            uid: 1000,
            kind,
            action: KERNEL_HOOK_ACTION_AUDIT,
            detail_len: detail.len().min(KERNEL_HOOK_DETAIL_BYTES) as u8,
            reserved: 0,
            detail_code: 7,
            detail: bytes,
            comm: *b"fio\0\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn layout_derivation_uses_the_real_kernel_format_text() {
        let layout = derive_layout_from_formats(
            Some(CREATE_FORMAT),
            Some(REGISTER_FORMAT),
            Some(SUBMIT_FORMAT),
            Some(MODULE_LOAD_FORMAT),
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD as usize],
            8
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS as usize],
            32
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE as usize],
            16
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES as usize],
            20
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE as usize],
            32
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS as usize],
            8
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME as usize],
            12
        );
        assert_eq!(layout.known_fields(), 7);
    }

    #[test]
    fn layout_derivation_accepts_the_pre_6_12_register_field_name() {
        let legacy = REGISTER_FORMAT.replace("unsigned nr_files;", "unsigned nr_args;");
        let layout = derive_layout_from_formats(None, Some(&legacy), None, None);
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE as usize],
            16
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES as usize],
            20
        );
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD as usize],
            0
        );
    }

    #[test]
    fn unreadable_or_foreign_formats_degrade_to_zero_offsets() {
        let layout = derive_layout_from_formats(None, None, None, None);
        assert_eq!(layout, KernelHookLayout::empty());
        assert_eq!(layout.known_fields(), 0);
        // A format without the expected fields yields no invented offsets.
        let layout = derive_layout_from_formats(
            Some("name: io_uring_create\nformat:\n\tfield:int unrelated;\toffset:8;\tsize:4;\n"),
            None,
            None,
            None,
        );
        assert_eq!(layout.known_fields(), 0);
        // `offset:0` is a valid format offset but not a usable payload slot for
        // these fields: it must never be published as "known".
        let zero = "name: x\nformat:\n\tfield:u32 fd;\toffset:0;\tsize:4;\n";
        assert_eq!(field_offset_in_format(zero, &["fd"]), Some(0));
        let layout = derive_layout_from_formats(Some(zero), None, None, None);
        assert_eq!(
            layout.slots[KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD as usize],
            0
        );
    }

    #[test]
    fn format_parser_rejects_malformed_offsets() {
        assert_eq!(field_offset_in_format("", &["fd"]), None);
        assert_eq!(field_offset_in_format("garbage", &["fd"]), None);
        assert_eq!(
            field_offset_in_format("\tfield:int fd;\toffset:;\tsize:4;\n", &["fd"]),
            None
        );
        assert_eq!(
            field_offset_in_format("\tfield:int fd;\toffset:8x;\tsize:4;\n", &["fd"]),
            None
        );
        assert_eq!(
            field_offset_in_format("\tfield:int fd;\toffset:9999;\tsize:4;\n", &["fd"]),
            None
        );
        assert_eq!(
            field_offset_in_format("\tfield:int fd;\tsize:4;\n", &["fd"]),
            None
        );
        // A field without a declaration name cannot match anything.
        assert_eq!(
            field_offset_in_format("\tfield:;\toffset:8;\n", &["fd"]),
            None
        );
        // Exact name matching: `nr_files` must not be matched by `files`.
        assert_eq!(
            field_offset_in_format("\tfield:unsigned nr_files;\toffset:20;\n", &["files"]),
            None
        );
    }

    #[test]
    fn state_word_carries_epoch_armed_flags_magic_and_abi() {
        let word = kernel_hook_state_word(0xdead_beef, true, KERNEL_HOOK_FLAG_ALL);
        assert!(kernel_hook_state_armed(word));
        assert_eq!(kernel_hook_state_flags(word), KERNEL_HOOK_FLAG_ALL);
        assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
        assert_eq!((word >> KERNEL_HOOK_STATE_ARMED_SHIFT) & 1, 1, "armed bit");
        assert_eq!(
            (word >> KERNEL_HOOK_STATE_MAGIC_SHIFT) & 0xff,
            u64::from(KERNEL_HOOK_STATE_MAGIC)
        );
        assert_eq!(
            (word >> KERNEL_HOOK_STATE_ABI_SHIFT) & 0xff,
            u64::from(KERNEL_HOOK_STATE_ABI)
        );
        assert!(!kernel_hook_state_armed(kernel_hook_state_word(
            7, false, 0
        )));
    }

    #[test]
    fn epoch_rendering_is_sixteen_lowercase_hex_chars() {
        let epoch = random_epoch();
        assert_ne!(epoch, 0);
        let rendered = format!("{epoch:016x}");
        assert_eq!(rendered.len(), 16);
        assert!(rendered
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
    }

    #[test]
    fn event_text_record_has_nine_bounded_fields() {
        let event = sample_event(KERNEL_HOOK_KIND_MODULE_LOAD, b"evil_lkm");
        let record = encode_event_text(&event);
        assert_eq!(record.split(':').count(), 9);
        assert_eq!(
            record,
            "1700000000000000000:4242:4241:1000:4:1:7:66696f:6576696c5f6c6b6d"
        );
        // An empty detail still leaves the 9-field contract intact: the trailing
        // separator is present (the sample comm "fio" is not empty).
        let record = encode_event_text(&sample_event(KERNEL_HOOK_KIND_LSM_URING_CMD, b""));
        assert_eq!(record.split(':').count(), 9);
        assert!(record.ends_with(':'));
        assert_eq!(record, "1700000000000000000:4242:4241:1000:9:1:7:66696f:");
        // Identity-only with an empty comm leaves *both* trailing fields empty, so
        // the record legitimately ends with "::" (two separators, 9 fields).
        let mut identity_only = sample_event(KERNEL_HOOK_KIND_LSM_URING_CMD, b"");
        identity_only.comm = [0u8; KERNEL_HOOK_COMM_BYTES];
        let record = encode_event_text(&identity_only);
        assert_eq!(record.split(':').count(), 9);
        assert!(record.ends_with("::"));
        assert_eq!(record, "1700000000000000000:4242:4241:1000:9:1:7::");
        // Worst-case 16-record batch fits the documented payload budget.
        let max_record = "18446744073709551615:4294967295:4294967295:4294967295:255:255:4294967295:00112233445566778899aabbccddeeff:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(max_record.split(':').count(), 9);
        let worst_batch = max_record.len() * KERNEL_HOOK_MAX_EVENTS_PER_DRAIN
            + KERNEL_HOOK_MAX_EVENTS_PER_DRAIN
            + 21;
        assert!(worst_batch <= KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES);
    }

    #[test]
    fn status_string_has_the_exactly_ten_documented_fields() {
        let status = format_status(true, true, true, false, 2, 1, 11, 3, 4, 5);
        assert_eq!(
            status,
            "enabled=1:attached=1:io_uring=1:module_trace=0:kprobes=2:lsm_extra=1:events=11:drops=3:loads=4:ring_creates=5"
        );
        assert_eq!(status.split(':').count(), 10);
        let status = format_status(false, false, false, false, 0, 0, 0, 0, 0, 0);
        assert_eq!(
            status,
            "enabled=0:attached=0:io_uring=0:module_trace=0:kprobes=0:lsm_extra=0:events=0:drops=0:loads=0:ring_creates=0"
        );
    }

    #[test]
    fn kprobe_symbol_ladder_prefers_direct_arguments_and_handles_clones() {
        let symbols: Vec<String> = [
            "do_init_module",
            "init_module",
            "init_module.isra.0",
            "__x64_sys_init_module",
            "__x64_sys_init_module.constprop.0",
            "__do_sys_finit_module",
            "__x64_sys_finit_module",
            "__ia32_sys_finit_module",
            "delete_module",
            "unrelated",
            "titan_exec.attach",
        ]
        .iter()
        .map(|symbol| (*symbol).to_owned())
        .collect();

        let candidates = probe_symbol_candidates(&symbols, "init_module");
        assert_eq!(candidates.first().map(String::as_str), Some("init_module"));
        assert!(candidates.iter().any(|value| value == "init_module.isra.0"));
        assert!(candidates
            .iter()
            .any(|value| value == "__x64_sys_init_module"));
        assert!(!candidates.iter().any(|value| value == "do_init_module"));
        assert!(!candidates.iter().any(|value| value == "unrelated"));

        let candidates = probe_symbol_candidates(&symbols, "finit_module");
        // `__do_sys_finit_module` receives the real fd argument, so it must be
        // preferred over every `__*_sys_*` wrapper.
        assert_eq!(
            candidates.first().map(String::as_str),
            Some("__do_sys_finit_module")
        );
        assert!(candidates
            .iter()
            .any(|value| value == "__x64_sys_finit_module"));

        assert!(probe_symbol_candidates(&symbols, "delete_module").len() == 1);

        assert!(direct_arguments_symbol("init_module", "init_module"));
        assert!(direct_arguments_symbol("init_module.isra.0", "init_module"));
        assert!(direct_arguments_symbol(
            "__do_sys_finit_module",
            "finit_module"
        ));
        assert!(direct_arguments_symbol(
            "__se_sys_delete_module",
            "delete_module"
        ));
        assert!(!direct_arguments_symbol(
            "__x64_sys_finit_module",
            "finit_module"
        ));
        assert!(syscall_wrapper_symbol(
            "__x64_sys_finit_module",
            "finit_module"
        ));
        assert!(syscall_wrapper_symbol(
            "__ia32_sys_finit_module",
            "finit_module"
        ));
        assert!(!syscall_wrapper_symbol("init_module", "init_module"));
        assert_eq!(strip_clone_suffix("init_module.isra.0"), "init_module");
        assert_eq!(strip_clone_suffix("init_module"), "init_module");
    }

    #[test]
    fn absent_symbols_produce_no_kprobe_candidates() {
        let symbols: Vec<String> = ["do_init_module", "__x64_sys_read"]
            .iter()
            .map(|symbol| (*symbol).to_owned())
            .collect();
        assert!(probe_symbol_candidates(&symbols, "init_module").is_empty());
        assert!(probe_symbol_candidates(&[], "delete_module").is_empty());
    }
}
