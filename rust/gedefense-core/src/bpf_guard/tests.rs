#[cfg(test)]
mod tests {
    use super::super::*;
use super::super::attach::*;
use super::super::drain::*;
    use gedefense_common::{
        BPF_GUARD_STATE_ABI, BPF_GUARD_STATE_ABI_SHIFT, BPF_GUARD_STATE_ARMED_SHIFT,
        BPF_GUARD_STATE_MAGIC, BPF_GUARD_STATE_MAGIC_SHIFT,
    };

    fn sample_event() -> BpfGuardEvent {
        BpfGuardEvent {
            ts_ns: 1_700_000_000_000_000_000,
            pid: 4242,
            tgid: 4241,
            uid: 1000,
            action: gedefense_common::BPF_GUARD_ACTION_OBSERVED,
            command: gedefense_common::BPF_GUARD_COMMAND_PROG_LOAD,
            prog_type: gedefense_common::BPF_GUARD_PROG_TYPE_LSM,
            reserved: 0,
            helper_mask: 0,
            helper_ids: [0; BPF_GUARD_HELPER_IDS_PER_EVENT],
            exe_dev: 0,
            exe_ino: 0,
            comm: *b"bpftool\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn state_word_carries_epoch_armed_magic_and_abi() {
        let word = encode_state_word(0xdead_beef_cafe_f00d, true);
        assert!(gedefense_common::bpf_guard_state_armed(word));
        assert_eq!((word & u64::from(u32::MAX)) as u32, 0xcafe_f00d);
        assert_eq!((word >> BPF_GUARD_STATE_ARMED_SHIFT) & 1, 1, "armed bit");
        assert_eq!(
            (word >> BPF_GUARD_STATE_MAGIC_SHIFT) & 0xff,
            u64::from(BPF_GUARD_STATE_MAGIC)
        );
        assert_eq!(
            (word >> BPF_GUARD_STATE_ABI_SHIFT) & 0xff,
            u64::from(BPF_GUARD_STATE_ABI)
        );
        assert!(!gedefense_common::bpf_guard_state_armed(encode_state_word(
            7, false
        )));
        assert!(!gedefense_common::bpf_guard_state_armed(0));
    }

    #[test]
    fn epoch_rendering_is_sixteen_lowercase_hex_chars() {
        let core_epoch = 0x0123_4567_89ab_cdefu64;
        assert_eq!(format!("{core_epoch:016x}"), "0123456789abcdef");
        let epoch = random_epoch();
        assert_ne!(epoch, 0);
        let rendered = format!("{epoch:016x}");
        assert_eq!(rendered.len(), 16);
        assert!(rendered
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn event_text_record_has_fifteen_bounded_fields() {
        let record = encode_event_text(&sample_event());
        assert_eq!(record.split(':').count(), 15);
        assert_eq!(
            record,
            "1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:627066746f6f6c"
        );
        // Worst-case 16-record batch fits the documented payload budget.
        let max_record = "18446744073709551615:4294967295:4294967295:4294967295:3:255:63:7:65535:65535:65535:65535:4294967295:18446744073709551615:00112233445566778899aabbccddeeff";
        assert!(max_record.split(':').count() == 15);
        let worst_batch =
            max_record.len() * BPF_GUARD_MAX_EVENTS_PER_DRAIN + BPF_GUARD_MAX_EVENTS_PER_DRAIN + 21;
        assert!(worst_batch <= BPF_GUARD_MAX_DRAIN_PAYLOAD_BYTES);
    }

    /// Minimal synthetic BTF image with one FUNC named `function`.
    fn synthetic_btf(function: &str) -> Vec<u8> {
        const HEADER: usize = 24;
        let strings = format!("\0{function}\0other\0");
        let func_name_off = 1u32;
        let mut types = Vec::new();
        // One FUNC type: name_off, info = kind(12) << 24, value = 0.
        types.extend_from_slice(&func_name_off.to_le_bytes());
        types.extend_from_slice(&(12u32 << 24).to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        let mut image = Vec::new();
        image.extend_from_slice(&0xeb9fu16.to_le_bytes());
        image.push(1);
        image.push(0);
        image.extend_from_slice(&(HEADER as u32).to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes()); // type_off
        image.extend_from_slice(&(types.len() as u32).to_le_bytes());
        image.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        image.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        image.extend_from_slice(&types);
        image.extend_from_slice(strings.as_bytes());
        image
    }

    #[test]
    fn btf_func_scan_answers_only_about_the_requested_function() {
        let image = synthetic_btf("check_helper_call");
        assert_eq!(btf_has_func_in(&image, "check_helper_call"), Ok(true));
        assert_eq!(btf_has_func_in(&image, "other"), Ok(false));
        assert_eq!(btf_has_func_in(&image, "absent"), Ok(false));

        let mut bad = image.clone();
        bad[0] ^= 0xff;
        assert!(btf_has_func_in(&bad, "check_helper_call").is_err());
        assert!(btf_has_func_in(&image[..16], "check_helper_call").is_err());
        let mut truncated = image;
        truncated.truncate(HEADER_TEST_LEN);
        assert!(btf_has_func_in(&truncated, "check_helper_call").is_err());
    }

    const HEADER_TEST_LEN: usize = 24;
}
