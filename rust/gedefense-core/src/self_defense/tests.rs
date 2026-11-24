#[cfg(test)]
mod tests {
    use super::super::*;

    fn empty_core() -> SelfDefenseCore {
        SelfDefenseCore::empty()
    }

    fn drain(core: &mut SelfDefenseCore) -> Vec<(u64, u8, u32, String)> {
        let payload = core.take_events().expect("drain succeeds");
        let (_, records) = payload.split_once('|').expect("wire has a drop separator");
        records
            .split(',')
            .filter(|record| !record.is_empty())
            .map(|record| {
                let fields: Vec<&str> = record.split(':').collect();
                assert_eq!(fields.len(), 4, "record must have four fields");
                (
                    fields[0].parse::<u64>().expect("ts"),
                    fields[1].parse::<u8>().expect("kind"),
                    fields[2].parse::<u32>().expect("detail code"),
                    fields[3].to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn take_events_is_bounded_and_reports_overflow_delta() {
        let mut core = empty_core();
        for index in 0..(TAMPER_QUEUE_CAPACITY + 6) {
            core.push_event(
                1_700_000_000_000 + index as u64,
                KIND_PIN_MISSING,
                index as u32,
                b"x",
            );
        }
        assert_eq!(core.queue.len(), TAMPER_QUEUE_CAPACITY);
        let payload = core.take_events().expect("drain succeeds");
        let (dropped, _) = payload.split_once('|').expect("separator");
        assert_eq!(dropped, "6");
        let events = drain(&mut core);
        assert_eq!(events.len(), MAX_EVENTS_PER_REPLY);
        for event in events {
            assert!(event.0 >= 1_700_000_000_000);
            assert!(event.1 <= KIND_CANARY_RECOVERED);
            assert!(event.3.len() <= MAX_DETAIL_BYTES * 2);
        }
        // The final drain reports the remaining records and no overflow twice.
        let mut remaining = 0usize;
        while core.take_events().expect("drain succeeds") != "empty" {
            remaining += 1;
            if remaining > TAMPER_QUEUE_CAPACITY {
                panic!("queue did not drain");
            }
        }
        // The explicit drain above plus the second one already consumed 16
        // records; the rest is 48 / 8 = 6 more non-empty drains, then "empty".
        assert_eq!(
            remaining,
            (TAMPER_QUEUE_CAPACITY - 2 * MAX_EVENTS_PER_REPLY) / MAX_EVENTS_PER_REPLY
        );
    }

    #[test]
    fn empty_queue_drains_to_the_empty_token() {
        let mut core = empty_core();
        assert_eq!(core.take_events().expect("drain succeeds"), "empty");
        core.dropped_pending = 2;
        assert_eq!(core.take_events().expect("drain succeeds"), "2|");
    }

    #[test]
    fn detail_is_truncated_to_the_contract_size() {
        let mut core = empty_core();
        core.push_event(1, KIND_PIN_REPLACED, 1, &[b'a'; 64]);
        let payload = core.take_events().expect("drain succeeds");
        let (_, records) = payload.split_once('|').expect("separator");
        let detail = records.split(':').nth(3).expect("detail");
        assert_eq!(detail.len(), MAX_DETAIL_BYTES * 2);
        assert_eq!(hex::decode(detail).expect("hex").len(), MAX_DETAIL_BYTES);
    }

    #[test]
    fn status_has_the_exact_bounded_fields_and_no_paths() {
        let mut core = empty_core();
        core.enabled = true;
        core.pins_usable = true;
        core.manifest.push(PinEntry {
            name: "EXEC_EVENTS",
            path: PathBuf::from("/secret/path/must/not/leak/EXEC_EVENTS"),
            dev: 1,
            ino: 2,
            state: PinState::Healthy,
        });
        core.push_event(7, KIND_PIN_MISSING, 1, b"EXEC_EVENTS");
        let status = core.status();
        assert!(!status.contains("/secret"));
        let fields: Vec<&str> = status.split(':').collect();
        assert_eq!(fields.len(), 9);
        let keys: Vec<&str> = fields
            .iter()
            .map(|field| field.split('=').next().expect("key"))
            .collect();
        assert_eq!(
            keys,
            [
                "enabled",
                "pins",
                "missing",
                "replaced",
                "canary",
                "canary_runs",
                "canary_failures",
                "events",
                "dropped"
            ]
        );
        assert!(status.contains("pins=1"));
        assert!(status.contains("events=1"));
        let mut unavailable = empty_core();
        assert!(unavailable.status().contains("pins=unavailable"));
        unavailable.enabled = true;
        assert!(unavailable.status().starts_with("enabled=1"));
    }

    #[test]
    fn set_enabled_token_is_closed() {
        let mut core = empty_core();
        assert_eq!(core.set_enabled_token("1").expect("arm"), "armed");
        assert!(core.enabled);
        assert_eq!(core.set_enabled_token("0").expect("disarm"), "disarmed");
        assert!(!core.enabled);
        for token in ["", "2", "true", " 1", "1 ", "armed"] {
            assert!(core.set_enabled_token(token).is_err(), "accepted {token:?}");
        }
    }

    #[test]
    fn pin_missing_and_replaced_transitions_are_reported_once() {
        let root = std::env::temp_dir().join(format!("gd-selfdef-pins-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temp pin dir");
        let path = root.join("EXEC_EVENTS");
        fs::write(&path, b"pin").expect("write pin file");
        let metadata = fs::metadata(&path).expect("pin metadata");
        // Created while the pin path still exists, so its inode is guaranteed to
        // differ from the pin's inode even on a filesystem that reuses freed
        // inode numbers.
        let other = root.join("other");
        fs::write(&other, b"other").expect("write second file");
        let mut core = SelfDefenseCore::empty();
        core.enabled = true;
        core.pins_usable = true;
        core.manifest.push(PinEntry {
            name: "EXEC_EVENTS",
            path: path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            state: PinState::Healthy,
        });
        core.pin_verify_due_ms = 0;
        core.poll(1_000);
        assert_eq!(core.take_events().expect("drain"), "empty");

        fs::remove_file(&path).expect("unlink pin");
        core.pin_verify_due_ms = 0;
        core.poll(2_000);
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_PIN_MISSING);
        assert_eq!(core.pins_missing, 1);

        // A persistent condition is not recorded again on the next verify.
        core.pin_verify_due_ms = 0;
        core.poll(3_000);
        assert_eq!(core.take_events().expect("drain"), "empty");

        // A different inode is a replacement, not a restore.
        fs::hard_link(&other, &path).expect("replace pin with another inode");
        core.pin_verify_due_ms = 0;
        core.poll(4_000);
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_PIN_REPLACED);
        assert_eq!(core.pins_replaced, 1);

        // Deleting it again restores the missing state once.
        fs::remove_file(&path).expect("unlink pin again");
        core.pin_verify_due_ms = 0;
        core.poll(5_000);
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_PIN_MISSING);
        assert_eq!(core.take_events().expect("drain"), "empty");

        // A non-regular node at the pin path is never treated as a pin.
        fs::create_dir(&path).expect("directory at pin path");
        core.pin_verify_due_ms = 0;
        core.poll(6_000);
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_PIN_REPLACED);
        assert_eq!(events[0].2, CODE_PIN_REPLACED_TYPE);
        let _ = fs::remove_dir(&path);
        let _ = fs::remove_file(&other);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn canary_watcher_parser_rejects_unknown_shapes() {
        let active =
            "roots=1:registered=2:queued=7:dropped=0:mark_failures=0:watcher=active:last_error=00";
        assert_eq!(parse_canary_status(active), Some((true, 7)));
        let degraded = active.replace("watcher=active", "watcher=degraded");
        assert_eq!(parse_canary_status(&degraded), Some((false, 7)));
        assert_eq!(parse_canary_status("roots=1:watcher=maybe:queued=0"), None);
        assert_eq!(parse_canary_status(""), None);
        assert_eq!(parse_canary_status("roots=1"), None);
        assert_eq!(parse_canary_status("watcher=active"), None);
        assert_eq!(parse_canary_status("roots=1:queued=x:watcher=active"), None);
        assert_eq!(
            parse_canary_status("roots=1:queued=0:watcher=active"),
            Some((true, 0))
        );
        assert_eq!(parse_canary_status(&"x".repeat(600)), None);
    }

    #[test]
    fn canary_event_requires_the_probe_pid_and_the_decoy_path() {
        let path = Path::new("/var/lib/vgt/gedefense/canaries/.vgt-self-test");
        let encoded = URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes());
        let batch = format!("0|4242:0:{encoded}:DOTENV:0");
        assert!(canary_batch_observed(&batch, path, 4242));
        assert!(!canary_batch_observed(&batch, path, 4243));
        assert!(!canary_batch_observed(
            &batch,
            Path::new("/var/lib/vgt/gedefense/canaries/other"),
            4242
        ));
        assert!(!canary_batch_observed("empty", path, 4242));
        assert!(!canary_batch_observed("0|", path, 4242));
        assert!(!canary_batch_observed("0|4242:0:%%%:DOTENV:0", path, 4242));
    }

    #[test]
    fn canary_failure_reports_one_record_and_recovery_clears_it() {
        let mut core = empty_core();
        core.enabled = true;
        // Applying outcomes directly keeps this test free of fanotify/root
        // requirements while covering the record contract.
        core.apply_canary_outcome(
            CanaryOutcome::SensorFailure {
                code: CODE_CANARY_NO_EVENT,
            },
            10_000,
        );
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_CANARY_DEAD);
        assert_eq!(core.canary_state.token(), "degraded");
        assert_eq!(core.canary_failures, 1);

        core.apply_canary_outcome(
            CanaryOutcome::SensorFailure {
                code: CODE_CANARY_NO_EVENT,
            },
            20_000,
        );
        assert_eq!(core.take_events().expect("drain"), "empty");
        assert_eq!(core.canary_failures, 2);

        core.apply_canary_outcome(CanaryOutcome::Success, 30_000);
        let events = drain(&mut core);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, KIND_CANARY_RECOVERED);
        assert_eq!(core.canary_state.token(), "active");
        assert_eq!(core.canary_runs, 1);
        assert_eq!(core.take_events().expect("drain"), "empty");
    }
}
