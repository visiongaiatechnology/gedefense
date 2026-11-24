//! M2.2 low-latency ringbuf watcher: decodes `RansomEvent`s, resolves/filters
//! the target process group and freezes it before queueing the wire record.

use aya::maps::{MapData, RingBuf};
use crate::process_tree;
use gedefense_common::{decode_ransom_event, RANSOM_SIGNAL_RENAME_STORM};
use std::{
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use super::{
    policy::{RANSOM_POLL_TIMEOUT_MS, TRUSTED_COMMS},
    queue::{lock_queue, RansomQueue},
    signals::{encode_event_text, reason_token},
    BoxError,
};

pub(crate) fn spawn_watcher(
    mut events: RingBuf<MapData>,
    queue: Arc<Mutex<RansomQueue>>,
    stop: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, BoxError> {
    let handle = thread::Builder::new()
        .name("gedefense-ransom-watch".to_owned())
        .spawn(move || {
            let ring_fd = events.as_raw_fd();
            while !stop.load(Ordering::Acquire) {
                while let Some(item) = events.next() {
                    process_ring_item(&item, &queue);
                }
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let mut pfd = libc::pollfd {
                    fd: ring_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `pfd` points to a single initialized `pollfd` on the stack with `nfds = 1`.
                let ready = unsafe { libc::poll(&mut pfd, 1, RANSOM_POLL_TIMEOUT_MS) };
                if ready < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    thread::sleep(Duration::from_millis(RANSOM_POLL_TIMEOUT_MS as u64));
                }
            }
        })?;
    Ok(handle)
}

fn process_ring_item(raw: &[u8], queue: &Mutex<RansomQueue>) {
    let Some(event) = decode_ransom_event(raw) else {
        let mut guard = lock_queue(queue);
        guard.rejected = guard.rejected.saturating_add(1);
        return;
    };
    let rule = reason_token(event.signal);
    // Resolve the real PGID: the kernel event names the TGID only.
    let pgid = process_tree::process_group_of(event.tgid as i32).unwrap_or(0);
    if pgid <= 0 {
        let mut guard = lock_queue(queue);
        guard.stops_failed = guard.stops_failed.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        eprintln!(
            "GeDefense ransomware freeze skipped tgid={} (process vanished before PGID lookup)",
            event.tgid
        );
        return;
    }
    if pgid == 1 {
        let mut guard = lock_queue(queue);
        guard.stops_failed = guard.stops_failed.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        guard.push_record(encode_event_text(&event, pgid));
        eprintln!(
            "GeDefense ransomware freeze skipped tgid={} pgid=1 (init group protected)",
            event.tgid
        );
        return;
    }
    let pooled_worker = process_tree::is_service_pool_worker(event.tgid as i32)
        .unwrap_or(false);
    if pooled_worker && event.signal == RANSOM_SIGNAL_RENAME_STORM {
        let mut guard = lock_queue(queue);
        guard.stops_skipped = guard.stops_skipped.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        return;
    }
    // FP guard: never freeze or queue for tree-kill a group that contains a
    // trusted package/build/service comm or a protected core/init/systemd task.
    let exempt = match process_tree::process_group_has_trusted_comm(pgid, TRUSTED_COMMS) {
        Ok(true) => Ok(true),
        Ok(false) => process_tree::process_group_has_protected_target(pgid),
        Err(error) => Err(error),
    };
    match exempt {
        Ok(true) => {
            let mut guard = lock_queue(queue);
            guard.stops_skipped = guard.stops_skipped.saturating_add(1);
            guard.last_event_ts = event.ts_ns;
            eprintln!(
                "GeDefense ransomware freeze skipped exempt/protected group tgid={} pgid={pgid}",
                event.tgid
            );
            return;
        }
        Ok(false) => {
            // A pooled worker (e.g. compromised php-fpm child sharing the master PGID)
            // is frozen by PID/descendants alone so healthy pool siblings keep serving.
            let stop_result = if pooled_worker {
                process_tree::stop_process_descendants(event.tgid as i32, rule)
            } else {
                process_tree::stop_process_group(pgid, rule)
            };
            let mut guard = lock_queue(queue);
            match stop_result {
                Ok(()) => guard.stops_ok = guard.stops_ok.saturating_add(1),
                Err(error) => {
                    guard.stops_failed = guard.stops_failed.saturating_add(1);
                    eprintln!(
                        "GeDefense ransomware freeze failed tgid={} pgid={pgid} error={error}",
                        event.tgid
                    );
                }
            }
            guard.last_event_ts = event.ts_ns;
            guard.push_record(encode_event_text(&event, pgid));
        }
        Err(error) => {
            let mut guard = lock_queue(queue);
            guard.stops_failed = guard.stops_failed.saturating_add(1);
            guard.last_event_ts = event.ts_ns;
            guard.push_record(encode_event_text(&event, pgid));
            eprintln!(
                "GeDefense ransomware freeze skipped tgid={} pgid={pgid}: exemption check failed: {error}",
                event.tgid
            );
        }
    }
}
