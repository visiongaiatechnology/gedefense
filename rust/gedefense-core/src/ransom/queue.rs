//! M2.2 bounded FIFO between the low-latency watcher thread and the
//! `RANSOM_EVENTS` IPC drain.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::policy::{MAX_PENDING_RANSOM_RECORDS, MAX_RANSOM_EVENTS_PER_RESPONSE, MAX_RANSOM_PAYLOAD_BYTES};

#[derive(Default)]
pub(crate) struct RansomQueue {
    records: VecDeque<String>,
    dropped_local: u64,
    pub(crate) rejected: u64,
    pub(crate) stops_ok: u64,
    pub(crate) stops_failed: u64,
    pub(crate) stops_skipped: u64,
    pub(crate) last_event_ts: u64,
}

impl RansomQueue {
    pub(crate) fn push_record(&mut self, record: String) {
        if self.records.len() >= MAX_PENDING_RANSOM_RECORDS {
            self.records.pop_front();
            self.dropped_local = self.dropped_local.saturating_add(1);
        }
        self.records.push_back(record);
    }

    pub(crate) fn pop_batch(&mut self) -> (Vec<String>, u64) {
        let mut records = Vec::with_capacity(MAX_RANSOM_EVENTS_PER_RESPONSE);
        let mut total_bytes = 0usize;
        while records.len() < MAX_RANSOM_EVENTS_PER_RESPONSE {
            let Some(front) = self.records.front() else {
                break;
            };
            // Reserve room for "<dropped>|" prefix and comma separator inside 2048 B.
            let separator = usize::from(!records.is_empty());
            if total_bytes.saturating_add(separator).saturating_add(front.len())
                > MAX_RANSOM_PAYLOAD_BYTES.saturating_sub(32)
            {
                break;
            }
            if let Some(record) = self.records.pop_front() {
                total_bytes = total_bytes.saturating_add(separator).saturating_add(record.len());
                records.push(record);
            }
        }
        let dropped_local = self.dropped_local;
        self.dropped_local = 0;
        (records, dropped_local)
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.records.len()
    }
}

pub(crate) fn lock_queue(queue: &Mutex<RansomQueue>) -> std::sync::MutexGuard<'_, RansomQueue> {
    queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
