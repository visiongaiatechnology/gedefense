use super::*;

/// One bounded self-tamper record. `detail` is a fixed 32-byte buffer so the
/// queue never grows past its contract, and it is hex-encoded on the wire.
#[derive(Clone, Copy)]
pub(super) struct TamperRecord {
    pub(super) ts_ms: u64,
    pub(super) kind: u8,
    pub(super) detail_code: u32,
    pub(super) detail: [u8; MAX_DETAIL_BYTES],
    pub(super) detail_len: u8,
}

impl TamperRecord {
    pub(super) fn encode(&self) -> String {
        let detail_len = usize::from(self.detail_len).min(MAX_DETAIL_BYTES);
        format!(
            "{}:{}:{}:{}",
            self.ts_ms,
            self.kind,
            self.detail_code,
            hex::encode(&self.detail[..detail_len])
        )
    }
}

impl SelfDefenseCore {
    /// `SELF_GUARD_STATUS` -> bounded `key:value` health fields (no paths).
    pub(crate) fn status(&self) -> String {
        let pins = if self.pins_usable {
            self.manifest.len().to_string()
        } else {
            "unavailable".to_owned()
        };
        format!(
            "enabled={}:pins={}:missing={}:replaced={}:canary={}:canary_runs={}:canary_failures={}:events={}:dropped={}",
            u8::from(self.enabled),
            pins,
            self.pins_missing,
            self.pins_replaced,
            self.canary_state.token(),
            self.canary_runs,
            self.canary_failures,
            self.events_total,
            self.dropped_total
        )
    }

    // ------------------------------------------------------------------ state
}

impl SelfDefenseCore {
    /// Enqueues one bounded record. The queue is forcibly capped: an overflow
    /// is counted (and reported by the next drain) instead of growing memory.
    pub(super) fn push_event(&mut self, ts_ms: u64, kind: u8, detail_code: u32, detail: &[u8]) {
        self.events_total = self.events_total.saturating_add(1);
        if self.queue.len() >= TAMPER_QUEUE_CAPACITY {
            self.queue.pop_front();
            self.dropped_total = self.dropped_total.saturating_add(1);
            self.dropped_pending = self.dropped_pending.saturating_add(1);
        }
        let mut bounded = [0u8; MAX_DETAIL_BYTES];
        let detail_len = detail.len().min(MAX_DETAIL_BYTES);
        bounded[..detail_len].copy_from_slice(&detail[..detail_len]);
        self.queue.push_back(TamperRecord {
            ts_ms,
            kind,
            detail_code,
            detail: bounded,
            detail_len: detail_len as u8,
        });
    }

    // ------------------------------------------------------------- pin guard
}
