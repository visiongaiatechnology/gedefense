//! M2.2 core owner of the `RANSOM_*` maps: mandatory map lookup, optional
//! kprobe attach, armed state, event drain and health counters.

use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::{KProbe, ProgramError},
    Ebpf,
};
use gedefense_common::{RANSOM_TRUST_FULL, RANSOM_TRUST_POOL_METADATA};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

use super::{
    policy::{MAX_RANSOM_PAYLOAD_BYTES, RANSOM_KPROBES, POOL_SERVICE_COMMS, TRUSTED_COMMS},
    queue::{lock_queue, RansomQueue},
    signals::{encode_state_word, random_epoch},
    watcher::spawn_watcher,
    BoxError,
};

/// Ransomware sensor state owned by the core.
pub(crate) struct RansomCore {
    _events: Option<RingBuf<MapData>>,
    state: AyaArray<MapData, u64>,
    trusted_comm: AyaHashMap<MapData, [u8; 16], u8>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    track_failures: PerCpuArray<MapData, u64>,
    queue: Arc<Mutex<RansomQueue>>,
    stop_watcher: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    epoch: u64,
    attached: bool,
    armed: bool,
    last_ring_drops: u64,
}

impl Drop for RansomCore {
    fn drop(&mut self) {
        self.stop_watcher.store(true, Ordering::Release);
        if let Some(handle) = self.watcher.take() {
            let _ = handle.join();
        }
    }
}

impl RansomCore {
    /// Takes the mandatory maps, populates the trusted-comm exemptions and
    /// attaches the three optional kprobes. Errors only for a missing/
    /// incompatible object, never for an unavailable kprobe.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_EVENTS")).ok_or("RANSOM_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_STATE")).ok_or("RANSOM_STATE missing")?,
        )?;
        let trusted_comm = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_TRUSTED_COMM"))
                .ok_or("RANSOM_TRUSTED_COMM missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_EVENTS_EMITTED"))
                .ok_or("RANSOM_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_RING_DROPS")).ok_or("RANSOM_RING_DROPS missing")?,
        )?;
        let track_failures = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("RANSOM_TRACK_FAILURES"))
                .ok_or("RANSOM_TRACK_FAILURES missing")?,
        )?;
        let queue = Arc::new(Mutex::new(RansomQueue::default()));
        let stop_watcher = Arc::new(AtomicBool::new(false));
        let mut core = Self {
            _events: Some(events),
            state,
            trusted_comm,
            emitted,
            ring_drops,
            track_failures,
            queue,
            stop_watcher,
            watcher: None,
            epoch: random_epoch(),
            attached: false,
            armed: false,
            last_ring_drops: 0,
        };
        core.populate_trusted_comm()?;
        core.attach_kprobes(ebpf);
        // Fail-safe default for the endpoint P1 mitigation: arm as soon as at
        // least one kprobe is attached and launch the <= 10 ms ringbuf watcher
        // so non-trusted groups are frozen immediately via SIGSTOP without
        // waiting for the control plane's 100 ms IPC drain tick.
        let armed_at_load = core.attached;
        core.set_armed(armed_at_load)?;
        if core.attached {
            if let Some(ring) = core._events.take() {
                core.watcher = Some(spawn_watcher(
                    ring,
                    Arc::clone(&core.queue),
                    Arc::clone(&core.stop_watcher),
                )?);
            }
        }
        eprintln!(
            "GeDefense ransomware sensor: armed={} attached={} watcher={} trusted_comms={}",
            u8::from(armed_at_load),
            core.attached,
            u8::from(core.watcher.is_some()),
            TRUSTED_COMMS.len()
        );
        Ok(core)
    }

    fn insert_comm_tier(&mut self, comms: &[&str], tier: u8) -> Result<(), BoxError> {
        for name in comms {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() >= 16 {
                return Err("trusted comm entry exceeds the task-name ABI".into());
            }
            let mut key = [0u8; 16];
            key[..bytes.len()].copy_from_slice(bytes);
            self.trusted_comm.insert(&key, tier, 0)?;
        }
        Ok(())
    }

    fn populate_trusted_comm(&mut self) -> Result<(), BoxError> {
        self.insert_comm_tier(TRUSTED_COMMS, RANSOM_TRUST_FULL)?;
        self.insert_comm_tier(POOL_SERVICE_COMMS, RANSOM_TRUST_POOL_METADATA)?;
        Ok(())
    }

    /// Best-effort attach: a kernel without kprobe support keeps the rest of
    /// the core alive, and `RANSOM_STATUS` reports `attached=0` honestly.
    fn attach_kprobes(&mut self, ebpf: &mut Ebpf) {
        for (program_name, symbol) in RANSOM_KPROBES {
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
                eprintln!("ransomware kprobe program {program_name} missing; sensor stays audit-only");
                continue;
            };
            let result = (|| -> Result<(), ProgramError> {
                let kprobe: &mut KProbe = program.try_into()?;
                kprobe.load()?;
                kprobe.attach(*symbol, 0)?;
                Ok(())
            })();
            match result {
                Ok(()) => self.attached = true,
                Err(error) => eprintln!(
                    "ransomware kprobe {symbol} unavailable ({error}); continuing without it"
                ),
            }
        }
    }

    /// Writes the armed state word (`epoch | armed | magic | abi`).
    fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(0, word, 0)?;
        self.armed = armed;
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }

    /// §M2.2 IPC: `RANSOM_SET <0|1>`.
    pub(crate) fn set_armed_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("RANSOM_SET accepts 0 or 1".into()),
        }
    }

    /// Pops up to 8 pre-frozen 8-field records drained by the watcher thread.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let (records, dropped_local, rejected) = {
            let mut queue = lock_queue(&self.queue);
            let (records, dropped_local) = queue.pop_batch();
            let rejected = std::mem::take(&mut queue.rejected);
            (records, dropped_local, rejected)
        };
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
        let dropped_kernel = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        let dropped = dropped_kernel.saturating_add(dropped_local);
        if records.is_empty() {
            if dropped == 0 && rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        let payload = format!("{dropped}|{}", records.join(","));
        if payload.len() > MAX_RANSOM_PAYLOAD_BYTES {
            return Err("ransomware event batch exceeds the response payload budget".into());
        }
        Ok(payload)
    }

    /// Eight decimal health fields:
    /// `armed:attached:emitted:drops:stops_ok:stops_failed:stops_skipped:track_failures`.
    pub(crate) fn status(&self) -> Result<String, BoxError> {
        let emitted = Self::per_cpu_sum(&self.emitted)?;
        let drops = Self::per_cpu_sum(&self.ring_drops)?;
        let track_failures = Self::per_cpu_sum(&self.track_failures)?;
        let (stops_ok, stops_failed, stops_skipped) = {
            let queue = lock_queue(&self.queue);
            (queue.stops_ok, queue.stops_failed, queue.stops_skipped)
        };
        Ok(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            u8::from(self.armed),
            u8::from(self.attached),
            emitted,
            drops,
            stops_ok,
            stops_failed,
            stops_skipped,
            track_failures
        ))
    }

    fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}
