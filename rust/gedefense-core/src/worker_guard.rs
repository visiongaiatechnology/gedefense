//! 6.1.0 Module B: privileged half of the worker crash-storm sensor.
//!
//! Owns the `WORKER_GUARD_*` maps and the `signal:signal_deliver` tracepoint
//! from `rust/gedefense-ebpf/src/worker_guard.rs`. The map lookups are
//! mandatory (a stale object fails loudly, like every other 6.x subsystem);
//! the attach itself is optional and reported honestly, because a kernel
//! without tracefs or with a restricted perf event paranoia still has to run
//! the rest of the core. The Go control plane never claims "active" unless
//! `attached=1` is in the status line.

use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use gedefense_common::{decode_worker_crash_event, WORKER_CRASH_EVENT_WIRE_BYTES};
use std::error::Error;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

const MAX_COMMS: usize = 256;
const MAX_UIDS: usize = 256;
const MAX_EVENTS_PER_RESPONSE: usize = 16;
const MAX_COMM_BYTES: usize = 15;

pub struct WorkerGuardCore {
    state: AyaArray<MapData, u64>,
    comms: AyaHashMap<MapData, [u8; 16], u8>,
    uids: AyaHashMap<MapData, u32, u8>,
    events: RingBuf<MapData>,
    emitted: PerCpuArray<MapData, u64>,
    drops: PerCpuArray<MapData, u64>,
    attached: bool,
    enabled: bool,
    comm_count: usize,
    uid_count: usize,
}

impl WorkerGuardCore {
    /// Takes the mandatory maps and attaches the signal tracepoint when the
    /// kernel permits it. Returns an error only for a missing/incompatible
    /// object, never for an unavailable tracepoint.
    pub fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_GUARD_STATE"))
                .ok_or("WORKER_GUARD_STATE missing")?,
        )?;
        let comms = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_COMMS")).ok_or("WORKER_COMMS missing")?,
        )?;
        let uids = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_UIDS")).ok_or("WORKER_UIDS missing")?,
        )?;
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_CRASH_EVENTS")).ok_or("WORKER_CRASH_EVENTS missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_CRASH_EMITTED"))
                .ok_or("WORKER_CRASH_EMITTED missing")?,
        )?;
        let drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("WORKER_CRASH_RING_DROPS"))
                .ok_or("WORKER_CRASH_RING_DROPS missing")?,
        )?;
        let attached = match ebpf.program_mut(&crate::chameleon::program_name("gedefense_worker_signal")) {
            Some(program) => {
                let program: &mut TracePoint = program.try_into()?;
                program.load()?;
                match program.attach("signal", "signal_deliver") {
                    Ok(_) => true,
                    Err(error) => {
                        eprintln!(
                            "Worker crash tracepoint unavailable ({error}); the guard reports inactive instead of claiming enforcement"
                        );
                        false
                    }
                }
            }
            None => {
                eprintln!("Worker crash tracepoint program missing from the eBPF object");
                false
            }
        };
        Ok(Self {
            state,
            comms,
            uids,
            events,
            emitted,
            drops,
            attached,
            enabled: false,
            comm_count: 0,
            uid_count: 0,
        })
    }

    pub fn set_enabled(&mut self, token: &str) -> Result<String, BoxError> {
        let enabled = match token {
            "0" => false,
            "1" => true,
            _ => return Err("worker guard state must be 0 or 1".into()),
        };
        self.state.set(0, u64::from(enabled), 0)?;
        self.enabled = enabled;
        Ok(self.status()?)
    }

    pub fn comm_add(&mut self, comm: &str) -> Result<String, BoxError> {
        let key = encode_comm(comm)?;
        if self.comms.get(&key, 0).is_err() {
            if self.comm_count >= MAX_COMMS {
                return Err("worker comm registry is full".into());
            }
            self.comm_count += 1;
        }
        self.comms.insert(key, 1u8, 0)?;
        Ok(self.status()?)
    }

    pub fn comm_del(&mut self, comm: &str) -> Result<String, BoxError> {
        let key = encode_comm(comm)?;
        match self.comms.remove(&key) {
            Ok(()) => {
                self.comm_count = self.comm_count.saturating_sub(1);
            }
            Err(aya::maps::MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(self.status()?)
    }

    pub fn uid_add(&mut self, uid: &str) -> Result<String, BoxError> {
        let uid = parse_uid(uid)?;
        if self.uids.get(&uid, 0).is_err() {
            if self.uid_count >= MAX_UIDS {
                return Err("worker uid registry is full".into());
            }
            self.uid_count += 1;
        }
        self.uids.insert(uid, 1u8, 0)?;
        Ok(self.status()?)
    }

    pub fn uid_del(&mut self, uid: &str) -> Result<String, BoxError> {
        let uid = parse_uid(uid)?;
        match self.uids.remove(&uid) {
            Ok(()) => {
                self.uid_count = self.uid_count.saturating_sub(1);
            }
            Err(aya::maps::MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(self.status()?)
    }

    /// Drains at most 16 records, one per line. A malformed record is skipped
    /// (the kernel denial/enforcement already happened) instead of poisoning
    /// the batch.
    pub fn take_events(&mut self) -> Result<String, BoxError> {
        let mut lines = Vec::with_capacity(MAX_EVENTS_PER_RESPONSE);
        while lines.len() < MAX_EVENTS_PER_RESPONSE {
            let Some(item) = self.events.next() else {
                break;
            };
            if item.len() != WORKER_CRASH_EVENT_WIRE_BYTES {
                eprintln!("worker crash record has an invalid size; skipping");
                continue;
            }
            let Some(event) = decode_worker_crash_event(&item) else {
                continue;
            };
            let comm = String::from_utf8_lossy(&event.comm)
                .trim_end_matches('\0')
                .to_owned();
            lines.push(format!(
                "{}:{}:{}:{}:{}:{}:{}",
                event.pid,
                event.uid,
                event.gid,
                event.cgroup_id,
                event.signal,
                event.exit_code,
                hex::encode(comm.as_bytes())
            ));
        }
        if lines.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(lines.join("\n"))
        }
    }

    pub fn status(&self) -> Result<String, BoxError> {
        let emitted = per_cpu_sum(&self.emitted)?;
        let drops = per_cpu_sum(&self.drops)?;
        Ok(format!(
            "enabled={} attached={} comms={} uids={} emitted={} dropped={}",
            u8::from(self.enabled),
            u8::from(self.attached),
            self.comm_count,
            self.uid_count,
            emitted,
            drops
        ))
    }
}

fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
    let values = counter.get(&0, 0)?;
    Ok(values
        .iter()
        .copied()
        .fold(0u64, |sum, value| sum.saturating_add(value)))
}

fn encode_comm(comm: &str) -> Result<[u8; 16], BoxError> {
    let bytes = comm.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_COMM_BYTES || bytes.contains(&0) {
        return Err("worker comm must be 1..15 non-NUL bytes".into());
    }
    let mut key = [0u8; 16];
    key[..bytes.len()].copy_from_slice(bytes);
    Ok(key)
}

fn parse_uid(token: &str) -> Result<u32, BoxError> {
    if token.is_empty() || token.len() > 10 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err("worker uid must be a plain decimal integer".into());
    }
    Ok(token.parse::<u32>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_encoding_is_exact_and_bounded() {
        let key = encode_comm("php-fpm").expect("valid comm");
        assert_eq!(&key[..7], b"php-fpm");
        assert_eq!(&key[7..], &[0u8; 9]);
        assert!(encode_comm("").is_err());
        assert!(encode_comm("0123456789abcdef").is_err()); // 16 bytes
        assert!(encode_comm("bad\0comm").is_err());
    }

    #[test]
    fn uid_parsing_rejects_non_decimal() {
        assert_eq!(parse_uid("33").expect("uid"), 33);
        assert!(parse_uid("-1").is_err());
        assert!(parse_uid("1e3").is_err());
        assert!(parse_uid("").is_err());
    }
}
