//! Wave 3a extraction: ring-buffer consumers and their bounded response helpers
//! (`EXEC_EVENTS`, `INGRESS_EVENTS`, `EGRESS_EVENTS`, `FLOW_EVENTS`, ingress
//! flood backpressure) formerly inline in `main.rs`.

use crate::*;

pub(crate) const MAX_EXEC_EVENTS_PER_RESPONSE: usize = 24;
pub(crate) const MAX_EGRESS_EVENTS_PER_RESPONSE: usize = 24;
pub(crate) const MAX_INGRESS_EVENTS_PER_RESPONSE: usize = 12;
// How many undecodable ingress samples in a single drain mean the wire format itself is wrong.
//
// One such sample is a loss of fidelity and is skipped; a batch full of them is a real fault, and
// the control plane has to be told so the operator sees a sensor that receives nothing instead of
// a sensor that looks healthy. The threshold is far above the sporadic rate a busy host produces,
// so it cannot be tripped by ordinary mixed-protocol aggregates.
pub(crate) const INGRESS_REJECTED_ALARM_THRESHOLD: u64 = 16;

impl KernelCore {
    pub(crate) fn take_exec_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EXEC_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EXEC_EVENTS_PER_RESPONSE {
            let Some(item) = self.exec_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<ExecEvent>() {
                return Err("kernel exec event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let gid = u32::from_ne_bytes(item[8..12].try_into()?);
            let comm: [u8; EXEC_COMM_BYTES] = item[12..12 + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{gid}:{}",
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    pub(crate) fn per_cpu_counter_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }

    /// §5 PING: the existing mode token plus the additive lockdown state.
    pub(crate) fn ping_mode(&self) -> String {
        format!("{}{}", self.mode, self.lockdown.ping_suffix())
    }

    pub(crate) fn ingress_health(&self) -> Result<String, BoxError> {
        let emitted = Self::per_cpu_counter_sum(&self.ingress_events_emitted)?;
        let ring_drops = Self::per_cpu_counter_sum(&self.ingress_ring_drops)?;
        let track_insert_failures = Self::per_cpu_counter_sum(&self.ingress_track_insert_failures)?;
        // A fourth field, appended rather than inserted so a control plane from before
        // this change still parses the response. The mode is what an operator needs in
        // order to know whether the kernel enforces in the driver path, in the generic
        // path, or only at the traffic-control layer.
        Ok(format!(
            "{emitted}:{ring_drops}:{track_insert_failures}:{}",
            self.ingress_mode
        ))
    }

    pub(crate) fn take_ingress_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_INGRESS_EVENTS_PER_RESPONSE);
        let mut rejected = 0u64;
        while encoded.len() < MAX_INGRESS_EVENTS_PER_RESPONSE {
            let Some(item) = self.ingress_events.next() else {
                break;
            };
            // One undecodable sample is skipped and named, not fatal.
            //
            // Returning an error here failed the entire drain, and the control plane reads a
            // failed drain as a lost kernel hook: the mandatory ingress sensor was declared
            // degraded, every automatic decision paused, and before the fail-closed change the
            // release gate emptied the kernel blocklist outright - a production host was found
            // unprotected twenty hours later. A record this process cannot interpret is a loss
            // of fidelity; it must not cost the protection.
            let Some(event) = decode_ingress_event(&item) else {
                if rejected < 4 {
                    eprintln!(
                        "kernel ingress sample rejected: {} bytes; size, family or counters are not consistent",
                        item.len()
                    );
                }
                rejected = rejected.saturating_add(1);
                continue;
            };
            let address_len = if event.family == NETWORK_FAMILY_V4 {
                4
            } else {
                NETWORK_ADDRESS_BYTES
            };
            encoded.push(format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                event.family,
                event.protocol,
                event.tcp_flags,
                event.attempt_count,
                event.src_port,
                event.dst_port,
                event.packets,
                event.bytes,
                event.syn_count,
                event.ack_count,
                event.window_epoch_sec,
                hex::encode(&event.source[..address_len]),
                hex::encode(&event.destination[..address_len])
            ));
        }
        // A batch in which many samples cannot be decoded states something else: the wire format
        // itself does not match what this core expects. That is a real fault and the operator has
        // to hear about it, rather than being left with a sensor that silently receives nothing.
        if rejected >= INGRESS_REJECTED_ALARM_THRESHOLD {
            return Err(format!(
                "kernel ingress event format is inconsistent: {rejected} samples rejected in one drain"
            )
            .into());
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    pub(crate) fn take_egress_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EGRESS_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EGRESS_EVENTS_PER_RESPONSE {
            let Some(item) = self.egress_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<EgressDropEvent>() {
                return Err("kernel egress event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let family = item[8];
            let protocol = item[9];
            let action = item[10];
            if action != ACTION_DROP || !matches!(family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6) {
                return Err("kernel egress event has invalid metadata".into());
            }
            let address_len = if family == NETWORK_FAMILY_V4 {
                4
            } else {
                NETWORK_ADDRESS_BYTES
            };
            let destination = &item[12..12 + address_len];
            let comm_start = 12 + NETWORK_ADDRESS_BYTES;
            let comm: [u8; EXEC_COMM_BYTES] =
                item[comm_start..comm_start + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{family}:{protocol}:{}:{}",
                hex::encode(destination),
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }
}

impl KernelCore {
    pub(crate) fn styx_take_flow_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE);
        while records.len() < styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE {
            let Some(item) = self.styx_flow_events.next() else {
                break;
            };
            if item.len() != STYX_FLOW_EVENT_WIRE_BYTES {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            }
            // A record this core cannot decode is skipped and counted, never a
            // reason to abort the drain (§3.2: no degradation on first miss).
            let Some(event) = decode_styx_flow_event(&item) else {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            };
            let Some(encoded) = styx_flow::encode_styx_flow_event_text(&event) else {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            };
            records.push(encoded);
        }
        let ring_drops = Self::per_cpu_counter_sum(&self.styx_ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.styx_last_ring_drops);
        self.styx_last_ring_drops = ring_drops;
        let response = styx_flow_batch_response(&records, dropped);
        if response.len() > styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES {
            return Err("styx flow batch exceeds the response payload budget".into());
        }
        Ok(response)
    }
}

impl KernelCore {
    pub(crate) fn styx_flow_health(&self) -> Result<String, BoxError> {
        let counters = [
            Self::per_cpu_counter_sum(&self.styx_flow_emitted)?,
            Self::per_cpu_counter_sum(&self.styx_ring_drops)?,
            Self::per_cpu_counter_sum(&self.styx_agg_insert_failures)?,
            Self::per_cpu_counter_sum(&self.styx_egress_parse_errors)?,
            Self::per_cpu_counter_sum(&self.styx_egress_drops_total)?,
            Self::per_cpu_counter_sum(&self.styx_egress_policy_drops)?,
        ];
        Ok(styx_flow::encode_styx_flow_health(&counters))
    }
}

/// §3.3 response shape: `empty` only for a truly idle poll. A drop-only poll
/// still reports the FLOW_RING_DROPS delta (`<dropped>|`) so the control plane
/// can see the visibility loss instead of a silent "no events".
pub(crate) fn styx_flow_batch_response(records: &[String], dropped: u64) -> String {
    if records.is_empty() {
        if dropped == 0 {
            "empty".to_owned()
        } else {
            format!("{dropped}|")
        }
    } else {
        format!("{dropped}|{}", records.join(","))
    }
}
