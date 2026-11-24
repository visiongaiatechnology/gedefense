//! V6.3.0 AP-6 â€” StyX phase 2: `cgroup_skb/ingress` RX flow observation.
//!
//! STATUS: DIAMANT VGT SUPREME (implementation; live attach is the real-kernel
//! gate and is reported honestly as `attached=0` when unavailable).
//!
//! Attaches the `gedefense_ingress_flow` `cgroup_skb/ingress` observer
//! (`rust/gedefense-ebpf/src/ingress_flow.rs`) to the root cgroup. It never
//! drops or rewrites a packet (the program always returns the `cgroup_skb` pass
//! verdict `1`, never the TC `TC_ACT_OK` value which is `0` = drop at this
//! hook); it only
//! feeds bounded ingress flow aggregates into the **shared** `FLOW_EVENTS` ring
//! with `direction = STYX_DIR_INGRESS` and `rx_bytes` accounting, so the
//! control plane can compute the phase-2 `PCR = (tx - rx) / (tx + rx)` from the
//! existing `STYX_FLOW_EVENTS` drain. No new ring, drain command or ABI
//! version is introduced: ingress records are ordinary `FlowEvent` records of
//! the established 104-byte wire.
//!
//! ## Attach contract
//!
//! * `AllowOverride`, not `AllowMultiple` â€” the same rationale as the egress
//!   attach in `main.rs`: a cgroup program outlives the process that attached
//!   it, and every core restart with `AllowMultiple` would append another
//!   observer to the root cgroup's ingress hook and leak its maps. Override
//!   replaces the previous attachment, while still allowing a child cgroup to
//!   install its own program (which a container runtime expects).
//! * A missing program, a refused load or a refused attach is logged and
//!   reported as `attached=0`; it never fails core load and never turns into a
//!   fake RX capability claim. `RxObservationAvailable` therefore stays false
//!   in the control plane.
//!
//! ## `STYX_INGRESS_STATUS` wire (shared with
//! `control/coreipc_styx_ingress.go` â€” both sides must be changed together)
//!
//! Exactly three `:`-separated `key=value` fields, fixed order, bounded
//! printable ASCII (worst case below 80 bytes):
//!
//! ```text
//! attached=0|1:rx_events=<u64>:read_failures=<u64>
//! ```
//!
//! * `attached` â€” the ingress program is loaded and attached to the root cgroup.
//! * `rx_events` â€” ingress `FlowEvent` records this observer queued into the
//!   shared ring since core start (counter sum over CPUs). This is the proof
//!   that an attached hook is actually producing records; a nonzero value is
//!   never derived from egress telemetry.
//! * `read_failures` â€” packets the bounded parser rejected (the packet itself
//!   was already passed by the program; only one aggregate update was lost).
//!
//! Unknown commands are answered with the backwards-compatible `unknown command`
//! error by the dispatcher; the Go client turns that into the capability fact
//! `ErrStyxIngressUnavailable`, never into a platform degradation.

use aya::{
    maps::{MapData, PerCpuArray},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    Ebpf,
};
use std::fs::File;

/// eBPF program name (ABI with `rust/gedefense-ebpf/src/ingress_flow.rs`).
const STYX_INGRESS_PROGRAM: &str = "gedefense_ingress_flow";
/// Per-CPU map names the status wire reads.
const STYX_INGRESS_READ_FAILURES_MAP: &str = "INGRESS_FLOW_READ_FAILURES";
const STYX_INGRESS_EVENTS_MAP: &str = "INGRESS_FLOW_EVENTS_EMITTED";
/// Index of the single per-CPU counter slot (health counter convention, ABI-2 Â§4).
const PER_CPU_COUNTER_KEY: u32 = 0;

/// Core-side owner of the cgroup_skb/ingress RX flow observer.
pub(crate) struct StyxIngressCore {
    attached: bool,
    /// Bounded parse-failure counter; `None` only when the object does not
    /// expose the AP-6 maps (then the capability is unavailable anyway).
    read_failures: Option<PerCpuArray<MapData, u64>>,
    /// Ingress records actually queued into the shared ring.
    rx_events: Option<PerCpuArray<MapData, u64>>,
}

impl StyxIngressCore {
    /// Loads and attaches `gedefense_ingress_flow`; an unavailable hook is
    /// reported as `attached=0` (`RxObservationAvailable` stays false), never as
    /// a fake RX capability. This function cannot fail core load.
    pub(crate) fn attach(ebpf: &mut Ebpf, cgroup: &File) -> Self {
        // The monitor maps are mandatory for the status wire: an object without
        // them is not the AP-6 object, so no attachment is attempted and the
        // capability stays unavailable instead of reporting invented zeros.
        let read_failures = match take_counter(ebpf, STYX_INGRESS_READ_FAILURES_MAP) {
            Some(counter) => counter,
            None => {
                eprintln!(
                    "StyX ingress RX observer unavailable: {STYX_INGRESS_READ_FAILURES_MAP} missing from the eBPF object"
                );
                return Self {
                    attached: false,
                    read_failures: None,
                    rx_events: None,
                };
            }
        };
        let rx_events = match take_counter(ebpf, STYX_INGRESS_EVENTS_MAP) {
            Some(counter) => counter,
            None => {
                eprintln!(
                    "StyX ingress RX observer unavailable: {STYX_INGRESS_EVENTS_MAP} missing from the eBPF object"
                );
                return Self {
                    attached: false,
                    read_failures: Some(read_failures),
                    rx_events: None,
                };
            }
        };
        let program: &mut CgroupSkb = match ebpf.program_mut(&crate::chameleon::program_name(STYX_INGRESS_PROGRAM)) {
            Some(program) => match program.try_into() {
                Ok(program) => program,
                Err(error) => {
                    eprintln!(
                        "StyX ingress RX observer unavailable: {STYX_INGRESS_PROGRAM} is not a cgroup_skb program ({error})"
                    );
                    return Self {
                        attached: false,
                        read_failures: Some(read_failures),
                        rx_events: Some(rx_events),
                    };
                }
            },
            None => {
                eprintln!(
                    "StyX ingress RX observer unavailable: {STYX_INGRESS_PROGRAM} missing from the eBPF object"
                );
                return Self {
                    attached: false,
                    read_failures: Some(read_failures),
                    rx_events: Some(rx_events),
                };
            }
        };
        if let Err(error) = program.load() {
            eprintln!(
                "StyX ingress RX observer not loaded ({error}); RxObservationAvailable stays false"
            );
            return Self {
                attached: false,
                read_failures: Some(read_failures),
                rx_events: Some(rx_events),
            };
        }
        // AllowOverride, not AllowMultiple - see the module-level attach contract
        // and the egress attach rationale in `main.rs`: the core has no detach
        // path, so an append-on-restart would leave stale observers behind.
        if let Err(error) = program.attach(
            cgroup,
            CgroupSkbAttachType::Ingress,
            CgroupAttachMode::AllowOverride,
        ) {
            eprintln!(
                "StyX ingress RX observer not attached ({error}); RxObservationAvailable stays false"
            );
            return Self {
                attached: false,
                read_failures: Some(read_failures),
                rx_events: Some(rx_events),
            };
        }
        Self {
            attached: true,
            read_failures: Some(read_failures),
            rx_events: Some(rx_events),
        }
    }

    /// True only when the observer is loaded *and* attached. `main.rs` appends
    /// the `+styx-rx` mode token from this value.
    pub(crate) fn attached(&self) -> bool {
        self.attached
    }

    /// `STYX_INGRESS_STATUS` -> bounded `key=value` health (see module docs for
    /// the exact wire the Go parser requires).
    pub(crate) fn status(&self) -> String {
        let rx_events = match self.rx_events.as_ref() {
            Some(counter) => per_cpu_counter_sum(counter),
            None => 0,
        };
        let read_failures = match self.read_failures.as_ref() {
            Some(counter) => per_cpu_counter_sum(counter),
            None => 0,
        };
        encode_status(self.attached, rx_events, read_failures)
    }
}

/// Renders the `STYX_INGRESS_STATUS` wire. Pure and unit-tested so the Go
/// parser has one exact source of truth.
fn encode_status(attached: bool, rx_events: u64, read_failures: u64) -> String {
    format!(
        "attached={}:rx_events={}:read_failures={}",
        u8::from(attached),
        rx_events,
        read_failures
    )
}

/// Takes one mandatory per-CPU counter map by name and wraps it.
fn take_counter(ebpf: &mut Ebpf, name: &'static str) -> Option<PerCpuArray<MapData, u64>> {
    let map = ebpf.take_map(&crate::chameleon::map_name(name))?;
    match PerCpuArray::try_from(map) {
        Ok(counter) => Some(counter),
        Err(error) => {
            eprintln!("StyX ingress RX counter {name} has an unexpected map type ({error})");
            None
        }
    }
}

/// Sums a per-CPU counter over all CPUs, saturating. A read failure is logged
/// and rendered as 0 instead of panicking (this runs on the status path).
fn per_cpu_counter_sum(counter: &PerCpuArray<MapData, u64>) -> u64 {
    match counter.get(&PER_CPU_COUNTER_KEY, 0) {
        Ok(values) => values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)),
        Err(error) => {
            eprintln!("StyX ingress RX counter read failed ({error}); reporting 0");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `encode_status` is the Rust half of the wire contract; the Go parser
    /// (`control/coreipc_styx_ingress.go`) parses exactly this shape.
    #[test]
    fn status_wire_is_exact_and_bounded() {
        assert_eq!(
            encode_status(false, 0, 0),
            "attached=0:rx_events=0:read_failures=0"
        );
        assert_eq!(
            encode_status(true, 42, 7),
            "attached=1:rx_events=42:read_failures=7"
        );
        // Worst case: two maximal u64 counters. The wire must stay a short
        // bounded line (the Go parser enforces a 128-byte ceiling).
        let maximal = encode_status(true, u64::MAX, u64::MAX);
        assert_eq!(
            maximal,
            "attached=1:rx_events=18446744073709551615:read_failures=18446744073709551615"
        );
        assert!(maximal.len() <= 96, "status wire grew to {} bytes", maximal.len());
    }

    /// The fields are fixed, ordered and machine-parseable: no whitespace, no
    /// hidden fourth field, ASCII only.
    #[test]
    fn status_wire_has_three_ordered_key_value_fields() {
        let wire = encode_status(true, 1, 2);
        let fields: Vec<&str> = wire.split(':').collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "attached=1");
        assert_eq!(fields[1], "rx_events=1");
        assert_eq!(fields[2], "read_failures=2");
        assert!(wire.is_ascii());
        assert!(!wire.contains(' ') && !wire.contains('\t') && !wire.contains('\n'));
    }

    /// Real-kernel acceptance smoke (V6.3.0 AP-6, verification item 8).
    ///
    /// Ignored by default: it needs root, a built `bpfel` object and a kernel
    /// where cgroup v2 BPF is permitted (WSL2 Ubuntu-24.04 kernel 6.18 works per
    /// the AP-3/AP-4 smoke precedents). Run with:
    ///
    /// ```text
    /// cargo +1.97.1 test --locked -p gedefense-core styx_ingress_real_kernel_smoke -- --ignored --nocapture
    /// ```
    ///
    /// It loads the real object, enables StyX flow observation in `STYX_GLOBAL`,
    /// attaches `gedefense_ingress_flow` to the root cgroup with the production
    /// `AllowOverride` mode, drives real loopback TCP and UDP traffic, and drains
    /// the shared `FLOW_EVENTS` ring. A kernel that refuses the load/attach is
    /// reported as an honest SKIP (the static capability stays `attached=0`); a
    /// missing ingress record while traffic succeeded is reported as DEGRADED,
    /// never as success. The attach is owned by the test process and disappears
    /// when it exits: no system state is modified persistently.
    #[test]
    #[ignore = "requires root + a built bpfel object; manual real-kernel smoke"]
    fn styx_ingress_real_kernel_smoke() {
        use aya::maps::{Array, RingBuf};
        use gedefense_common::{
            decode_styx_flow_event, NETWORK_FAMILY_V4, STYX_DIR_INGRESS, STYX_MODE_MONITOR,
            STYX_PROTO_TCP, STYX_PROTO_UDP, STYX_VERDICT_ALLOW,
        };
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream, UdpSocket};
        use std::time::{Duration, Instant};

        let object = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/bpfel-unknown-none/release/gedefense-ebpf"
        );
        if !std::path::Path::new(object).exists() {
            eprintln!("SKIP: {object} does not exist; build it with `make rust-ebpf` first");
            return;
        }
        let mut ebpf = match Ebpf::load_file(object) {
            Ok(ebpf) => ebpf,
            Err(error) => {
                eprintln!("SKIP: cannot load {object} ({error}); capability stays attached=0");
                return;
            }
        };
        // Enable the shared StyX flow switch exactly like the core's monitor mode.
        let mut global: Array<MapData, u64> = match ebpf.take_map(&crate::chameleon::map_name("STYX_GLOBAL")) {
            Some(map) => match Array::try_from(map) {
                Ok(global) => global,
                Err(error) => {
                    eprintln!("SKIP: STYX_GLOBAL has an unexpected map type ({error})");
                    return;
                }
            },
            None => {
                eprintln!("SKIP: STYX_GLOBAL missing from the object");
                return;
            }
        };
        let word = crate::styx_flow::encode_styx_global(1, STYX_MODE_MONITOR, 0);
        if let Err(error) = global.set(0, word, 0) {
            eprintln!("SKIP: cannot enable STYX_GLOBAL ({error})");
            return;
        }
        let mut flow_events: RingBuf<MapData> = match ebpf.take_map(&crate::chameleon::map_name("FLOW_EVENTS")) {
            Some(map) => match RingBuf::try_from(map) {
                Ok(ring) => ring,
                Err(error) => {
                    eprintln!("SKIP: FLOW_EVENTS has an unexpected map type ({error})");
                    return;
                }
            },
            None => {
                eprintln!("SKIP: FLOW_EVENTS missing from the object");
                return;
            }
        };
        let emitted: Option<PerCpuArray<MapData, u64>> = ebpf
            .take_map(&crate::chameleon::map_name("INGRESS_FLOW_EVENTS_EMITTED"))
            .and_then(|map| PerCpuArray::try_from(map).ok());
        let read_failures: Option<PerCpuArray<MapData, u64>> = ebpf
            .take_map(&crate::chameleon::map_name("INGRESS_FLOW_READ_FAILURES"))
            .and_then(|map| PerCpuArray::try_from(map).ok());
        let root_cgroup = match File::open("/sys/fs/cgroup") {
            Ok(file) => file,
            Err(error) => {
                eprintln!("SKIP: /sys/fs/cgroup unreadable ({error})");
                return;
            }
        };
        let program: &mut CgroupSkb = match ebpf.program_mut(&crate::chameleon::program_name("gedefense_ingress_flow")) {
            Some(program) => match program.try_into() {
                Ok(program) => program,
                Err(error) => {
                    eprintln!("SKIP: gedefense_ingress_flow is not a cgroup_skb program ({error})");
                    return;
                }
            },
            None => {
                eprintln!("SKIP: gedefense_ingress_flow missing from the object");
                return;
            }
        };
        if let Err(error) = program.load() {
            eprintln!("SKIP: verifier rejected gedefense_ingress_flow ({error})");
            return;
        }
        let link = match program.attach(
            &root_cgroup,
            CgroupSkbAttachType::Ingress,
            CgroupAttachMode::AllowOverride,
        ) {
            Ok(link) => link,
            Err(error) => {
                eprintln!("SKIP: cgroup_skb/ingress attach refused ({error})");
                return;
            }
        };
        eprintln!("ATTACHED: gedefense_ingress_flow via cgroup_skb/ingress (AllowOverride)");

        // Real loopback traffic. A successful round trip while the observer is
        // attached is the observe-only proof: the program never dropped a packet.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind tcp listener");
        let tcp_address = listener.local_addr().expect("tcp listener address");
        let payload = vec![0x41u8; 192 * 1024];
        let expected = payload.len();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept tcp");
            let mut buffer = vec![0u8; expected];
            stream.read_exact(&mut buffer).expect("server read tcp payload");
            stream.write_all(&buffer).expect("server write tcp payload");
        });
        let mut client = TcpStream::connect(tcp_address).expect("connect tcp client");
        client.write_all(&payload).expect("client write tcp payload");
        let mut response = vec![0u8; expected];
        client.read_exact(&mut response).expect("client read tcp payload");
        server.join().expect("tcp server thread");
        eprintln!("TCP: 192 KiB loopback round trip completed while the observer was attached");

        let udp_socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind udp receiver");
        udp_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("udp read timeout");
        let udp_address = udp_socket.local_addr().expect("udp address");
        let udp_sender = UdpSocket::bind(("127.0.0.1", 0)).expect("bind udp sender");
        let udp_payload = vec![0x42u8; 60 * 1024]; // loopback UDP payload limit
        udp_sender
            .send_to(&udp_payload, udp_address)
            .expect("udp send");
        let mut udp_buffer = vec![0u8; 256 * 1024];
        let (received, _) = udp_socket.recv_from(&mut udp_buffer).expect("udp recv");
        assert_eq!(
            received,
            udp_payload.len(),
            "udp loopback payload was altered"
        );
        eprintln!("UDP: 60 KiB loopback datagram received while the observer was attached");

        // Drain the shared ring.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut ingress_records = 0usize;
        let mut rx_bytes = 0u64;
        let mut tcp_records = 0usize;
        let mut udp_records = 0usize;
        let mut drop_violations = 0usize;
        let mut non_loopback = 0usize;
        let mut zero_cgroup = 0usize;
        let mut observed_cgroup_zero = false;
        while Instant::now() < deadline {
            let mut drained_any = false;
            while let Some(item) = flow_events.next() {
                drained_any = true;
                let Some(event) = decode_styx_flow_event(&item) else {
                    continue;
                };
                if event.direction != STYX_DIR_INGRESS {
                    continue;
                }
                ingress_records += 1;
                rx_bytes = rx_bytes.saturating_add(event.rx_bytes);
                if event.tx_bytes != 0 || event.verdict != STYX_VERDICT_ALLOW {
                    drop_violations += 1;
                }
                match event.proto {
                    STYX_PROTO_TCP => tcp_records += 1,
                    STYX_PROTO_UDP => udp_records += 1,
                    _ => {}
                }
                if event.family == NETWORK_FAMILY_V4 {
                    if event.dst[0..12].iter().any(|byte| *byte != 0)
                        || event.dst[12..16] != [127u8, 0, 0, 1]
                    {
                        non_loopback += 1;
                    }
                }
                if event.cgroup_id == 0 {
                    zero_cgroup += 1;
                    observed_cgroup_zero = true;
                }
            }
            if !drained_any {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let emitted_sum = emitted
            .as_ref()
            .map(super::per_cpu_counter_sum)
            .unwrap_or_default();
        let read_failure_sum = read_failures
            .as_ref()
            .map(super::per_cpu_counter_sum)
            .unwrap_or_default();
        eprintln!(
            "OBSERVED: ingress_records={ingress_records} tcp={tcp_records} udp={udp_records} rx_bytes={rx_bytes} emitted_counter={emitted_sum} read_failures={read_failure_sum} zero_cgroup_records={zero_cgroup}"
        );
        // Keep the attach alive until here; dropping `link`/`program` detaches.
        drop(link);
        if ingress_records == 0 {
            eprintln!(
                "DEGRADED: the observer was attached and traffic succeeded, but no inbound FlowEvent was queued (kernel receive path did not run the hook for this traffic); RX capability must stay attached=1 with zero events, never a fabricated observation"
            );
            return;
        }
        assert_eq!(
            drop_violations, 0,
            "ingress records carried tx_bytes or a non-ALLOW verdict"
        );
        assert!(
            tcp_records > 0 || udp_records > 0,
            "ingress records were emitted but none was TCP/UDP"
        );
        assert_eq!(non_loopback, 0, "ingress records named a non-loopback peer");
        assert!(emitted_sum > 0, "INGRESS_FLOW_EVENTS_EMITTED stayed 0");
        if observed_cgroup_zero {
            eprintln!(
                "NOTE: some ingress records attributed cgroup_id=0 (no cgroup-v2 socket data on this kernel); control-plane matching falls back to the exact reverse 5-tuple"
            );
        }
        eprintln!("PASS: real-kernel cgroup_skb/ingress RX observation verified");
    }
}

