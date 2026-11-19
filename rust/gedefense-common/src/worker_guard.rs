//! 6.1.0 kernel wire contract for the worker-integrity guard.
//!
//! The eBPF side (`rust/gedefense-ebpf/src/worker_guard.rs`) emits one
//! `WorkerCrashEvent` per fatal signal delivered to a registered web-worker
//! comm or uid. The core drains the ring and re-encodes it as bounded text;
//! the field order and the 48-byte wire size below are the contract between
//! both sides. Keep them in sync with the static assertions in the eBPF crate.

/// One worker crash record. `signal` is the Linux signal number, `exit_code`
/// is reserved for a future exit tracepoint and is `-1` until then.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerCrashEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub signal: u32,
    pub exit_code: i32,
    pub reserved: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

pub const WORKER_CRASH_EVENT_WIRE_BYTES: usize = 48;

/// Fatal memory-corruption and abort signals the guard treats as crashes.
pub const WORKER_SIGNAL_ILL: u32 = 4;
pub const WORKER_SIGNAL_ABRT: u32 = 6;
pub const WORKER_SIGNAL_BUS: u32 = 7;
pub const WORKER_SIGNAL_SEGV: u32 = 11;

/// A registered worker that receives one of these is a crash candidate. The
/// control plane additionally requires that the process is gone before it
/// opens a storm; a handled signal alone is an audit-level event.
pub fn worker_signal_is_fatal(signal: u32) -> bool {
    matches!(
        signal,
        WORKER_SIGNAL_ILL | WORKER_SIGNAL_ABRT | WORKER_SIGNAL_BUS | WORKER_SIGNAL_SEGV
    )
}

/// LSM socket-create policy bits (6.1.0). Bit 0 is the pre-existing
/// `CELL_LSM_DENY_NON_UNIX_SOCKET`; bits 1..6 are the LPE kill-chain deny set.
pub const CELL_LSM_DENY_AF_PACKET: u8 = 1 << 1;
pub const CELL_LSM_DENY_AF_TIPC: u8 = 1 << 2;
pub const CELL_LSM_DENY_AF_VSOCK: u8 = 1 << 3;
pub const CELL_LSM_DENY_SCTP: u8 = 1 << 4;
pub const CELL_LSM_DENY_DCCP: u8 = 1 << 5;
pub const CELL_LSM_DENY_RDS: u8 = 1 << 6;

/// Every policy bit this build understands. Unknown bits are rejected by the
/// core before the first map write.
pub const CELL_LSM_DENY_ALL_KNOWN: u8 = 0x01
    | CELL_LSM_DENY_AF_PACKET
    | CELL_LSM_DENY_AF_TIPC
    | CELL_LSM_DENY_AF_VSOCK
    | CELL_LSM_DENY_SCTP
    | CELL_LSM_DENY_DCCP
    | CELL_LSM_DENY_RDS;

// ---------------------------------------------------------------------------
// 6.1.0 LPE socket-create deny predicate.
//
// The decision lives here, in a pure `no_std` function, instead of only in the
// eBPF object: the eBPF crate is a `no_std` binary for `bpfel-unknown-none` and
// cannot run `cargo test`, so the shared predicate is the host-testable single
// source of truth. The eBPF LSM hook calls exactly this function; the kernel and
// the test can therefore never disagree about which family/protocol is denied.
// ---------------------------------------------------------------------------

/// `AF_RDS` (uapi value 21). Linux creates an RDS socket as
/// `socket(AF_RDS, SOCK_SEQPACKET, 0)`: the RDS marker is the *address family*,
/// the protocol argument is 0. Comparing `protocol == 21` instead matched
/// pre-created `AF_INET` sockets whose protocol argument happens to equal
/// `IPPROTO_RDS` (a value no supported socket type accepts) and let a real
/// `AF_RDS` socket through - the deny bit was dead. FIND-002.
pub const AF_RDS: i32 = 21;
/// `AF_PACKET` (uapi value 17).
pub const AF_PACKET: i32 = 17;
/// `AF_TIPC` (uapi value 30).
pub const AF_TIPC: i32 = 30;
/// `AF_VSOCK` (uapi value 40).
pub const AF_VSOCK: i32 = 40;
/// `IPPROTO_DCCP` (uapi value 33).
pub const IPPROTO_DCCP: i32 = 33;
/// `IPPROTO_SCTP` (uapi value 132).
pub const IPPROTO_SCTP: i32 = 132;

/// Returns true when the per-cgroup policy word denies creating this socket.
///
/// `flags` is the `CELL_LSM_DENY_*` word of the matched cgroup. Bit 0
/// (`CELL_LSM_DENY_NON_UNIX_SOCKET`) is intentionally *not* evaluated here: it
/// denies every non-`AF_UNIX` family and is checked by the caller before this
/// predicate, exactly so that the two rules stay independently testable.
///
/// RDS is matched by family only; SCTP and DCCP are matched by protocol because
/// Linux creates both as `AF_INET`/`AF_INET6` sockets with their protocol value.
#[inline(always)]
pub fn cell_lsm_socket_create_denied(flags: u8, family: i32, protocol: i32) -> bool {
    if flags & CELL_LSM_DENY_AF_PACKET != 0 && family == AF_PACKET {
        return true;
    }
    if flags & CELL_LSM_DENY_AF_TIPC != 0 && family == AF_TIPC {
        return true;
    }
    if flags & CELL_LSM_DENY_AF_VSOCK != 0 && family == AF_VSOCK {
        return true;
    }
    if flags & CELL_LSM_DENY_SCTP != 0 && protocol == IPPROTO_SCTP {
        return true;
    }
    if flags & CELL_LSM_DENY_DCCP != 0 && protocol == IPPROTO_DCCP {
        return true;
    }
    if flags & CELL_LSM_DENY_RDS != 0 && family == AF_RDS {
        return true;
    }
    false
}

/// Decodes one ring record, returning `None` for malformed metadata instead of
/// poisoning the whole drain batch.
pub fn decode_worker_crash_event(item: &[u8]) -> Option<WorkerCrashEvent> {
    if item.len() != WORKER_CRASH_EVENT_WIRE_BYTES {
        return None;
    }
    let pid = u32::from_ne_bytes(item[0..4].try_into().ok()?);
    let uid = u32::from_ne_bytes(item[4..8].try_into().ok()?);
    let gid = u32::from_ne_bytes(item[8..12].try_into().ok()?);
    let signal = u32::from_ne_bytes(item[12..16].try_into().ok()?);
    let exit_code = i32::from_ne_bytes(item[16..20].try_into().ok()?);
    let cgroup_id = u64::from_ne_bytes(item[24..32].try_into().ok()?);
    let mut comm = [0u8; 16];
    comm.copy_from_slice(&item[32..48]);
    if pid == 0 || !worker_signal_is_fatal(signal) {
        return None;
    }
    Some(WorkerCrashEvent {
        pid,
        uid,
        gid,
        signal,
        exit_code,
        reserved: 0,
        cgroup_id,
        comm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_signal_set_is_exact() {
        for signal in [WORKER_SIGNAL_ILL, WORKER_SIGNAL_ABRT, WORKER_SIGNAL_BUS, WORKER_SIGNAL_SEGV] {
            assert!(worker_signal_is_fatal(signal));
        }
        for signal in [0, 1, 9, 15, 19, 31] {
            assert!(!worker_signal_is_fatal(signal));
        }
    }

    #[test]
    fn decode_rejects_short_and_nonfatal_records() {
        assert!(decode_worker_crash_event(&[0u8; 47]).is_none());
        let mut record = [0u8; WORKER_CRASH_EVENT_WIRE_BYTES];
        record[0..4].copy_from_slice(&123u32.to_ne_bytes());
        record[12..16].copy_from_slice(&9u32.to_ne_bytes()); // SIGKILL
        assert!(decode_worker_crash_event(&record).is_none());
        record[12..16].copy_from_slice(&WORKER_SIGNAL_SEGV.to_ne_bytes());
        let decoded = decode_worker_crash_event(&record).expect("segv record");
        assert_eq!(decoded.pid, 123);
        assert_eq!(decoded.signal, WORKER_SIGNAL_SEGV);
    }

    #[test]
    fn policy_bit_set_has_no_overlap() {
        let bits = [
            CELL_LSM_DENY_AF_PACKET,
            CELL_LSM_DENY_AF_TIPC,
            CELL_LSM_DENY_AF_VSOCK,
            CELL_LSM_DENY_SCTP,
            CELL_LSM_DENY_DCCP,
            CELL_LSM_DENY_RDS,
        ];
        let mut seen = 0u8;
        for bit in bits {
            assert_eq!(seen & bit, 0);
            seen |= bit;
        }
        assert_eq!(seen, CELL_LSM_DENY_ALL_KNOWN & !1);
    }

    // uapi AF_INET is 2; the RDS family check must not collide with it.
    const AF_INET: i32 = 2;

    #[test]
    fn rds_deny_is_keyed_on_the_address_family_not_the_protocol() {
        // Linux creates RDS as socket(AF_RDS /*21*/, SOCK_SEQPACKET, 0).
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_RDS, AF_RDS, 0));
        // The pre-6.1.0 comparison `protocol == 21` matched an AF_INET socket
        // whose protocol argument equals 21 - not an RDS socket at all - and
        // missed the real AF_RDS socket above. Both directions are locked here.
        assert!(!cell_lsm_socket_create_denied(CELL_LSM_DENY_RDS, AF_INET, 21));
        // Without the policy bit the family is allowed (default-open policy).
        assert!(!cell_lsm_socket_create_denied(0, AF_RDS, 0));
        // The RDS bit only covers AF_RDS, never an unrelated family.
        for family in [1, AF_INET, 10, AF_PACKET, AF_TIPC, AF_VSOCK] {
            assert!(!cell_lsm_socket_create_denied(CELL_LSM_DENY_RDS, family, 0));
        }
    }

    #[test]
    fn family_and_protocol_bits_match_exactly() {
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_AF_PACKET, AF_PACKET, 0));
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_AF_TIPC, AF_TIPC, 0));
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_AF_VSOCK, AF_VSOCK, 0));
        // SCTP/DCCP are AF_INET sockets with their protocol value.
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_SCTP, AF_INET, IPPROTO_SCTP));
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_DCCP, AF_INET, IPPROTO_DCCP));
        // Wrong family/protocol pairing never denies.
        assert!(!cell_lsm_socket_create_denied(CELL_LSM_DENY_AF_PACKET, AF_INET, 0));
        assert!(!cell_lsm_socket_create_denied(CELL_LSM_DENY_SCTP, AF_INET, IPPROTO_DCCP));
        assert!(!cell_lsm_socket_create_denied(CELL_LSM_DENY_DCCP, AF_INET, IPPROTO_SCTP));
        // Every 6.1.0 bit set still denies the RDS family; the NON_UNIX bit 0
        // stays owned by the caller and is not evaluated by this predicate.
        assert!(cell_lsm_socket_create_denied(CELL_LSM_DENY_ALL_KNOWN, AF_RDS, 0));
        assert!(!cell_lsm_socket_create_denied(0x01, AF_INET, 0));
    }
}
