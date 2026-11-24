use aya_ebpf::{
    helpers::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    },
    macros::lsm,
    programs::LsmContext,
};
use gedefense_common::{
    cell_lsm_socket_create_denied, CellLsmDenyEvent, ACTION_DROP, CELL_LSM_DENY_NON_UNIX_SOCKET,
    KERNEL_PROBE_ACTION_DENY, KERNEL_PROBE_KIND_PROTOCOL,
};
use crate::maps::{CELL_LSM_EVENTS, CELL_LSM_POLICIES};
use crate::util::{EPERM, MAX_CGROUP_ANCESTOR_LEVELS};
use crate::xdr_kernel;

const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IPPROTO_RDS: i32 = 21;
const IPPROTO_DCCP: i32 = 33;
const IPPROTO_SCTP: i32 = 132;

/// 6.1.0 Module D: the per-cgroup socket-deny bits beyond the pre-existing
/// NON_UNIX bit. The policy word stays a u8; the core rejects unknown bits.
///
/// The decision itself is `gedefense_common::cell_lsm_socket_create_denied`, so
/// it is unit-tested by the host test suite instead of only by the BPF
/// verifier. In particular the RDS bit is keyed on `family == AF_RDS` (Linux
/// creates RDS as `socket(AF_RDS /*21*/, SOCK_SEQPACKET, 0)`), never on the
/// protocol argument; SCTP/DCCP stay protocol-keyed because they are AF_INET
/// sockets carrying that protocol value. FIND-002.
#[inline(always)]
fn socket_policy_denies(flags: u8, family: i32, protocol: i32) -> bool {
    cell_lsm_socket_create_denied(flags, family, protocol)
}

#[lsm(hook = "socket_create")]
pub fn gedefense_cell_socket_create(ctx: LsmContext) -> i32 {
    match try_cell_socket_create(ctx) {
        Ok(value) | Err(value) => value,
    }
}

#[inline(always)]
fn try_cell_socket_create(ctx: LsmContext) -> Result<i32, i32> {
    // The trailing argument is the return value of the previously attached LSM
    // program on this hook. Defer to it, exactly like the kernel LSM chain does,
    // before applying the Gaia Cell policy.
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return Ok(previous);
    }
    let family: i32 = ctx.arg(0);
    // 6.1.0 Module D: socket(2) protocol (third LSM argument). The kernel keeps
    // it in the hook signature; the pre-6.1.0 hook ignored it. Reading it is
    // required to refuse SCTP/DCCP/RDS on an otherwise allowed AF_INET socket.
    let protocol: i32 = ctx.arg(2);
    if family == AF_UNIX {
        return Ok(0);
    }
    // AF_UNSPEC (0) reaches this hook because __sock_create() only range-checks
    // the family and performs the real lookup afterwards; a socket for it can
    // never exist (-EAFNOSUPPORT). Refuse such requests explicitly instead of
    // passing them through the policy check. Families that do not fit the u8
    // field of CellLsmDenyEvent are refused the same way and without telemetry:
    // the core's CELL_LSM event validator rejects family <= 0 or > u8::MAX as
    // malformed wire data, so emitting a deny event there would abort a whole
    // event drain. The matching userspace boundary is fixed in the core crate
    // (rust/gedefense-core/src/main.rs); this is the kernel-side half.
    if family <= 0 || family > i32::from(u8::MAX) {
        return Ok(-EPERM);
    }
    if (family == AF_INET || family == AF_INET6)
        && (protocol == IPPROTO_SCTP || protocol == IPPROTO_DCCP || protocol == IPPROTO_RDS)
    {
        xdr_kernel::emit_kernel_probe(
            KERNEL_PROBE_KIND_PROTOCOL,
            KERNEL_PROBE_ACTION_DENY,
            0,
            protocol as u32,
            if protocol == IPPROTO_SCTP {
                b"SCTP"
            } else if protocol == IPPROTO_DCCP {
                b"DCCP"
            } else {
                b"RDS"
            },
        );
        return Ok(-EPERM);
    }
    // Walk the complete cgroup-v2 ancestry from the root (level 0) down to the
    // current cgroup instead of matching only the current cgroup id. A policy
    // installed on the Gaia Cell cgroup has to cover every descendant/leaf cgroup
    // a cell process can be moved into; the previous direct-key match let child
    // cgroups escape enforcement entirely. The kernel returns 0 for levels below
    // the current cgroup, which ends the bounded loop. The matched cgroup id is
    // reported in the event because that is the cell boundary the control plane
    // installs policies for and correlates evidence against.
    //
    // Coverage boundary: socket_create is only reached when a socket is created.
    // Sockets inherited across fork/exec or received over SCM_RIGHTS never pass
    // this hook again, so a task inside an enforcing cell can still receive an
    // already-created AF_INET socket from outside the cell. Closing that gap needs
    // connect/sendmsg-time enforcement and remains a documented residual risk of
    // this hook; it cannot be observed or repaired here.
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let cgroup_id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if cgroup_id == 0 {
            break;
        }
        if let Some(policy) = unsafe { CELL_LSM_POLICIES.get(&cgroup_id) } {
            if *policy & CELL_LSM_DENY_NON_UNIX_SOCKET != 0
                || socket_policy_denies(*policy, family, protocol)
            {
                let pid_tgid = bpf_get_current_pid_tgid();
                let uid_gid = bpf_get_current_uid_gid();
                let event = CellLsmDenyEvent {
                    cgroup_id,
                    pid: (pid_tgid >> 32) as u32,
                    uid: uid_gid as u32,
                    family,
                    action: ACTION_DROP,
                    reserved: [0; 3],
                };
                let _ = CELL_LSM_EVENTS.output::<CellLsmDenyEvent>(&event, 0);
                return Ok(-EPERM);
            }
        }
        level += 1;
    }
    Ok(0)
}
