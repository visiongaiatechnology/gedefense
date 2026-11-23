//! Shared wire contracts for kernel-side XDR behavioral sensors:
//! - [`ExecArgvEvent`]: bounded filename + argv capture from `sys_enter_execve`
//!   so short-lived subshells (`< 15 ms`) are never lost before `/proc` polling.
//! - [`KernelProbeEvent`]: bounded kernel probe telemetry for `ptrace`,
//!   blacklisted LPE socket protocols (`SCTP`/`DCCP`/`RDS`), pre-DAC credential
//!   `openat` attempts, and sensitive symlink attempts.

pub const EXEC_ARGV_BUF_BYTES: usize = 472;
pub const EXEC_ARGV_EVENT_WIRE_BYTES: usize = 512;
pub const EXEC_ARGV_EVENT_RING_BYTES: u32 = 2 << 20;

pub const KERNEL_PROBE_EVENT_WIRE_BYTES: usize = 64;
pub const KERNEL_PROBE_EVENT_RING_BYTES: u32 = 512 * 1024;
pub const KERNEL_PROBE_DETAIL_BYTES: usize = 20;

pub const KERNEL_PROBE_KIND_PTRACE: u8 = 1;
pub const KERNEL_PROBE_KIND_PROTOCOL: u8 = 2;
pub const KERNEL_PROBE_KIND_CRED_OPENAT: u8 = 3;
pub const KERNEL_PROBE_KIND_SYMLINK: u8 = 4;
pub const KERNEL_PROBE_KIND_MAX: u8 = KERNEL_PROBE_KIND_SYMLINK;

pub const KERNEL_PROBE_ACTION_DENY: u8 = 1;
pub const KERNEL_PROBE_ACTION_AUDIT: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecArgvEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub filename_len: u16,
    pub argv_len: u16,
    pub reserved: u32,
    pub comm: [u8; 16],
    pub buf: [u8; EXEC_ARGV_BUF_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelProbeEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub target_pid: u32,
    pub detail_code: u32,
    pub kind: u8,
    pub action: u8,
    pub detail_len: u8,
    pub reserved: u8,
    pub comm: [u8; 16],
    pub detail: [u8; KERNEL_PROBE_DETAIL_BYTES],
}

pub fn decode_exec_argv_event(bytes: &[u8]) -> Option<ExecArgvEvent> {
    if bytes.len() != EXEC_ARGV_EVENT_WIRE_BYTES {
        return None;
    }
    let pid = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    let ppid = u32::from_ne_bytes(bytes[4..8].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let gid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let filename_len = u16::from_ne_bytes(bytes[16..18].try_into().ok()?);
    let argv_len = u16::from_ne_bytes(bytes[18..20].try_into().ok()?);
    let reserved = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    if pid == 0
        || reserved != 0
        || usize::from(filename_len) > usize::from(argv_len)
        || usize::from(argv_len) > EXEC_ARGV_BUF_BYTES
    {
        return None;
    }
    let mut comm = [0u8; 16];
    comm.copy_from_slice(&bytes[24..40]);
    if !comm.contains(&0) {
        return None;
    }
    let mut buf = [0u8; EXEC_ARGV_BUF_BYTES];
    buf.copy_from_slice(&bytes[40..512]);
    Some(ExecArgvEvent {
        pid,
        ppid,
        uid,
        gid,
        filename_len,
        argv_len,
        reserved,
        comm,
        buf,
    })
}

pub fn decode_kernel_probe_event(bytes: &[u8]) -> Option<KernelProbeEvent> {
    if bytes.len() != KERNEL_PROBE_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let target_pid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let detail_code = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let kind = bytes[24];
    let action = bytes[25];
    let detail_len = bytes[26];
    let reserved = bytes[27];
    if ts_ns == 0
        || pid == 0
        || reserved != 0
        || kind == 0
        || kind > KERNEL_PROBE_KIND_MAX
        || (action != KERNEL_PROBE_ACTION_DENY && action != KERNEL_PROBE_ACTION_AUDIT)
        || usize::from(detail_len) > KERNEL_PROBE_DETAIL_BYTES
    {
        return None;
    }
    let mut comm = [0u8; 16];
    comm.copy_from_slice(&bytes[28..44]);
    if !comm.contains(&0) {
        return None;
    }
    let mut detail = [0u8; KERNEL_PROBE_DETAIL_BYTES];
    detail.copy_from_slice(&bytes[44..64]);
    Some(KernelProbeEvent {
        ts_ns,
        pid,
        uid,
        target_pid,
        detail_code,
        kind,
        action,
        detail_len,
        reserved,
        comm,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_sizes_match_contract() {
        assert_eq!(core::mem::size_of::<ExecArgvEvent>(), EXEC_ARGV_EVENT_WIRE_BYTES);
        assert_eq!(core::mem::size_of::<KernelProbeEvent>(), KERNEL_PROBE_EVENT_WIRE_BYTES);
    }

    #[test]
    fn decoders_reject_corrupt_or_out_of_bounds_records() {
        let mut raw_exec = [0u8; EXEC_ARGV_EVENT_WIRE_BYTES];
        raw_exec[0..4].copy_from_slice(&123u32.to_ne_bytes());
        raw_exec[16..18].copy_from_slice(&7u16.to_ne_bytes());
        raw_exec[18..20].copy_from_slice(&18u16.to_ne_bytes());
        raw_exec[24..28].copy_from_slice(b"bash");
        assert!(decode_exec_argv_event(&raw_exec).is_some());
        raw_exec[18..20].copy_from_slice(&500u16.to_ne_bytes());
        assert!(decode_exec_argv_event(&raw_exec).is_none());

        let mut raw_probe = [0u8; KERNEL_PROBE_EVENT_WIRE_BYTES];
        raw_probe[0..8].copy_from_slice(&999u64.to_ne_bytes());
        raw_probe[8..12].copy_from_slice(&123u32.to_ne_bytes());
        raw_probe[24] = KERNEL_PROBE_KIND_PTRACE;
        raw_probe[25] = KERNEL_PROBE_ACTION_AUDIT;
        raw_probe[26] = 6;
        raw_probe[28..34].copy_from_slice(b"ptrace");
        assert!(decode_kernel_probe_event(&raw_probe).is_some());
        raw_probe[24] = 99;
        assert!(decode_kernel_probe_event(&raw_probe).is_none());
    }
}
