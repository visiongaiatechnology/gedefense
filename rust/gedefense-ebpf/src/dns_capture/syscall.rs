//! Syscall tracepoint readers of the AP-6 DNS capture (child module of
//! `dns_capture`): `sys_enter_sendto`/`sys_enter_sendmsg` payload extraction and
//! the userspace `sockaddr`/`msghdr`/`iovec` head layouts; the public
//! `#[tracepoint]` entry points stay in the parent module.

use aya_ebpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_buf},
    programs::TracePointContext,
};
use gedefense_common::{DNS_CAPTURE_COUNTER_PROBES, DNS_CAPTURE_COUNTER_READ_FAILURES};

use super::emit::{bump, capture_armed};
use super::{capture_user_query, DNS_HEADER_BYTES};

/// `struct trace_event_raw_sys_enter`: `trace_entry` (8) + `long id` (8), then
/// `unsigned long args[6]`; `sendto(fd, buff, len, flags, addr, addr_len)`.
const SYS_ENTER_SENDTO_BUF_OFFSET: usize = 24;
const SYS_ENTER_SENDTO_LEN_OFFSET: usize = 32;
const SYS_ENTER_SENDTO_ADDR_OFFSET: usize = 48;
/// `sendmsg(fd, msg, flags)`.
const SYS_ENTER_SENDMSG_MSG_OFFSET: usize = 24;

/// DNS transport port the capture is pinned to (UDP only in practice: TCP DNS
/// uses `send`/`write`, never `sendto` with a destination sockaddr).
const DNS_PORT: u16 = 53;
/// `AF_INET` / `AF_INET6` (stable Linux values).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Shortest readable userspace `sockaddr` head (family + port).
const SOCKADDR_HEAD_BYTES: usize = 16;
/// `sizeof(struct sockaddr_in)`-minimum `msg_namelen` worth reading.
const SOCKADDR_MIN_BYTES: u32 = 8;

/// `struct user_msghdr` head (x86_64 UAPI): only the fields the capture uses.
#[repr(C)]
struct UserMsghdrHead {
    msg_name: u64,
    msg_namelen: u32,
    _padding: u32,
    msg_iov: u64,
    msg_iovlen: u64,
}

/// UAPI `struct iovec`.
#[repr(C)]
struct IovecHead {
    iov_base: u64,
    iov_len: u64,
}

// Compile-time coupling to the documented userspace layouts: a drift fails the
// eBPF build instead of reading a wrong offset.
const _: () = assert!(core::mem::size_of::<UserMsghdrHead>() == 32);
const _: () = assert!(core::mem::offset_of!(UserMsghdrHead, msg_name) == 0);
const _: () = assert!(core::mem::offset_of!(UserMsghdrHead, msg_namelen) == 8);
const _: () = assert!(core::mem::offset_of!(UserMsghdrHead, msg_iov) == 16);
const _: () = assert!(core::mem::offset_of!(UserMsghdrHead, msg_iovlen) == 24);
const _: () = assert!(core::mem::size_of::<IovecHead>() == 16);

/// True when the userspace `sockaddr` names UDP/53. `None` means the sockaddr
/// could not be read (counted as a read failure by the caller).
#[inline(always)]
fn destination_is_dns(addr_ptr: u64) -> Option<bool> {
    if addr_ptr == 0 {
        return Some(false);
    }
    let mut head = [0u8; SOCKADDR_HEAD_BYTES];
    if unsafe { bpf_probe_read_user_buf(addr_ptr as *const u8, &mut head) }.is_err() {
        return None;
    }
    // `sa_family_t` is native endian; the port is network endian in
    // `sockaddr_in.sin_port` and `sockaddr_in6.sin6_port`, both at offset 2.
    let family = u16::from_ne_bytes([head[0], head[1]]);
    if family != AF_INET && family != AF_INET6 {
        return Some(false);
    }
    let port = u16::from_be_bytes([head[2], head[3]]);
    Some(port == DNS_PORT)
}

#[inline(always)]
pub(crate) fn try_sendto(ctx: &TracePointContext) -> Option<()> {
    if !capture_armed() {
        return None;
    }
    let buf: u64 = unsafe { ctx.read_at(SYS_ENTER_SENDTO_BUF_OFFSET).ok()? };
    let length: u64 = unsafe { ctx.read_at(SYS_ENTER_SENDTO_LEN_OFFSET).ok()? };
    let addr: u64 = unsafe { ctx.read_at(SYS_ENTER_SENDTO_ADDR_OFFSET).ok()? };
    match destination_is_dns(addr) {
        Some(true) => {}
        Some(false) => return None,
        None => {
            bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
            return None;
        }
    }
    bump(DNS_CAPTURE_COUNTER_PROBES);
    capture_user_query(buf, length, false)
}

#[inline(always)]
pub(crate) fn try_sendmsg(ctx: &TracePointContext) -> Option<()> {
    if !capture_armed() {
        return None;
    }
    let msg_ptr: u64 = unsafe { ctx.read_at(SYS_ENTER_SENDMSG_MSG_OFFSET).ok()? };
    if msg_ptr == 0 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let head: UserMsghdrHead =
        match unsafe { bpf_probe_read_user(msg_ptr as *const UserMsghdrHead) } {
            Ok(value) => value,
            Err(_) => {
                bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
                return None;
            }
        };
    if head.msg_name == 0 || head.msg_namelen < SOCKADDR_MIN_BYTES {
        // Documented fallback: a connected UDP socket carries no destination in
        // the syscall, so the port cannot be determined. Emit nothing and count
        // the unobservable query instead of guessing a port.
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    match destination_is_dns(head.msg_name) {
        Some(true) => {}
        Some(false) => return None,
        None => {
            bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
            return None;
        }
    }
    if head.msg_iov == 0 || head.msg_iovlen == 0 {
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    let iovec: IovecHead = match unsafe { bpf_probe_read_user(head.msg_iov as *const IovecHead) } {
        Ok(value) => value,
        Err(_) => {
            bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
            return None;
        }
    };
    if iovec.iov_base == 0 || iovec.iov_len < (DNS_HEADER_BYTES + 2) as u64 {
        // Multi-iovec DNS messages are not stitched: only iov[0] is inspected
        // and a message whose DNS header does not fit is a counted read failure.
        bump(DNS_CAPTURE_COUNTER_READ_FAILURES);
        return None;
    }
    bump(DNS_CAPTURE_COUNTER_PROBES);
    capture_user_query(iovec.iov_base, iovec.iov_len, true)
}
