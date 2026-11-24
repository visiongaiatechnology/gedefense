//! V6.3.0 AP-4 — kernel hook wire contract (`KERNEL_HOOK_EVENTS`).
//!
//! The kernel half (`rust/gedefense-ebpf/src/kernel_hooks.rs`) closes the
//! `io_uring` syscall-tracepoint bypass and captures module (LKM) loading before
//! a rootkit can unlink the module from `mod_list`:
//!
//! - `tp/io_uring/io_uring_create|io_uring_register|io_uring_submit_req`:
//!   an `io_uring` ring is created, a registration opcode runs, or a request is
//!   submitted (sampled per TGID so `submit_req` cannot flood the ring),
//! - `tp/module/module_load`: a module load succeeded; the kernel taint mask
//!   tells unsigned/out-of-tree/forced loads apart, and the module name is
//!   carried best-effort from the tracepoint's `__data_loc` string,
//! - `kprobe/init_module|finit_module|delete_module`: pre-stealth capture of the
//!   load/unload syscall, including the module name for `delete_module` when the
//!   probe attached to a direct-argument symbol (see `KERNEL_HOOK_FLAG_*`),
//! - BTF-optional `lsm/uring_override_creds|uring_sqpoll|uring_cmd`: the LSM
//!   hooks that exist only on kernels which expose them. They are observe-only
//!   and always return the previous LSM program's verdict.
//!
//! The guard is observe-only: it never denies, kills or changes kernel policy.
//! The control plane maps the records onto `XDR.IO_URING_ANOMALY` /
//! `XDR.LKM_LOAD` evidence.
//!
//! # Wire layout (64 bytes, native endian, `#[repr(C)]`)
//!
//! ```text
//! offset  size  field
//!      0     8  ts_ns: u64
//!      8     4  pid: u32             (task/thread id; BPF side keeps the thread)
//!     12     4  tgid: u32            (process id)
//!     16     4  uid: u32
//!     20     1  kind: u8             KERNEL_HOOK_KIND_* (1..=10)
//!     21     1  action: u8           AUDIT=1, DENY=2 (no producer emits DENY)
//!     22     1  detail_len: u8       bounded length of `detail` (0..=20)
//!     23     1  reserved: u8         must be zero
//!     24     4  detail_code: u32     kind-specific scalar (see below)
//!     28    20  detail: [u8; 20]     kind-specific bytes, zero padded
//!     48    16  comm: [u8; 16]       NUL-padded task name
//!     64
//! ```
//!
//! `detail_code`/`detail` per kind (documented so the control plane never has to
//! guess):
//!
//! | kind | `detail_code` | `detail` |
//! |---|---|---|
//! | `IO_URING_CREATE` | the new ring fd | native-endian `u32` setup flags |
//! | `IO_URING_REGISTER` | registration opcode | native-endian `u32` nr_files |
//! | `IO_URING_SUBMIT` | opcode of the first request in the window | empty |
//! | `MODULE_LOAD` (tracepoint) | kernel taint mask | bounded module name |
//! | `LKM_TAINT` | kernel taint mask | bounded module name |
//! | `MODULE_FINIT` (kprobe) | module fd when attached to a direct-argument symbol, else 0 | empty |
//! | `MODULE_DELETE` (kprobe) | unload flags when direct-argument, else 0 | best-effort module name (user pointer) |
//! | `MODULE_LOAD` (kprobe) | 0 | empty |
//! | `LSM_URING_*` | 0 | empty |
//!
//! The `comm` is normalised by the producer: control/8-bit bytes become `?` and a
//! full 16-byte name is truncated to 15 bytes plus NUL, so the wire invariant is
//! "NUL padded and printable ASCII". `detail` bytes are *not* restricted to
//! printable characters (the create flags are binary); the control plane
//! hex-encodes them and never renders them unescaped.
//!
//! # State word (`KERNEL_HOOK_STATE`)
//!
//! One `u64`: epoch bits 0..31, armed bit 32, producer flags bits 33..39, magic
//! bits 40..47 (`0x4B` = `K`), ABI bits 48..55 (`1`). Every eBPF program checks
//! the magic/ABI/armed bits first and emits nothing while the word is absent,
//! foreign or disarmed. The flags form is the core-side kprobe tier mask (see
//! [`KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS`]); it never changes the armed bit.
//!
//! # Layout map (`KERNEL_HOOK_OFFSETS`)
//!
//! Tracepoint context layouts are kernel-version specific. The core reads
//! `/sys/kernel/tracing/events/<category>/<event>/format` at load time and
//! publishes the byte offsets of the fields this contract carries into the
//! `KERNEL_HOOK_OFFSETS` array map (slot constants below). A slot value of `0`
//! means "not known on this kernel": the eBPF program then emits the event with
//! identity only and records a read failure instead of reading a wrong offset.
//! This is the honest degraded detail mode; it is never a fake claim.

mod helpers;

pub use self::helpers::*;

/// Wire size of one [`KernelHookEvent`].
pub const KERNEL_HOOK_EVENT_WIRE_BYTES: usize = 64;
/// `KERNEL_HOOK_EVENTS` ring size (64 KiB = 1024 queued 64-byte records).
pub const KERNEL_HOOK_EVENT_RING_BYTES: u32 = 64 * 1024;
/// Maximum records the core returns per drain (bounded control-plane response).
pub const KERNEL_HOOK_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload bytes the core returns per drain.
pub const KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;
/// Bounded `detail` payload bytes per record.
pub const KERNEL_HOOK_DETAIL_BYTES: usize = 20;
/// Bounded `comm` bytes per record (kernel `TASK_COMM_LEN`).
pub const KERNEL_HOOK_COMM_BYTES: usize = 16;
/// Highest representable kind; a record above this cannot be produced.
pub const KERNEL_HOOK_MAX_KIND: u8 = 10;

/// `KERNEL_HOOK_OFFSETS` capacity. Slots 0..6 carry tracepoint field byte
/// offsets; slot 7 is reserved and must stay zero.
pub const KERNEL_HOOK_OFFSET_SLOTS: u32 = 8;

/// `io_uring_create`: `int fd` field offset.
pub const KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD: u32 = 0;
/// `io_uring_create`: `u32 flags` field offset.
pub const KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS: u32 = 1;
/// `io_uring_register`: `unsigned opcode` field offset.
pub const KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE: u32 = 2;
/// `io_uring_register`: registration file-count field offset (`nr_files`, older
/// kernels: `nr_args`).
pub const KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES: u32 = 3;
/// `io_uring_submit_req`: `u8 opcode` field offset.
pub const KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE: u32 = 4;
/// `module_load`: `unsigned int taints` field offset.
pub const KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS: u32 = 5;
/// `module_load`: `__data_loc char[] name` field offset.
pub const KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME: u32 = 6;
/// Upper bound applied to a `__data_loc` name offset before it is used as a
/// pointer offset onto the tracepoint record (defensive bound, not a layout).
pub const KERNEL_HOOK_MAX_RECORD_OFFSET: u32 = 4096;

/// Event kind: an `io_uring` ring was created.
pub const KERNEL_HOOK_KIND_IO_URING_CREATE: u8 = 1;
/// Event kind: an `io_uring` registration command ran.
pub const KERNEL_HOOK_KIND_IO_URING_REGISTER: u8 = 2;
/// Event kind: the first `io_uring` submission of a per-TGID sampling window.
pub const KERNEL_HOOK_KIND_IO_URING_SUBMIT: u8 = 3;
/// Event kind: `tp/module/module_load` (or `kprobe/init_module`) reported a
/// module load.
pub const KERNEL_HOOK_KIND_MODULE_LOAD: u8 = 4;
/// Event kind: `kprobe/finit_module` (module-fd based load attempt).
pub const KERNEL_HOOK_KIND_MODULE_FINIT: u8 = 5;
/// Event kind: `kprobe/delete_module` (module unload attempt).
pub const KERNEL_HOOK_KIND_MODULE_DELETE: u8 = 6;
/// Event kind: `lsm/uring_override_creds` fired.
pub const KERNEL_HOOK_KIND_LSM_URING_OVERRIDE_CREDS: u8 = 7;
/// Event kind: `lsm/uring_sqpoll` fired.
pub const KERNEL_HOOK_KIND_LSM_URING_SQPOLL: u8 = 8;
/// Event kind: `lsm/uring_cmd` fired (sampled per TGID).
pub const KERNEL_HOOK_KIND_LSM_URING_CMD: u8 = 9;
/// Event kind: the module load carried a non-zero kernel taint mask.
pub const KERNEL_HOOK_KIND_LKM_TAINT: u8 = 10;

/// One kernel-hook observation (see the module-level wire layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelHookEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub kind: u8,
    pub action: u8,
    pub detail_len: u8,
    pub reserved: u8,
    pub detail_code: u32,
    pub detail: [u8; KERNEL_HOOK_DETAIL_BYTES],
    pub comm: [u8; KERNEL_HOOK_COMM_BYTES],
}

// Compile-time coupling to the wire contract: a layout drift must fail the eBPF
// and core builds, not silently corrupt a ring record.
const _: () = assert!(core::mem::size_of::<KernelHookEvent>() == KERNEL_HOOK_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<KernelHookEvent>() == 8);
const _: () = assert!(KERNEL_HOOK_STATE_MAGIC == 0x4b);
const _: () = assert!(KERNEL_HOOK_STATE_ABI == 1);
const _: () = assert!(KERNEL_HOOK_STATE_FLAGS_SHIFT == 33);
const _: () = assert!(KERNEL_HOOK_FLAG_ALL == 0b0000_0011);

/// Decodes one fixed-size kernel-hook record; `None` for every record the
/// kernel producer cannot have emitted.
///
/// Rejected here (never repaired): wrong length, zero timestamp/pid/tgid, an
/// unknown kind or action, a non-zero reserved byte, a `detail_len` above the
/// bounded detail size, a non-zero detail padding tail, and a `comm` that is not
/// NUL padded.
pub fn decode_kernel_hook_event(bytes: &[u8]) -> Option<KernelHookEvent> {
    if bytes.len() != KERNEL_HOOK_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let kind = bytes[20];
    let action = bytes[21];
    let detail_len = bytes[22];
    let reserved = bytes[23];
    let detail_code = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let detail: [u8; KERNEL_HOOK_DETAIL_BYTES] = bytes[28..48].try_into().ok()?;
    let comm: [u8; KERNEL_HOOK_COMM_BYTES] = bytes[48..64].try_into().ok()?;

    if ts_ns == 0
        || pid == 0
        || tgid == 0
        || reserved != 0
        || kind == 0
        || kind > KERNEL_HOOK_MAX_KIND
        || (action != KERNEL_HOOK_ACTION_AUDIT && action != KERNEL_HOOK_ACTION_DENY)
        || usize::from(detail_len) > KERNEL_HOOK_DETAIL_BYTES
        || !detail_tail_is_zero(&detail, usize::from(detail_len))
        || !comm_is_nul_padded(&comm)
    {
        return None;
    }

    Some(KernelHookEvent {
        ts_ns,
        pid,
        tgid,
        uid,
        kind,
        action,
        detail_len,
        reserved,
        detail_code,
        detail,
        comm,
    })
}

/// The producer zero-initialises the detail array and copies exactly
/// `detail_len` bytes; a non-zero byte after the declared length cannot happen.
fn detail_tail_is_zero(detail: &[u8; KERNEL_HOOK_DETAIL_BYTES], detail_len: usize) -> bool {
    let mut index = detail_len;
    while index < detail.len() {
        if detail[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

/// The producer always NUL-terminates `comm`; a full 16-byte name is truncated
/// to 15 bytes plus NUL, so at least one NUL is guaranteed and every byte after
/// the first NUL must be zero.
fn comm_is_nul_padded(comm: &[u8; KERNEL_HOOK_COMM_BYTES]) -> bool {
    let mut padded = false;
    let mut index = 0usize;
    while index < comm.len() {
        let byte = comm[index];
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        }
        index += 1;
    }
    padded
}

#[cfg(test)]
mod tests;
