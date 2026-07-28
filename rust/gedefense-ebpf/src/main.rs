#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC},
    macros::{map, xdp},
    maps::{lpm_trie::Key, LpmTrie},
    programs::XdpContext,
};
use core::mem;
use gedefense_common::{
    parse_network_header, NetworkHeader, ACTION_DROP, L2_PREFIX_BYTES, MAX_BLOCKLIST_ENTRIES_V4,
    MAX_BLOCKLIST_ENTRIES_V6,
};

const MAX_ALLOWLIST_ENTRIES: u32 = 65_536;

#[repr(C)]
struct L2Prefix {
    bytes: [u8; L2_PREFIX_BYTES],
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    total_len: [u8; 2],
    id: [u8; 2],
    frag: [u8; 2],
    ttl: u8,
    protocol: u8,
    checksum: [u8; 2],
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(C)]
struct Ipv6Hdr {
    version_flow: [u8; 4],
    payload_len: [u8; 2],
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

#[map]
static ALLOWLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static ALLOWLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static BLOCKLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V4, BPF_F_NO_PREALLOC);
#[map]
static BLOCKLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V6, BPF_F_NO_PREALLOC);

#[xdp]
pub fn gedefense_xdp(ctx: XdpContext) -> u32 {
    match inspect(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn inspect(ctx: &XdpContext) -> Result<u32, ()> {
    let prefix: *const L2Prefix = ptr_at(ctx, 0)?;
    // SAFETY: ptr_at proves the complete fixed prefix lies inside data..data_end.
    // Copying it into the stack exposes the same bounded parser to host fuzzing.
    let bytes = unsafe { (*prefix).bytes };
    match parse_network_header(&bytes) {
        NetworkHeader::Ipv4(offset) => inspect_v4(ctx, offset),
        NetworkHeader::Ipv6(offset) => inspect_v6(ctx, offset),
        NetworkHeader::Other => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn inspect_v4(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv4Hdr = ptr_at(ctx, offset)?;
    let version_ihl = unsafe { (*header).version_ihl };
    if version_ihl >> 4 != 4 {
        return Err(());
    }
    // Source-CIDR filtering only needs the fixed IPv4 base header. Do not add
    // attacker-controlled IHL/total_len values to packet pointers: older and
    // hardened kernel verifiers correctly reject such arithmetic unless every
    // scalar bound remains provable across all compiler optimizations.
    //
    // ptr_at::<Ipv4Hdr>() above already proves that all fields read below are
    // inside data..data_end. Options and payload are deliberately left to the
    // normal network stack; malformed packets therefore remain fail-open.
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return Err(());
    }

    let key = Key::new(32, unsafe { (*header).src });
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }
    if let Some(action) = BLOCKLIST_V4.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn inspect_v6(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv6Hdr = ptr_at(ctx, offset)?;
    if u32::from_be_bytes(unsafe { (*header).version_flow }) >> 28 != 6 {
        return Err(());
    }
    // Source-CIDR filtering only consumes the fixed IPv6 header. Avoid
    // packet-dependent payload_len pointer arithmetic for the same verifier
    // reason as IPv4. ptr_at::<Ipv6Hdr>() already bounds every field we read.
    let key = Key::new(128, unsafe { (*header).src });
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }
    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start
        .checked_add(offset)
        .and_then(|value| value.checked_add(len))
        .ok_or(())?
        > end
    {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot unwind. This branch is unreachable in verified paths.
    unsafe { core::hint::unreachable_unchecked() }
}
