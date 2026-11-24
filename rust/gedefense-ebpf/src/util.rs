use aya_ebpf::maps::PerCpuArray;

const INGRESS_HEALTH_KEY: u32 = 0;

pub(crate) const EPERM: i32 = 1;

// Maximum cgroup-v2 ancestor levels inspected per socket creation. The walk
// starts at the root (level 0) and the kernel returns 0 once the requested level
// is below the current cgroup, so the real cost is hierarchy depth + 2 helper
// calls. cgroup.max.depth defaults to "max"; hierarchies deeper than this bound
// are a documented residual limitation of the bounded eBPF loop.
pub(crate) const MAX_CGROUP_ANCESTOR_LEVELS: i32 = 64;

pub(crate) const NS_PER_SECOND: u64 = 1_000_000_000;

#[inline(always)]
pub(crate) fn increment_counter(counter: &PerCpuArray<u64>) {
    // Every health counter map has exactly one per-CPU slot at key 0 (§4).
    if let Some(ptr) = counter.get_ptr_mut(INGRESS_HEALTH_KEY) {
        let value = unsafe { &mut *ptr };
        *value = value.saturating_add(1);
    }
}
