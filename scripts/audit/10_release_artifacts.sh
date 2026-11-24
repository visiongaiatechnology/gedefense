#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 10 (original lines 2796-2904).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
if [[ -f "$ROOT/dist/gedefense-ebpf" ]]; then
  # The release host may not ship LLVM alongside the bpf-linker toolchain. Both
  # llvm-objdump and readelf prove the same things (section names + symbol table);
  # refuse the gate only when neither inspector exists instead of dying with 127.
  if command -v llvm-objdump >/dev/null 2>&1; then
    ebpf_sections=$(llvm-objdump -h "$ROOT/dist/gedefense-ebpf")
    ebpf_symbols=$(llvm-objdump -t "$ROOT/dist/gedefense-ebpf")
  elif command -v readelf >/dev/null 2>&1; then
    ebpf_sections=$(readelf -S -W "$ROOT/dist/gedefense-ebpf")
    ebpf_symbols=$(readelf -s -W "$ROOT/dist/gedefense-ebpf")
  else
    fail 'no ELF inspector available to verify the built eBPF object (need llvm-objdump or readelf)'
  fi
  grep -Eq '[[:space:]]lsm/socket_create[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no socket_create LSM section'
  for symbol in gedefense_cell_socket_create CELL_LSM_POLICIES CELL_LSM_EVENTS; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing ${symbol}"
  done
  pass 'built eBPF object contains the GaiaCells socket LSM and policy maps'
  # POINT 3 (P3-T6): the Point 3 hook and maps must be present in the shipped
  # object as well, not only in the source tree. Sections prove the hook is
  # compiled; symbols prove the core can take the maps it depends on at startup.
  grep -Eq '[[:space:]]cgroup_skb/egress[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no cgroup_skb/egress section'
  for symbol in CELL_EGRESS_MODE FLOW_EVENTS STYX_GLOBAL STYX_RESOLVED FLOW_AGG_V4; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing Point 3 map ${symbol}"
  done
  pass 'built eBPF object contains the cgroup_skb/egress hook and Point 3 maps'
  # POINT 1 (P1-T6): both Titan exec-gate LSM sections and every map/ring the core
  # takes by name at startup must exist in the shipped object. A source-only
  # anchor would not catch a build that silently dropped a hook or a map.
  for section in lsm/bprm_check_security lsm/mmap_file; do
    grep -Eq "[[:space:]]${section}[[:space:]]" <<<"$ebpf_sections" ||
      fail "built eBPF object has no ${section} section"
  done
  for symbol in TITAN_EXEC_STATE TITAN_EXEC_OFFSETS TITAN_EXEC_MODE TITAN_EXEC_POLICY \
                TITAN_EXEC_EVENTS gedefense_titan_exec_bprm gedefense_titan_exec_mmap; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing Titan exec-gate symbol ${symbol}"
  done
  pass 'built eBPF object contains both Titan exec-gate LSM hooks and the map/ring set'
  # POINT 5 (P5-T4): the lockdown fastpath map and both drop/witness counters must
  # exist in the shipped object. The core takes them by name at startup and fails
  # loudly on a stale object; a source-only anchor would miss a dropped map.
  for symbol in LOCKDOWN_STATE LOCKDOWN_DROPS LOCKDOWN_WITNESS_PASSES; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing Point 5 lockdown symbol ${symbol}"
  done
  grep -Eq '[[:space:]]xdp[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no XDP section (lockdown external-ingress drop)'
  pass 'built eBPF object contains the Point 5 lockdown state map, counters and XDP drop path'
  # V6.3.0 (AP-1/AP-2): the executable-inode trust gate and the attach-time eBPF
  # guard must exist in the shipped object, not only in the source tree. The core
  # takes every map by name at startup and fails loudly on a stale object.
  grep -Eq '[[:space:]]lsm/bpf_prog[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no bpf_prog LSM section (AP-2 attach-time guard)'
  for symbol in TRUSTED_EXEC_INODES EXEC_INODE_STATE EXEC_INODE_OFFSETS \
                EXEC_INODE_EVENTS MALWARE_TTL_INODES \
                BPF_GUARD_STATE BPF_GUARD_EVENTS BPF_GUARD_HELPER_BITMAP \
                BPF_GUARD_HELPER_IDS \
                gedefense_bpf_prog_guard gedefense_bpf_syscall gedefense_check_helper_call; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing V6.3.0 symbol ${symbol}"
  done
  pass 'built eBPF object contains the V6.3.0 inode-trust and attach-time guard maps/programs'
  # V6.3.0 round 2: the cross-view socket tap, io_uring/LKM hooks and the
  # persistence/peripheral LSM+TP hooks must exist in the shipped object too.
  # The core takes every map by name at startup and fails loudly on a stale object.
  for section in lsm/socket_create lsm/socket_setsockopt lsm/file_open lsm/mmap_file lsm/ptrace_access_check; do
    grep -Eq "[[:space:]]${section}[[:space:]]" <<<"$ebpf_sections" ||
      fail "built eBPF object has no ${section} section (V6.3.0 round 2)"
  done
  for symbol in gedefense_crossview_socket_create gedefense_crossview_socket_setsockopt \
                gedefense_crossview_sk_attach_filter CROSS_VIEW_EVENTS CROSS_VIEW_STATE \
                gedefense_io_uring_create gedefense_io_uring_register gedefense_io_uring_submit_req \
                gedefense_module_load gedefense_init_module gedefense_finit_module gedefense_delete_module \
                gedefense_lsm_uring_override_creds gedefense_lsm_uring_sqpoll gedefense_lsm_uring_cmd \
                KERNEL_HOOK_EVENTS KERNEL_HOOK_STATE KERNEL_HOOK_OFFSETS \
                gedefense_persistence_file_open gedefense_persistence_mmap gedefense_persistence_ptrace \
                gedefense_process_vm_readv gedefense_process_vm_writev \
                PERSIST_GUARD_EVENTS PERSIST_GUARD_STATE PERSIST_GUARD_PATHS PERSIST_GUARD_EXECS PERSIST_GUARD_OFFSETS; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing V6.3.0 round-2 symbol ${symbol}"
  done
  pass 'built eBPF object contains the V6.3.0 cross-view, io_uring/LKM and persistence hook set'
  # V6.3.0 round 3: the ingress RX observer and the bounded DNS capture
  # tracepoints must exist in the shipped object as well.
  grep -Eq '[[:space:]]cgroup_skb/ingress[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no cgroup_skb/ingress section (AP-6 RX observer)'
  for symbol in gedefense_ingress_flow INGRESS_FLOW_AGG_V4 INGRESS_FLOW_AGG_V6 \
                INGRESS_FLOW_READ_FAILURES INGRESS_FLOW_EVENTS_EMITTED \
                gedefense_dns_sendto gedefense_dns_sendmsg \
                DNS_CAPTURE_STATE DNS_CAPTURE_EVENTS DNS_CAPTURE_COUNTERS; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing V6.3.0 round-3 symbol ${symbol}"
  done
  pass 'built eBPF object contains the V6.3.0 ingress RX and DNS capture set'
  # V6.3.0 round 4: the independent high-priority security ring and the
  # telemetry token-bucket maps must exist in the shipped object.
  for symbol in SEC_CRIT_EVENTS SEC_CRIT_STATE SEC_CRIT_COUNTERS \
                TELEMETRY_FLOOD_BUCKETS TELEMETRY_FLOOD_SUPPRESSED; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing V6.3.0 round-4 symbol ${symbol}"
  done
  pass 'built eBPF object contains the V6.3.0 S12 high-priority ring and flood-bucket set'
fi

