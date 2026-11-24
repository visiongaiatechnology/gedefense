#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 9 (original lines 2485-2795).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PYV63R3'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-6 ingress RX / PCR
ingress_ebpf = read('rust/gedefense-ebpf/src/ingress_flow.rs')
for anchor in ['CGROUP_SKB_ACT_PASS', 'pub fn gedefense_ingress_flow',
               'static INGRESS_FLOW_AGG_V4', 'static INGRESS_FLOW_AGG_V6',
               'static INGRESS_FLOW_READ_FAILURES', 'STYX_DIR_INGRESS']:
    need('ap6-ingress-ebpf', ingress_ebpf, anchor)
ingress_core = read('rust/gedefense-core/src/styx_ingress.rs')
for anchor in ['CgroupSkbAttachType::Ingress', 'CgroupAttachMode::AllowOverride',
               'pub(crate) fn attach']:
    need('ap6-ingress-core', ingress_core, anchor)
phase2 = read('control/styx_phase2.go')
for anchor in ['XDR.STYX_PCR_EXFIL', 'styxPhase2PCRComputeBytes',
               'styxPhase2PCRThreshold', 'func (e *XDREngine) pollStyxPhase2',
               'func (e *XDREngine) phase2ObserveFlowBatch']:
    need('ap6-phase2', phase2, anchor)
forbid('ap6-phase2', phase2, r'\bKillEligible\s*:\s*true', 'kill-eligible PCR rule')
forbid('ap6-phase2', phase2, r'Decision:\s*"kill"', 'PCR kill decision')
need('ap6-ingress-ipc', read('control/coreipc_styx_ingress.go'),
     'func (c *CoreClient) StyxIngressStatus()')
need('ap6-ingress-ipc-err', read('control/coreipc_styx_ingress.go'),
     'ErrStyxIngressUnavailable')
need('ap6-phase2-tests', read('control/styx_phase2_test.go'), 'func Test')

# AP-6 DNS capture + tunnelling
dns_common = read('rust/gedefense-common/src/dns_capture.rs')
for anchor in ['DNS_CAPTURE_EVENT_WIRE_BYTES', 'pub struct DnsCaptureEvent',
               'pub fn decode_dns_capture_event', 'DNS_CAPTURE_QNAME_TAIL_BYTES']:
    need('ap6-dns-abi', dns_common, anchor)
dns_ebpf = read('rust/gedefense-ebpf/src/dns_capture.rs')
for anchor in ['pub fn gedefense_dns_sendto', 'pub fn gedefense_dns_sendmsg',
               'static DNS_CAPTURE_EVENTS', 'static DNS_CAPTURE_STATE',
               'static DNS_CAPTURE_COUNTERS']:
    need('ap6-dns-ebpf', dns_ebpf, anchor)
dns_core = read('rust/gedefense-core/src/dns_capture.rs')
for anchor in ['DNS_CAPTURE_EVENTS', 'fn take_events', 'fn set_enabled_token']:
    need('ap6-dns-core', dns_core, anchor)
dns_ipc = read('control/coreipc_dns.go')
for anchor in ['ErrDnsUnavailable', 'func parseCoreDnsEvents',
               'func (c *CoreClient) DnsEvents()']:
    need('ap6-dns-ipc', dns_ipc, anchor)
need('ap6-dns-fuzz', read('control/coreipc_dns_test.go'),
     'func FuzzCoreDnsParser')
need('ap6-dns-makefile', read('Makefile'), 'FuzzCoreDnsParser')
dns_tunnel = read('control/dns_tunnel.go')
for anchor in ['XDR.DNS_TUNNEL', 'dnsEntropyThreshold', 'dnsZipfRatioThreshold',
               '"entropy"', '"zipf"', 'func (e *XDREngine) pollDnsTunnel']:
    need('ap6-dns-tunnel', dns_tunnel, anchor)
forbid('ap6-dns-tunnel', dns_tunnel, r'\bKillEligible\s*:\s*true',
       'kill-eligible DNS rule')
dns_tests = read('control/dns_tunnel_test.go')
for anchor in ['TestDnsTunnelRequiresThreeSimultaneousSignals',
               'TestDnsTunnelBenignDomainsDoNotFire',
               'TestDnsShannonEntropyKnownStrings']:
    need('ap6-dns-tests', dns_tests, anchor)

# AP-6 GIEF v1.0 + SBC fusion
gief_types = read('control/gief_types.go')
for anchor in ['GIEFVersion = "gief/v1.0"', 'SBC-PROV-01', 'SBC-EVID-08',
               'SBC-C2-05']:
    need('ap6-gief-types', gief_types, anchor)
gief = read('control/gief.go')
for anchor in ['func (e *XDREngine) attachGIEFEnvelope', 'Capability']:
    need('ap6-gief', gief, anchor)
forbid('ap6-gief', gief, r'\bKillEligible\s*:\s*true', 'kill-eligible GIEF field')
forbid('ap6-gief', gief, r'Decision:\s*"kill"', 'GIEF kill decision')
sbc = read('control/sbc_fusion.go') + read('control/sbc_graph.go')
for anchor in ['func NewSBCFusionEngine', 'func (e *XDREngine) recordSBCCorroborations',
               'halfLife']:
    need('ap6-sbc', sbc, anchor)
need('ap6-gief-tests', read('control/gief_test.go'),
     'TestGIEFAttachmentIsMetadataOnly')
need('ap6-sbc-immutability', read('control/sbc_fusion_test.go'),
     'TestSBCCorroborationContextAndDecisionImmutability')
need('ap6-sbc-families-complete', read('control/gief_mapping_test.go'),
     'TestGIEFSBCFamilySourceScan')

# AP-7 PermitV1 / review queue / prune / explainability
permit_types = read('control/permit_types.go')
for anchor in ['vgt-gedefense-permit-v1', 'AUTHORIZED', 'TOLERATED',
               'ANALYST_MODE', 'nonSuppressibleRuleIDs',
               'VGT-GEDEFENSE-PERMIT-V1']:
    need('ap7-permit-types', permit_types, anchor)
permit_eval = read('control/permit_eval.go')
for anchor in ['func (b *PermitBroker) Evaluate', 'func applyPermitDecision',
               'xdr.permit.authorized_suppressed']:
    need('ap7-permit-eval', permit_eval, anchor)
forbid('ap7-permit-eval', permit_eval, r'Decision:\s*"kill"',
       'permit path may never decide a kill')
need('ap7-permit-profiles', read('control/permit_profiles.go'),
     'func builtinPermitProfiles()')
need('ap7-permit-broker', read('control/permit_broker.go'),
     'func (e *XDREngine) pollPermits')
need('ap7-permit-xdr-hook', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go')), 'applyPermitDecision(decision, permitDecision)')
need('ap7-permit-fuzz', read('control/permit_fuzz_test.go'),
     'func FuzzPermitV1Decode')
need('ap7-permit-fuzz-makefile', read('Makefile'), 'FuzzPermitV1Decode')
permit_tests = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('permit_broker*_test.go')))
for anchor in ['TestPermitNeverAutoBlockDevBuildSimulation',
               'TestPermitNoPermitKeepsTheUnchangedKillGate',
               'TestPermitAuthorizedSuppressionRecordsEvidenceNoResponse',
               'TestPermitNonSuppressibleKernelRulesStayIncident',
               'TestPermitCorruptStoreFailsClosed',
               'TestPermitInvalidSignatureIsNeverAuthorized']:
    need('ap7-permit-tests', permit_tests, anchor)
rq = read('control/review_queue_types.go')
for anchor in ['vgt-gedefense-review-queue-v1', 'review-queue.json',
               'reviewQueueDiskReserveBytes', 'ReviewQueueView']:
    need('ap7-review-queue', rq, anchor)
need('ap7-review-tests', read('control/review_queue_test.go'),
     'TestReviewQueueCapacityAndDiskReserveRejections')
prune_rust = ''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('quarantine*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'quarantine').rglob('*.rs'))))
for anchor in ['pub fn prune_token', 'Ok("pruned".to_owned())']:
    need('ap7-prune-rust', prune_rust, anchor)
prune_ipc = read('control/coreipc_quarantine_prune.go')
need('ap7-prune-ipc', prune_ipc, 'func (c *CoreClient) QuarantinePrune')
prune_flow = read('control/quarantine_prune.go')
for anchor in ['errQuarantinePruneEvidence', 'quarantinePruner']:
    need('ap7-prune-flow', prune_flow, anchor)
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for anchor in ['POST /api/v1/quarantine/prune',
               'GET /api/v1/xdr/review',
               'POST /api/v1/xdr/review/{id}/ack',
               'DELETE /api/v1/xdr/review/{id}']:
    need('ap7-routes', server, anchor)
need('ap7-prune-handler', read('control/server_handlers_permits.go'),
     'func (s *APIServer) quarantinePrune')
need('ap7-prune-evidence-tests', read('control/quarantine_prune_test.go'),
     'TestQuarantinePruneEvidenceFirstRefusal')
explain = read('control/explainability.go')
for anchor in ['func (e *XDREngine) attachFindingExplainability',
               'CapabilityStatus', 'ExoneratingEvidenceHint', 'Blindspots']:
    need('ap7-explainability', explain, anchor)
need('ap7-explain-tests', read('control/explainability_test.go'),
     'TestExplainabilityDoesNotMutateDecisionFields')
core_main = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
for anchor in ['["QUARANTINE_PRUNE", object_id, identity]', 'prune_token(']:
    need('ap7-prune-dispatch', core_main, anchor)

# Kill gate and observe-only negatives (must stay untouched by AP-6/AP-7).
need('kill-gate-r3', read('control/xdr_rules.go'),
     'responseScore >= 120 && len(killCategories) >= 2')
forbid('xdr-core-r3', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go')), r'Decision:\s*"kill"',
       'a hard-coded kill decision in the XDR engine')

if missing:
    raise SystemExit('V6.3.0 round-3 anchors missing:\n' + '\n'.join(missing))
PYV63R3
pass 'V6.3.0 AP-6 ingress/PCR, DNS capture/tunnelling, GIEF v1.0/SBC fusion and AP-7 PermitV1/review-queue/prune/explainability anchors present'

# V6.3.0 round 4 (AP-8 Chameleon install profile and AP-9 S12 high-priority
# ring/backpressure + R6 RBAC + S08/S15 witness priority push). Anchors pin the
# default-off guarantee, the kernel name renaming, the independent high-priority
# ring, the role/step-up enforcement and the pre-log witness hand-off.
python3 - "$ROOT" <<'PYV63R4'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-8: opt-in Chameleon installation identity.
chameleon_rs = read('rust/gedefense-core/src/chameleon.rs')
for anchor in ['CHAMELEON_MANIFEST_SCHEMA', 'pub(crate) struct ManagedEbpf',
               'pub fn from_manifest', 'pub fn load_object',
               'pub(crate) fn map_name', 'pub(crate) fn program_name']:
    need('ap8-chameleon-core', chameleon_rs, anchor)
need('ap8-chameleon-default-off', chameleon_rs, 'Ebpf::load_file')
chameleon_go = read('control/chameleon.go')
for anchor in ['func NewChameleonProfile', 'func (p *ChameleonProfile) Active',
               'func (p *ChameleonProfile) Apply', 'func (p *ChameleonProfile) AuditMapping',
               'func chameleonScanSocket']:
    need('ap8-chameleon-control', chameleon_go, anchor)
need('ap8-chameleon-seam', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('main*.go')) if not p.name.endswith('_test.go')), 'NewChameleonProfile(chameleonManifestPath)')
need('ap8-chameleon-flag', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('main*.go')) if not p.name.endswith('_test.go')), 'chameleon-manifest')
need('ap8-chameleon-load', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts)), 'chameleon::ManagedEbpf::new')
need('ap8-chameleon-arg', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts)), '"chameleon-manifest"')
need('ap8-chameleon-installer', read('scripts/apply-chameleon-profile.sh'),
     'vgt-gedefense-chameleon-v1')
need('ap8-chameleon-template', read('packaging/templates/chameleon-manifest.example'),
     'bpf_name_salt')
need('ap8-chameleon-doc', read('docs/V6.3.0-CHAMELEON.md'), 'Chameleon')

# AP-9 S12: independent high-priority ring + telemetry token buckets.
sec_common = read('rust/gedefense-common/src/sec_crit.rs')
for anchor in ['SEC_CRIT_EVENT_WIRE_BYTES', 'decode_sec_crit_event',
               'telemetry_bucket_step', 'SEC_CRIT_SOURCE_CRED_GUARD',
               'SEC_CRIT_BUCKET_ENTRIES']:
    need('ap9-sec-crit-abi', sec_common, anchor)
sec_ebpf = read('rust/gedefense-ebpf/src/sec_crit.rs')
for anchor in ['static SEC_CRIT_EVENTS', 'static SEC_CRIT_STATE',
               'static SEC_CRIT_COUNTERS', 'TELEMETRY_FLOOD_BUCKETS',
               'fn sec_crit_armed', 'fn sec_crit_emit', 'fn telemetry_budget_allow',
               'fn telemetry_note_suppressed']:
    need('ap9-sec-crit-ebpf', sec_ebpf, anchor)
for emitter in ['rust/gedefense-ebpf/src/xdr_kernel.rs',
                'rust/gedefense-ebpf/src/ingress_flow.rs',
                'rust/gedefense-ebpf/src/dns_capture.rs',
                'rust/gedefense-ebpf/src/styx_egress.rs']:
    need('ap9-s12-budget-' + emitter.rsplit('/', 1)[-1], read(emitter),
         'telemetry_budget_allow')
for critical in ['rust/gedefense-ebpf/src/credential_guard.rs',
                 'rust/gedefense-ebpf/src/bpf_guard.rs',
                 'rust/gedefense-ebpf/src/kernel_hooks.rs',
                 'rust/gedefense-ebpf/src/persistence.rs']:
    need('ap9-s12-critical-' + critical.rsplit('/', 1)[-1], read(critical),
         'sec_crit_emit')
sec_core = read('rust/gedefense-core/src/sec_crit.rs')
for anchor in ['SEC_CRIT_EVENTS', 'fn take_events', 'fn status',
               'crate::chameleon::map_name("SEC_CRIT_EVENTS")']:
    need('ap9-sec-crit-core', sec_core, anchor)
sec_control = read('control/xdr_sec_crit.go')
for anchor in ['XDR.TELEMETRY_FLOOD_SUPPRESSION', 'XDR.SEC_CRIT_DIFFERENTIAL_GAP',
               'func (e *XDREngine) pollSecCrit']:
    need('ap9-sec-crit-control', sec_control, anchor)
forbid('ap9-sec-crit-control', sec_control, r'\bKillEligible\s*:\s*true',
       'kill-eligible S12 rule')
forbid('ap9-sec-crit-control', sec_control, r'Decision:\s*"kill"', 'S12 kill decision')
need('ap9-sec-crit-flood-severity', sec_control, 'secCritPressureCause      = "sec_crit_backpressure"')
need('ap9-sec-crit-degraded', sec_control, 'e.markDegradedCause(secCritPressureCause')
need('ap9-sec-crit-recovered', sec_control, 'e.clearDegradedCause(secCritPressureCause)')
need('ap9-sec-crit-ipc', read('control/coreipc_sec_crit.go'),
     'func (c *CoreClient) SecCritEvents()')
need('ap9-sec-crit-fuzz', read('control/coreipc_sec_crit_test.go'),
     'func FuzzCoreSecCritParser')
need('ap9-sec-crit-makefile', read('Makefile'), 'FuzzCoreSecCritParser')

# AP-9 R6: management-API RBAC with step-up.
rbac_types = read('control/rbac_types.go')
for anchor in ['RoleObserver', 'RoleOperator', 'RoleCritical',
               'roleObserverName', 'roleOperatorName']:
    need('ap9-rbac-types', rbac_types, anchor)
rbac = read('control/rbac.go')
for anchor in ['func (s *APIServer) classifyCredential',
               'func (s *APIServer) requireRole',
               'func (s *APIServer) authStepUp',
               'func (s *APIServer) authRoles',
               'directStepUpHeader']:
    need('ap9-rbac', rbac, anchor)
rbac_auth = read('control/rbac_auth.go')
need('ap9-rbac-auth', rbac_auth, 'func (s *APIServer) criticalStepUpKey')
need('ap9-rbac-lockout', rbac_auth, 'newAttemptLockout')
server_rbac = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for anchor in ['GET /api/v1/auth/roles', 'POST /api/v1/auth/step-up',
               's.requireRole(RoleObserver, s.authRoles)',
               's.requireRole(RoleOperator, s.authStepUp)']:
    need('ap9-rbac-routes', server_rbac, anchor)
gateway_rbac = read('gateway/rbac.go')
for anchor in ['func newGatewayCriticalClaim', 'func gatewayCriticalRoute',
               'gatewayRoleHeader', 'gatewayClaimMACHeader']:
    need('ap9-rbac-gateway', gateway_rbac, anchor)
gateway_step = read('gateway/stepup.go')
for anchor in ['func (a *stepUpAuthority) issue', 'func (a *stepUpAuthority) consume',
               'func (a *stepUpAuthority) locked']:
    need('ap9-rbac-gateway-stepup', gateway_step, anchor)
rbac_tests = read('control/rbac_test.go')
for anchor in ['TestRBACCriticalActionsRequireStepUp', 'TestRBACObserverIsReadOnly',
               'TestRBACLockoutBoundedAndReported', 'TestRBACGatewayClaimVerification',
               'TestStepUpDirectProofVerification']:
    need('ap9-rbac-tests', rbac_tests, anchor)
need('ap9-rbac-gateway-tests', read('gateway/rbac_test.go'),
     'TestRBACGatewayPasswordStepUpFlow')
need('ap9-rbac-doc', read('docs/V6.3.0-RBAC.md'), 'Observer')

# AP-9 S08/S15: witness priority push before the local forensic log write.
witness = read('control/witness_priority.go')
for anchor in ['func (e *XDREngine) pushCriticalWitness', 'witnessPriorityQueueCapacity',
               'func criticalWitnessTrigger', 'xdr.witness_priority_failed']:
    need('ap9-witness-priority', witness, anchor)
need('ap9-witness-order', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go')),
     'e.pushCriticalWitness(incident)')
need('ap9-witness-order-before-log', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go')),
     'V6.3.0 AP-9 (S08/S15)')
need('ap9-witness-tests', read('control/witness_priority_test.go'),
     'TestWitnessPriorityOrderingBeforeForensicAppend')

# Kill gate unchanged.
need('kill-gate-r4', read('control/xdr_rules.go'),
     'responseScore >= 120 && len(killCategories) >= 2')

if missing:
    raise SystemExit('V6.3.0 round-4 anchors missing:\n' + '\n'.join(missing))
PYV63R4
pass 'V6.3.0 AP-8 Chameleon profile, AP-9 S12 high-priority ring/backpressure, R6 RBAC and S08/S15 witness priority anchors present'

