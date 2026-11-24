#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 7 (original lines 1752-2125).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PYP4'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
missing = []

def read(relative):
    path = root / relative
    if not path.is_file():
        missing.append(f'missing file: {relative}')
        return ''
    return path.read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text, re.S) is not None:
        missing.append(f'{component}: forbidden {label}')

# --- ABI-1: persistent ledger epoch + atomic checkpoint view (§3) ------------
ledger = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('evidence_ledger*.go')) if not p.name.endswith('_test.go'))
rotation = read('control/evidence_rotation.go')
for anchor in (
    'LedgerEpoch uint64 `json:"ledger_epoch,omitempty"`',
    'func (l *EvidenceLedger) Checkpoint() (EvidenceCheckpointView, error) {',
    'func (l *EvidenceLedger) Head() (EvidenceCheckpointView, error) {',
    'func (l *EvidenceLedger) PublicKeyFingerprint() (string, error) {',
    'func (l *EvidenceLedger) WitnessCheckpointSigner() WitnessCheckpointSigner {',
    'Records: l.sequence,',
    'LedgerEpoch: l.ledgerEpoch, PublicKeyFingerprint: evidencePublicKeyFingerprint(l.publicKey),',
    'checkpoint.LedgerEpoch != ledgerEpoch',
):
    need('go-ledger', ledger, anchor)
# A rotation increments the epoch before the fresh sequence: a legitimate
# rotation must never look like a rollback to a witness. Crash recovery reads the
# epoch back from the authenticated head instead of resetting it.
for anchor in (
    'nextEpoch := l.ledgerEpoch + 1',
    'if err := writeEvidenceCheckpoint(l.headPath, 0, "", nextEpoch, l.crypto); err != nil {',
    'l.ledgerEpoch = nextEpoch',
    'ledgerEpoch: checkpoint.LedgerEpoch}',
):
    need('go-rotation', rotation, anchor)

# --- ABI-2: signed checkpoint contract, domains and rejecting decoder (§3) ---
checkpoint = read('control/witness_checkpoint.go')
for anchor in (
    'WitnessCheckpointSchema = "vgt-gedefense-witness-checkpoint-v1"',
    'witnessCheckpointDomain = "VGT-GEDEFENSE-WITNESS-CHECKPOINT-V1\\x00"',
    'witnessQuoteKindNone = "none"',
    'witnessCheckpointMaxCounter = 1 << 53',
    'witnessCheckpointMaxBytes = 64 << 10',
    'func DecodeWitnessCheckpoint(data []byte) (WitnessCheckpoint, error) {',
    'func SignWitnessCheckpoint(checkpoint WitnessCheckpoint, signer WitnessCheckpointSigner) (WitnessCheckpoint, error) {',
    'func VerifyWitnessCheckpoint(checkpoint WitnessCheckpoint, publicKey ed25519.PublicKey) error {',
    'func BootPostureDigest(report BootTrustReport) string {',
    'func PolicyDigest(settings RuntimeSettings) (string, error) {',
    'if _, allowed := witnessCheckpointAllowedFields[name]; !allowed {',
    'if _, duplicate := seen[name]; duplicate {',
    'return WitnessCheckpoint{}, errors.New("witness checkpoint contains trailing data")',
    'if checkpoint.Records != checkpoint.Sequence {',
    'if checkpoint.QuoteKind != witnessQuoteKindNone {',
    'if checkpoint.LedgerEpoch > witnessCheckpointMaxCounter || checkpoint.Sequence > witnessCheckpointMaxCounter ||',
):
    need('go-checkpoint', checkpoint, anchor)
need('go-checkpoint', checkpoint, 'witnessBootPostures = map[string]struct{}{"VERIFIED": {}, "OBSERVE": {}, "NOT_SUPPORTED": {}}')
need('go-checkpoint', checkpoint, 'witnessSensorStates = map[string]struct{}{"online": {}, "degraded": {}, "offline": {}, "disabled": {}}')
# Privacy contract: the checkpoint is the only artifact that leaves the host, so
# it must carry hashes/fingerprints/enums/counters only - never a path, token,
# key material, target/IP or free-form boot evidence. The signed payload must not
# contain its own signature field (the signature separates from the payload).
if 'type witnessCheckpointPayload struct {' not in checkpoint:
    missing.append('go-checkpoint: signed payload type is missing')
else:
    checkpoint_struct = checkpoint.split('type WitnessCheckpoint struct {', 1)[-1].split('}', 1)[0]
    checkpoint_payload = checkpoint.split('type witnessCheckpointPayload struct {', 1)[-1].split('}', 1)[0]
    if 'json:"signature"' in checkpoint_payload:
        missing.append('go-checkpoint: the signed payload must not contain its own signature field')
    if re.search(r'json:"[a-z_]*(?:path|file|cmdline|evidence|source|target|token|ip|private|secret)[a-z_]*"', checkpoint_struct):
        missing.append('go-checkpoint: checkpoint must not carry paths, tokens, key material or free-form evidence/PII fields')
forbid('go-checkpoint', checkpoint, r'item\.(?:Source|Evidence|Summary|Command|Cmdline)', 'boot-posture digest must hash {id,state,digest} only')

# --- ABI-3: hardened witness HTTPS client (Mode A, §4) -----------------------
client = read('control/witness_client.go')
for anchor in (
    'Proxy: nil,',
    'CheckRedirect: func(*http.Request, []*http.Request) error {',
    'return errWitnessRedirectRefused',
    'if splitErr != nil || port != "443" {',
    'tls.Config{MinVersion: tls.VersionTLS12}',
    'witnessMaxResponseBytes = 64 << 10',
    'io.LimitReader(response.Body, c.maxResponse+1)',
    'response exceeds the 64 KiB bound',
    'func witnessSPKIPinMatches(pin []byte, cert *x509.Certificate) bool {',
    'subtle.ConstantTimeCompare(sum[:], pin) == 1',
    'func readWitnessPrivateFile(path string, max int64) ([]byte, error) {',
    'if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {',
    'if info.Mode().Perm()&0o077 != 0 {',
    'tls.LoadX509KeyPair(settings.ClientCertFile, settings.ClientKeyFile)',
    'witnessChallengeMaxHexBytes = 128',
    'if receipt.CheckpointID != checkpoint.CheckpointID {',
    'if receipt.WitnessSeq <= c.lastSeq {',
):
    need('go-witness-client', client, anchor)
need('go-witness-client', client, 'case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:')
need('go-witness-client', client, 'case response.StatusCode >= 400 && response.StatusCode < 500:')
need('go-witness-client', client, 'case response.StatusCode >= 300 && response.StatusCode < 400:')
forbid('go-witness-client', client, r'ProxyFromEnvironment', 'environment proxy (the transport must keep Proxy: nil)')

# --- ABI-4: signed receipts, monotonic acknowledgment (§4/§5) ----------------
export = read('control/witness_export.go')
for anchor in (
    'witnessReceiptSchema = "vgt-gedefense-witness-receipt-v1"',
    'witnessReceiptDomain = "VGT-GEDEFENSE-WITNESS-RECEIPT-V1\\x00"',
    'func ValidateWitnessReceipt(receipt WitnessReceipt) error {',
    'func DecodeWitnessReceipt(data []byte) (WitnessReceipt, error) {',
    'func VerifyWitnessReceipt(receipt WitnessReceipt, publicKey ed25519.PublicKey) error {',
    'func (e *WitnessEngine) ImportReceipt(_ context.Context, raw []byte) (WitnessReceipt, error) {',
    'if receipt.WitnessSeq <= ack.LastWitnessSeq {',
    'if receipt.CheckpointID != export.CheckpointID {',
    'e.flagEquivocation("rollback")',
):
    need('go-receipt', export, anchor)

# --- ABI-5: bounded, authenticated, fail-closed outbox (§4) ------------------
outbox = read('control/witness_outbox.go')
for anchor in (
    'witnessOutboxPurpose = "witness-outbox"',
    'errWitnessOutboxFull = errors.New("witness outbox is full")',
    'if o.maxEntries > 0 && len(o.entries)+1 > o.maxEntries {',
    'atomicWriteFile(o.path, sealed, 0o600)',
    'cipher.Decrypt(path, witnessOutboxPurpose, raw, nil)',
    'if entry.LocalSeq == 0 || entry.LocalSeq <= sequence {',
    'return 0, errWitnessOutboxFull',
):
    need('go-outbox', outbox, anchor)
engine = read('control/witness_engine.go')
for anchor in (
    'func (e *WitnessEngine) checkpointLocked(ctx context.Context) (WitnessCheckpoint, error) {',
    'if settings.Mode == witnessModeHTTP && e.outbox != nil && e.outbox.full() {',
    'e.markOutboxFull()',
    'e.recordEvent("info", "witness.checkpoint.created",',
    'e.recordEvent("info", "witness.acked",',
    'witnessAckPurpose = "witness-ack"',
    'func (e *WitnessEngine) recordAck(receipt WitnessReceipt, checkpoint WitnessCheckpoint) {',
    'func saveWitnessAckState(path string, cipher *StorageCipher, state witnessAckState) error {',
):
    need('go-witness-engine', engine, anchor)

# --- ABI-6: equitable detection: fork/rollback, rotation is NOT an alarm -----
for anchor in (
    'func (e *WitnessEngine) observeHead(head witnessHead) {',
    'func compareWitnessHeads(previous, head witnessHead) string {',
    'if head.epoch > previous.epoch {',
    'return "" // a rotation is legitimate',
    'func (e *WitnessEngine) flagEquivocation(kind string) {',
    'if settings.TriggerLockdownOnEquivocation && lockdown != nil {',
    'lockdown.TriggerWitnessEquivocation(fingerprint)',
    'func witnessEquivocationFingerprint(kind string) string {',
    'state.AddIncident(XDRIncident{',
):
    need('go-witness-engine', engine, anchor)
lockdown_triggers = read('control/lockdown_triggers.go')
need('go-lockdown', lockdown_triggers, 'func (e *LockdownEngine) TriggerWitnessEquivocation(fingerprint string) error {')
need('go-lockdown', lockdown_triggers, 'if !settings.TriggerWitnessEquivocation {')
need('go-lockdown', read('control/lockdown_settings.go'), 'lockdownReasonWitnessEquivocation = "witness-equivocation"')
need('go-lockdown', read('control/lockdown_settings.go'), 'TriggerWitnessEquivocation bool `json:"trigger_witness_equivocation"`')

# --- ABI-7: default-off engine, honest capability vocabulary (§7/§8) ---------
witness_core = read('control/witness.go')
for anchor in (
    'errWitnessDisabled = errors.New("witness is disabled")',
    'func NewWitnessEngine(cfg WitnessEngineConfig) (*WitnessEngine, error) {',
    'func (e *WitnessEngine) Run(ctx context.Context) {',
    'func (e *WitnessEngine) ApplyRuntimeSettings(settings RuntimeSettings) error {',
    'e.failClosed = "witness outbox is corrupt"',
    'e.failClosed = "witness ack baseline is corrupt"',
    'e.recordEventOnce("outbox-full", "critical", "witness.outbox_full",',
    'e.recordEventOnce("ack-corrupt", "critical", "witness.push.failed",',
    'return errors.New("witness returned a nonce it already issued")',
):
    need('go-witness', witness_core, anchor)
need_match('go-witness', witness_core, 'software key binding is honest (no hardware claim)', r'witnessKeyBinding\s+=\s+"software"')
need_match('go-witness', witness_core, 'event cooldown bounds a repeated condition', r'witnessEventCooldown\s+=\s+5 \* time\.Minute')

# --- ABI-8: Settings v17, default off, reject-not-repair (§7) ----------------
witness_settings = read('control/witness_settings.go')
for anchor in (
    'func defaultWitnessFabricSettings() WitnessFabricSettings {',
    'func validateWitnessFabricSettings(in *WitnessFabricSettings) error {',
    'if in.PinnedServerKeyFile == "" && in.PinnedServerSPKI == "" {',
    'return errors.New("witness is enabled but mode is off")',
    'if parsed.Scheme != "https" {',
    'if port := parsed.Port(); port != "" && port != "443" {',
    'if (in.ClientCertFile == "") != (in.ClientKeyFile == "") {',
    'witnessOutboxFloorBytes = 64 << 10',
    'witnessOutboxCeilingBytes = 64 << 20',
    'func witnessModeActive(settings WitnessFabricSettings) bool {',
    'witnessMigrationNote = "witness namespace added with enabled=false and mode=off',
):
    need('go-witness-settings', witness_settings, anchor)
need_match('go-witness-settings', witness_settings, 'witness defaults are enabled=false and mode=off', r'func defaultWitnessFabricSettings\(\) WitnessFabricSettings \{.*?Enabled:\s+false,.*?Mode:\s+witnessModeOff,')
runtime_settings = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
need_match('go-runtime', runtime_settings, 'settings schema version is at least v17 (POINT 4 witness migration)', r'const fabricSettingsVersion = (?:1[7-9]|[2-9][0-9])')
need('go-runtime', runtime_settings, 'Witness *WitnessFabricSettings `json:"witness,omitempty"`')
schema = read('control/fabric_schema.go')
need('go-schema', schema, '{module: "witness", group: "Transport", key: "enabled", label: "Out-of-Band Witness", kind: FabricTypeBoolean, def: false')
need('go-schema', schema, '{module: "witness", group: "Escalation", key: "trigger_lockdown_on_equivocation", label: "Lockdown on Equivocation", kind: FabricTypeBoolean, def: false')
need('go-schema', schema, 'key: "outbox_max_bytes"')

# --- ABI-9: operator API, evidence gate, status projection (§7) --------------
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for route in (
    'mux.HandleFunc("GET /api/v1/witness/status", s.auth(s.witnessStatus))',
    'mux.HandleFunc("GET /api/v1/witness/export", s.auth(s.witnessExport))',
    'mux.HandleFunc("POST /api/v1/witness/checkpoint", s.auth(s.witnessCheckpoint))',
    'mux.HandleFunc("POST /api/v1/witness/push", s.auth(s.witnessPush))',
    'mux.HandleFunc("POST /api/v1/witness/challenge", s.auth(s.witnessChallenge))',
    'mux.HandleFunc("POST /api/v1/witness/import", s.auth(s.witnessImport))',
):
    need('go-server', server, route)
if 'func evidenceGateExempt(path string) bool {' not in server:
    missing.append('go-server: evidenceGateExempt is missing')
else:
    gate_block = server.split('func evidenceGateExempt(path string) bool {', 1)[-1].split('\n}', 1)[0]
    if 'witness' in gate_block:
        missing.append('go-server: witness routes must not be exempt from the evidence gate (only the four documented exits are)')
witness_api = read('control/witness_api.go')
for anchor in (
    'witnessPushConfirmation = "PUSH WITNESS"',
    'witnessImportMaxBytes = 16 << 10',
    's.witnessLimiter = NewRateLimiter(12, 4)',
    'r.Body = http.MaxBytesReader(w, r.Body, witnessImportMaxBytes)',
    'func (e *WitnessEngine) StatusView() WitnessStatus {',
    'QuoteKind: witnessQuoteKindNone, KeyBinding: witnessKeyBinding,',
):
    need('go-witness-api', witness_api, anchor)
need('go-state', ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('state*.go')) if not p.name.endswith('_test.go')), 'Witness *WitnessStatus `json:"witness,omitempty"`')
main_go = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('main*.go')) if not p.name.endswith('_test.go'))
need('go-main', main_go, 'srv.AttachWitness(witnessEngine)')
need('go-main', main_go, 'go witnessEngine.Run(xdrCtx)')
need('go-main', main_go, 'filepath.Join(evidenceDir, "witness", "outbox.enc")')
need('go-main', main_go, 'filepath.Join(evidenceDir, "witness", "ack.enc")')

# --- no fake witness server: production code has no test server/listener -----
witness_prod = [path for path in sorted((root / 'control').glob('witness*.go')) if not path.name.endswith('_test.go')]
if not witness_prod:
    missing.append('control: witness production file set is empty')
for path in witness_prod:
    body = read('control/' + path.name)
    if re.search(r'\bnet\.Listen\(|\bListenAndServe\(|"net/http/httptest"', body):
        missing.append(f'{path.name}: production witness code must not contain a witness test server or listener')
need('go-witness-client-test', read('control/witness_client_test.go'), 'httptest.NewTLSServer')

# --- bounds: VGT 500-line rule for the new files + report limit --------------
for path in sorted((root / 'control').glob('witness*.go')):
    lines = len(path.read_text(encoding='utf-8').splitlines())
    if lines > 500:
        missing.append(f'{path.name}: {lines} lines exceed the VGT 500-line rule')
report = read('docs/POINT4-PHASE1-REPORT.md')
report_lines = len(report.splitlines())
if report_lines == 0 or report_lines > 180:
    missing.append(f'docs/POINT4-PHASE1-REPORT.md: {report_lines} lines (limit 180)')
need('docs-report', report, 'NOT_TESTED')
need('docs-report', report, 'Checkpoint+Receipt')

# --- documentation + packaging boundary -------------------------------------
p4doc = read('docs/POINT4-WITNESS.md')
for anchor in (
    '**Status:** IMPLEMENTIERT (Phase 1)',
    '## 13. Umsetzungsabweichungen',
    'ledger_epoch+1',
    'quote_kind="none"',
    'key_binding="software"',
    'vgtw1',
    'Witness-Server',
    'Evidence-Gate',
):
    need('docs-p4', p4doc, anchor)
need('docs-architecture', read('ARCHITECTURE.md'), '### 3.38 Point 4')
# Point-4 implementation anchor must live in versioned documentation rather
# than gitignored Next.md so fresh checkouts enforce the exact same gate.
need('docs-report', report, 'Phase-1-Implementierungs- und Verifikationsbericht')
control_unit = read('packaging/systemd/gedefense-control.service')
for directive in (
    'User=gedefense',
    'NoNewPrivileges=true',
    'ProtectSystem=strict',
    'ReadWritePaths=/var/lib/vgt/gedefense',
    'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK',
):
    need('systemd-control-unit', control_unit, directive)
# FIND-008 (VGT-AUDIT-20261118-GD61-R2): the control plane holds zero Linux
# capabilities and no AF_PACKET family; CAP_NET_RAW + CAP_NET_ADMIN + AF_PACKET
# are isolated inside gedefense-capture-helper.service with IPAddressDeny=any,
# no AF_INET/AF_INET6, and zero access to /etc/vgt/gedefense, /var/lib/vgt/gedefense,
# or /run/vgt-gedefense.
capability_lines = sorted(
    line.strip() for line in control_unit.splitlines()
    if line.strip().startswith(('CapabilityBoundingSet=', 'AmbientCapabilities='))
)
if capability_lines != ['CapabilityBoundingSet=']:
    missing.append('systemd-control-unit: capability lines must be exactly CapabilityBoundingSet= (zero capabilities, FIND-008)')
family_lines = [
    line.strip() for line in control_unit.splitlines()
    if line.strip().startswith('RestrictAddressFamilies=')
]
if family_lines != ['RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK']:
    missing.append('systemd-control-unit: RestrictAddressFamilies must be exactly AF_UNIX AF_INET AF_INET6 AF_NETLINK (no AF_PACKET, FIND-008)')

capture_unit = read('packaging/systemd/gedefense-capture-helper.service')
for directive in (
    'User=gedefense',
    'Group=gedefense',
    'RuntimeDirectory=vgt-gedefense-capture',
    'RuntimeDirectoryMode=0700',
    'NoNewPrivileges=true',
    'ProtectSystem=strict',
    'ProtectHome=true',
    'PrivateDevices=true',
    'IPAddressDeny=any',
    'ReadOnlyPaths=/opt/vgt/gedefense/current',
    'ReadWritePaths=/run/vgt-gedefense-capture',
    '--capture-helper',
    '--capture-helper-socket=/run/vgt-gedefense-capture/capture.sock',
):
    need('systemd-capture-helper-unit', capture_unit, directive)
capture_cap_lines = sorted(
    line.strip() for line in capture_unit.splitlines()
    if line.strip().startswith(('CapabilityBoundingSet=', 'AmbientCapabilities='))
)
if capture_cap_lines != sorted((
    'CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN',
    'AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN',
)):
    missing.append('systemd-capture-helper-unit: capability lines must be exactly the reviewed CAP_NET_RAW CAP_NET_ADMIN pair (FIND-008)')
capture_family_lines = [
    line.strip() for line in capture_unit.splitlines()
    if line.strip().startswith('RestrictAddressFamilies=')
]
if capture_family_lines != ['RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET']:
    missing.append('systemd-capture-helper-unit: RestrictAddressFamilies must be exactly AF_UNIX AF_NETLINK AF_PACKET (FIND-008)')
forbid('systemd-capture-helper-unit', capture_unit, r'(?:ReadWritePaths|ReadOnlyPaths)=[^\n]*(?:/etc/vgt/gedefense|/var/lib/vgt/gedefense|/run/vgt-gedefense(?:\s|$))', 'access to control secrets, state, or core/cell-helper sockets')
capture_helper_src = read('control/capture_helper_linux.go')
need('capture-helper-source', capture_helper_src, 'SO_PEERCRED')
need('capture-helper-source', capture_helper_src, '0o600')
# FIND-009 regression pin: exposure.js must render advisories through renderRows, never undefined renderAdvisoryRows.
exposure_js = read('control/web/v61/exposure.js')
need('v61-exposure-js', exposure_js, "renderRows('exposureAdvisoryRows'")
forbid('v61-exposure-js', exposure_js, r'\brenderAdvisoryRows\b', 'undefined renderAdvisoryRows call (FIND-009)')
forbid('systemd-control-unit', control_unit, r'ReadWritePaths=[^\n]*/witness', 'a witness-specific ReadWritePaths exception (state stays inside /var/lib/vgt/gedefense)')
core_unit = read('packaging/systemd/gedefense-core.service')
need('systemd-core-unit', core_unit, 'ReadWritePaths=/var/lib/vgt/gedefense')
forbid('systemd-core-unit', core_unit, r'ReadWritePaths=[^\n]*/witness', 'a witness state grant in the core unit (the state belongs to the control plane)')
witness_units = sorted(path.name for path in (root / 'packaging' / 'systemd').glob('*witness*'))
if witness_units:
    missing.append('packaging/systemd: no dedicated witness unit may ship (unprivileged Go control only): ' + ', '.join(witness_units))
need('tmpfiles', read('packaging/tmpfiles/vgt-gedefense.conf'), 'd /var/lib/vgt/gedefense 1770 root gedefense -')
need('validate-systemd', read('scripts/validate-systemd.sh'), 'POINT 4')
need('install-smoke', read('packaging/tests/install-smoke.sh'), 'POINT 4')
need('makefile', read('Makefile'), 'FuzzWitnessCheckpointDecode')
need('makefile', read('Makefile'), 'FuzzWitnessReceiptDecode')

if missing:
    raise SystemExit('Point 4 out-of-band witness anchors missing:\n' + '\n'.join(missing))
PYP4
