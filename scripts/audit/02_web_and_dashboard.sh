#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 2 (original lines 363-674).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
gw=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'gateway').glob('*.go')) if not p.name.endswith('_test.go'))
required=[
    'sameOriginRequired', 'Sec-Fetch-Site', 'subtle.ConstantTimeCompare',
    '__Host-vgt_gedefense_session', 'SameSiteStrictMode', 'HttpOnly: true',
    'Strict-Transport-Security', 'Host allowlisting',
]
# Host allowlisting is implemented through sameHost in security(), not a literal comment.
required.remove('Host allowlisting')
missing=[x for x in required if x not in gw]
if 'if !sameHost(r.Host, g.publicHost)' not in gw:
    missing.append('public Host allowlist')
if 'r.Header.Del(header)' not in gw:
    missing.append('central proxy header scrub loop')
for header in ['Origin','Referer','Cookie','Authorization','Forwarded','X-Forwarded-For','X-Forwarded-Host','X-Forwarded-Proto']:
    if f'"{header}"' not in gw:
        missing.append('proxy scrub list contains '+header)
if 'r.Header["X-Forwarded-For"] = nil' not in gw:
    missing.append('ReverseProxy X-Forwarded-For suppression')
# FIND-012 (VGT-AUDIT-20261114-GD51): no anonymous build/version surface. The
# former route and its handler must not come back; the retired path is answered
# with a plain 404 that carries no build metadata, and liveness stays the only
# anonymous health answer.
if 'func (g *gateway) version(' in gw:
    raise SystemExit('unauthenticated gateway version handler exists')
if 'mux.HandleFunc("GET /gateway/version", g.removed)' not in gw or 'func (g *gateway) removed(' not in gw:
    raise SystemExit('retired version path is not answered as a plain not-found')
if 'http.NotFound(w, r)' not in gw:
    raise SystemExit('removed version path does not produce a plain 404')
if 'fmt.Fprintln(w, version)' in gw:
    raise SystemExit('gateway source still writes the build version to a response')
if 'func (g *gateway) livez(' not in gw or '{"ok":true}' not in gw:
    raise SystemExit('minimal unauthenticated liveness endpoint missing or changed')
# FIND-010 (VGT-AUDIT-20261114-GD51): the memory-hard password verification must
# only be reachable through the process-wide admission gate on the sign-in path.
if 'maxConcurrentKDF' not in gw or 'func (k *kdfGate) acquire(' not in gw:
    raise SystemExit('password KDF admission gate missing')
if 'g.verifyPasswordGated(r.Context(), ip, password)' not in gw:
    raise SystemExit('sign-in handler bypasses the password KDF admission gate')
if 'Retry-After' not in gw:
    raise SystemExit('KDF backpressure response has no Retry-After header')
if missing:
    raise SystemExit('gateway trust-boundary anchors missing: '+', '.join(missing))
PY
pass 'login/session/CSRF/Host checks, reverse-proxy header scrubbing and no anonymous version surface present'

python3 - "$ROOT" <<'PYFIND9'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
sudoers=(root/'integration'/'astraeaos'/'90-astraeaos-gedefense.sudoers').read_text(encoding='utf-8')
# FIND-009 (VGT-AUDIT-20261114-GD51): the set-password helper must never be
# launchable through a passwordless sudo rule; the fixed-argument rule stays, but
# only with sudo's interactive re-authentication.
if re.search(r'(?m)^\s*%wheel\s+ALL=\(root\)\s+NOPASSWD:[^\n]*/usr/lib/astraeaos/gedefense-set-password\b', sudoers):
    raise SystemExit('sudoers still grants NOPASSWD for gedefense-set-password')
if not re.search(r'(?m)^\s*%wheel\s+ALL=\(root\)\s+/usr/lib/astraeaos/gedefense-set-password\s+""\s*$', sudoers):
    raise SystemExit('interactive fixed-argument set-password sudoers rule missing')
helper=(root/'integration'/'astraeaos'/'gedefense-set-password').read_text(encoding='utf-8')
for anchor in [
    '/dev/tty',
    '--verify-password-stdin',
    'Current GeDefense operator password',
    'installed credential was not changed',
    'initial_setup_authorized',
    'initial-access-password',
]:
    if anchor not in helper:
        raise SystemExit('set-password current-password step-up anchor missing: '+anchor)
gateway=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'gateway').glob('*.go')) if not p.name.endswith('_test.go'))
if 'verify-password-stdin' not in gateway:
    raise SystemExit('gateway verification path required by the set-password step-up is missing')
PYFIND9
pass 'set-password keeps interactive sudo/polkit re-authentication and requires a current-password step-up before overwriting'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
gw=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'gateway').glob('*.go')) if not p.name.endswith('_test.go'))
argon=(root/'gateway'/'argon2_linux.go').read_text(encoding='utf-8')
if 'v2$argon2id$v=19$m=%d,t=%d,p=%d' not in gw or 'memoryKiB uint32 = 65536' not in gw or 'timeCost uint32 = 3' not in gw:
    raise SystemExit('Argon2id password policy missing or changed')
if 'argon2id_hash_raw' not in argon or 'libargon2.so.1' not in argon:
    raise SystemExit('Argon2id implementation/runtime binding missing')
crypto=(root/'control'/'storage_crypto.go').read_text(encoding='utf-8')
for anchor in ['aes.NewCipher', 'cipher.NewGCM', 'storageAAD', 'AADHash', 'purposeKey', 'encrypted storage authentication failed']:
    if anchor not in crypto:
        raise SystemExit('storage encryption anchor missing: '+anchor)
PY
pass 'Argon2id credentials and AES-256-GCM AAD-bound operational storage present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import json, sys
root=Path(sys.argv[1])
ledger=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('evidence_ledger*.go')) if not p.name.endswith('_test.go'))
for anchor in [
    'ed25519.Sign', 'ed25519.Verify', '"evidence-record"', '"evidence-head"',
    'evidence checkpoint does not match verified ledger head',
    'evidence ledger size changed outside the trusted writer',
    'file.Sync()', 'atomicWriteFile',
]:
    if anchor not in ledger:
        raise SystemExit('Evidence Ledger v2 anchor missing: '+anchor)
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for anchor in [
    'GET /api/v1/evidence', 'GET /api/v1/evidence/verify',
    'operator.mutation.intent', 'mandatory evidence commit failed',
    'POST /api/v1/fim/scan', 'POST /api/v1/fim/baseline',
]:
    if anchor not in server:
        raise SystemExit('mandatory mutation evidence gate missing: '+anchor)
fim=(root/'control'/'fim.go').read_text(encoding='utf-8')
for anchor in [
    'policy.maxFiles', 'policy.maxTotalBytes', 'file identity changed while hashing',
    'e.storage.Encrypt(e.baselinePath, fimPurpose, generation, plaintext)',
    'unencrypted baselines are rejected',
]:
    if anchor not in fim:
        raise SystemExit('hardened FIM anchor missing: '+anchor)
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
if 'xdr.response.intent' not in xdr or 'mandatory evidence commit failed; active response disabled' not in xdr:
    raise SystemExit('XDR response evidence fail-closed gate missing')
contract=json.loads((root/'integration'/'astraeaos'/'contract.json').read_text(encoding='utf-8'))
version=(root/'VERSION').read_text(encoding='utf-8').strip()
if contract.get('schema') != 'vgt-gedefense-astraeaos-integration-v1':
    raise SystemExit('AstraeaOS integration schema mismatch')
if contract.get('gedefense_version') != version or contract.get('security_authority') != 'gedefense':
    raise SystemExit('AstraeaOS integration version/authority drift')
if contract.get('capabilities', {}).get('transaction_engine_v2') != 'implemented':
    raise SystemExit('AstraeaOS contract does not expose Transaction Engine v2')
PY
pass 'Evidence Ledger, hardened FIM, mutation gates and AstraeaOS authority contract present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
transactions=(root/'control'/'transactions.go').read_text(encoding='utf-8')
for anchor in [
    'transactionPreviewHash', 'subtle.ConstantTimeCompare',
    'expectedConfirmation := "APPLY "', 'expectedConfirmation := "REVERSE "',
    'transaction.reconcile.intent', 'transaction.drift',
    'recovery_required', 'e.storage.Encrypt',
]:
    if anchor not in transactions:
        raise SystemExit('Transaction Engine v2 anchor missing: '+anchor)
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for anchor in [
    'POST /api/v1/transactions/preview',
    'POST /api/v1/transactions/{id}/apply',
    'POST /api/v1/transactions/{id}/reverse',
]:
    if anchor not in server:
        raise SystemExit('transaction API route missing: '+anchor)
broker=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
for anchor in [
    'fn sysctl_spec(', 'SYSCTL_GET', 'SYSCTL_SET',
    'sysctl compare-set precondition failed',
    'sysctl post-state verification failed', 'libc::O_NOFOLLOW',
]:
    if anchor not in broker:
        raise SystemExit('typed Rust sysctl broker anchor missing: '+anchor)
unit=(root/'packaging'/'systemd'/'gedefense-core.service').read_text(encoding='utf-8')
if 'ProtectKernelTunables=true' not in unit or '-/proc/sys/kernel/kptr_restrict' not in unit:
    raise SystemExit('sysctl broker sandbox carve-out is missing')
PY
pass 'encrypted Transaction Engine and typed compare-set sysctl broker present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
broker=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
quarantine=''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('quarantine*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'quarantine').rglob('*.rs'))))
for anchor in [
    'QUARANTINE_INSPECT', 'QUARANTINE_APPLY', 'QUARANTINE_VERIFY',
    'QUARANTINE_RESTORE', 'HARDENING_GET', 'HARDENING_SET',
    'RENAME_EXCHANGE',
]:
    if anchor not in broker:
        raise SystemExit('privileged broker capability missing: '+anchor)
for anchor in [
    'Aes256Gcm', 'CHUNK_BYTES', 'openat2', 'RENAME_NOREPLACE',
    'identity.sha256', 'key.fill(0)', 'self.storage_key.fill(0)',
]:
    if anchor not in quarantine:
        raise SystemExit('encrypted quarantine invariant missing: '+anchor)
cases=(root/'control'/'cases.go').read_text(encoding='utf-8')
for anchor in [
    'caseMaxRecords', 'caseFingerprint', 'EvidenceRecord',
    'unencrypted case history refused', 'case history integrity unavailable',
]:
    if anchor not in cases:
        raise SystemExit('case engine invariant missing: '+anchor)
cells=(root/'control'/'cells.go').read_text(encoding='utf-8')
for anchor in [
    'VGTGC1', 'SO_PEERCRED', 'cellClockWindow', 'constantTimeBytesEqual',
    'CgroupID',
]:
    if anchor not in cells:
        raise SystemExit('Gaia Cells adapter invariant missing: '+anchor)
PY
pass 'encrypted quarantine, case engine, persistent hardening and Gaia Cells v1 adapter present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
malware=''.join(p.read_text(encoding='utf-8') for p in sorted(list((root/'rust'/'gedefense-core'/'src').glob('malware*.rs')) + list((root/'rust'/'gedefense-core'/'src'/'malware').rglob('*.rs'))))
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
control=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
web=(root/'control'/'web'/'index.html').read_text(encoding='utf-8')
app=(root/'control'/'web'/'app.js').read_text(encoding='utf-8') + ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control'/'web'/'js').glob('*.js')) if not p.name.endswith('_test.go'))
unit=(root/'packaging'/'systemd'/'gedefense-core.service').read_text(encoding='utf-8')
for anchor in [
    'fanotify_init', 'FAN_OPEN_EXEC_PERM', 'user_quarantine_path',
    'RESOLVE_NO_SYMLINKS', 'archive-expansion-boundary', 'conflicting-file-signatures',
    'metadata.uid() != uid',
]:
    if anchor not in malware:
        raise SystemExit('malware/on-access invariant missing: '+anchor)
for anchor in ['--scan-socket=/run/gedefense-scan/scan.sock', 'fanotify_init fanotify_mark', 'RuntimeDirectoryMode=0750']:
    if anchor not in unit:
        raise SystemExit('malware service sandbox invariant missing: '+anchor)
if 'RuntimeDirectoryMode=0755' in unit:
    raise SystemExit('privileged core runtime directory became publicly traversable')
for anchor in ['UserMalwareScan', '/run/gedefense-scan/scan.sock', 'parseMalwareScanResult', 'parseCoreMalwareEvents', 'MALWARE_EVENTS']:
    if anchor not in control:
        raise SystemExit('typed user malware IPC invariant missing: '+anchor)
for anchor in ['recordMalwareEvent', 'recordManualMalwareFinding', 'MALWARE.EVENT_QUEUE_OVERFLOW', 'deny-exec']:
    if anchor not in xdr:
        raise SystemExit('malware XDR correlation invariant missing: '+anchor)
if 'POST /api/v1/malware/scan' not in server or 'MALWARE_SCAN' not in core or 'MALWARE_EVENTS' not in core:
    raise SystemExit('authenticated malware scan/event API/core path missing')
for anchor in ['ON-ACCESS MALWARE DEFENSE', 'malwareScanForm', 'malwareProtectionHealth']:
    if anchor not in web:
        raise SystemExit('malware security-center dashboard missing: '+anchor)
for anchor in ['scanMalware', 'renderMalwareProtection', 'renderMalwareResult']:
    if anchor not in app:
        raise SystemExit('malware security-center controller missing: '+anchor)
PY
pass 'fanotify on-access guard, peer-bound quarantine scan and content classification present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
installer=(root/'scripts'/'oneclick-installer-header.sh').read_text(encoding='utf-8')
tmpfiles=(root/'packaging'/'tmpfiles'/'vgt-gedefense.conf').read_text(encoding='utf-8')
core_unit=(root/'packaging'/'systemd'/'gedefense-core.service').read_text(encoding='utf-8')
for anchor in (
    'install -d -o gedefense -g gedefense -m 0710 "$STATE"',
    "'gedefense:gedefense:710'",
    'install -d -o root -g gedefense -m 0700 "$QUARANTINE_DIR" "$QUARANTINE_OBJECT_DIR"',
):
    if anchor not in installer:
        raise SystemExit('quarantine DAC bootstrap invariant missing: '+anchor)
if 'd /var/lib/vgt/gedefense 1770 root gedefense -' not in tmpfiles:
    raise SystemExit('tmpfiles root-owned sticky state boundary invariant missing')
if 'User=root' not in core_unit or 'Group=gedefense' not in core_unit:
    raise SystemExit('core quarantine traversal identity invariant missing')
if 'CAP_DAC_OVERRIDE' in core_unit or 'CAP_DAC_READ_SEARCH' in core_unit:
    raise SystemExit('core must not regain broad DAC bypass capabilities')
PY
pass 'quarantine vault traversal works without broad DAC bypass capabilities'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
for anchor in [
    "script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
    'Origin-Agent-Cluster', 'X-Permitted-Cross-Domain-Policies', 'i18n.js',
]:
    if anchor not in server:
        raise SystemExit('control-plane browser hardening anchor missing: '+anchor)
login=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'gateway').glob('*.go')) if not p.name.endswith('_test.go'))
for anchor in ["default-src 'none'", "form-action 'self'", "frame-ancestors 'none'", "style-src 'nonce-"]:
    if anchor not in login:
        raise SystemExit('login CSP anchor missing: '+anchor)
PY
pass 'strict dashboard and login Content Security Policies present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
installer=(root/'scripts'/'oneclick-installer-header.sh').read_text(encoding='utf-8')
for anchor in [
    'storage-master.key', '--hash-password-stdin', 'libargon2.so.1',
    'root:gedefense mode=640 bytes=32', 'ensure_storage_key',
    'journalctl -u gedefense-control.service -n 160',
]:
    if anchor not in installer:
        raise SystemExit('installer security anchor missing: '+anchor)
for leaked_default in [
    'Domain [$default_host]', 'Dashboard: https://%s:%s',
    'Dashboard setzen) [$existing_allow]',
]:
    if leaked_default in installer:
        raise SystemExit('installer exposes a host/CIDR value in interactive output: '+leaked_default)
PY
pass 'installer provisions guarded secrets, hides host/CIDR defaults and captures activation diagnostics'

