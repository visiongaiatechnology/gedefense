#!/usr/bin/env bash
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fail(){ printf 'SECURITY AUDIT FAIL: %s\n' "$*" >&2; exit 1; }
pass(){ printf '  PASS  %s\n' "$*"; }

for cmd in python3 grep find; do command -v "$cmd" >/dev/null 2>&1 || fail "missing tool: $cmd"; done
cd "$ROOT"

echo 'VGT GeDefense Beta 5 static security regression audit'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
files=list((root/'control'/'web').glob('*.js'))+list((root/'control'/'web').glob('*.html'))
forbidden={
    'innerHTML': re.compile(r'\binnerHTML\b'),
    'outerHTML': re.compile(r'\bouterHTML\b'),
    'insertAdjacentHTML': re.compile(r'\binsertAdjacentHTML\b'),
    'document.write': re.compile(r'\bdocument\s*\.\s*write\s*\('),
    'eval': re.compile(r'(?<![\w.])eval\s*\('),
    'Function constructor': re.compile(r'\bnew\s+Function\s*\('),
    'javascript URL': re.compile(r'javascript\s*:', re.I),
    'srcdoc': re.compile(r'\bsrcdoc\s*=', re.I),
    'inline event handler': re.compile(r'\son[a-z]{3,}\s*=', re.I),
}
findings=[]
for path in files:
    text=path.read_text(encoding='utf-8')
    for label, pattern in forbidden.items():
        for match in pattern.finditer(text):
            line=text.count('\n',0,match.start())+1
            findings.append(f'{path.relative_to(root)}:{line}: {label}')
if findings:
    raise SystemExit('unsafe DOM/HTML sinks found:\n'+'\n'.join(findings))
PY
pass 'no unsafe DOM HTML sinks, eval, javascript URLs or inline handlers'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
i18n=(root/'control'/'web'/'i18n.js').read_text(encoding='utf-8')
used=set()
for rel in ['control/web/index.html','control/web/app.js','control/web/render.js','control/web/api.js','control/web/charts.js']:
    text=(root/rel).read_text(encoding='utf-8')
    used.update(re.findall(r'data-i18n(?:-placeholder|-aria|-title)?=["\']([^"\']+)',text))
    used.update(re.findall(r"\bt\(\s*['\"]([^'\"]+)['\"]",text))
for language in ('en','ru'):
    blocks='\n'.join(re.findall(rf'Object\.assign\(messages\.{language}, \{{(.*?)\n\}}\);',i18n,re.S))
    overrides=set(re.findall(r"['\"]([a-zA-Z0-9_.-]+)['\"]\s*:",blocks))
    missing=sorted(used-overrides)
    if missing:
        raise SystemExit(f'{language} translation coverage missing: '+', '.join(missing))
html=(root/'control'/'web'/'index.html').read_text(encoding='utf-8')
for value in [
    'GeDefense', 'VisionGaiaTechnology', '3.0.0-beta.1', 'paypal.me/dergoldenelotus',
    'bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm', '0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85',
]:
    if value not in html:
        raise SystemExit('dashboard branding/support anchor missing: '+value)
PY
pass 'German, English and Russian translation coverage plus branding/support anchors'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
api=(Path(sys.argv[1])/'control'/'web'/'api.js').read_text(encoding='utf-8')
if 'sessionStorage' in api or 'localStorage' in api:
    raise SystemExit('operator bearer token must not be persisted in browser storage')
if "let volatileToken = ''" not in api:
    raise SystemExit('volatile operator token storage anchor missing')
PY
pass 'manual operator bearer remains volatile and is never persisted by the browser UI'

if grep -RInE --include='*.go' '(^|[[:space:]\"])(os/exec|exec\.Command|syscall\.Exec)([[:space:]\"]|$)' control gateway; then
  fail 'runtime command execution primitive found in network-facing Go services'
fi
if grep -RInE --include='*.rs' '(std::process::Command|Command::new|libc::exec[a-z_]*|libc::system|/bin/(ba)?sh|[\"'"'"'`]bash[\"'"'"'`]|[\"'"'"'`]sh[\"'"'"'`][[:space:]]+-c)' \
  rust/gedefense-common rust/gedefense-core rust/gedefense-ebpf; then
  fail 'runtime command/shell execution primitive found in Rust core or eBPF source'
fi
pass 'no shell/command execution primitives in Go control/gateway or Rust core/eBPF'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
required={
    root/'control'/'security_fuzz_test.go': [
        'FuzzCoreResponseParser', 'FuzzPolicyDocumentParser', 'FuzzEncryptedEnvelopeParser',
    ],
    root/'control'/'xdr_linux_fuzz_test.go': ['FuzzProcStatParser'],
    root/'rust'/'gedefense-common'/'src'/'bin'/'xdp_packet_fuzz.rs': ['parse_network_header'],
}
for path, anchors in required.items():
    if not path.is_file():
        raise SystemExit('security fuzz target missing: '+str(path.relative_to(root)))
    text=path.read_text(encoding='utf-8')
    missing=[anchor for anchor in anchors if anchor not in text]
    if missing:
        raise SystemExit(f'{path.relative_to(root)} missing fuzz anchors: '+', '.join(missing))
lock=root/'rust'/'Cargo.lock'
if not lock.is_file() or 'name = "aya"' not in lock.read_text(encoding='utf-8'):
    raise SystemExit('committed Rust Cargo.lock missing or incomplete')
for rel in ['Makefile','.github/workflows/ci.yml','scripts/oneclick-installer-header.sh']:
    if '--locked' not in (root/rel).read_text(encoding='utf-8'):
        raise SystemExit('Rust locked-resolution gate missing: '+rel)
PY
pass 'fuzz targets and locked Rust dependency resolution are release-gated'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys
root=Path(sys.argv[1])
release=(root/'control'/'release.go').read_text(encoding='utf-8')
core_client=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
core=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
settings=(root/'control'/'runtime_settings.go').read_text(encoding='utf-8')
rules=(root/'control'/'xdr_rules.go').read_text(encoding='utf-8')
required={
    'release controller': [
        'FailSafeVerified', 'KernelPolicyState', 'ClearBlocklist() error',
        'VerifyBlocklistEmpty() error', 'authoritative kernel blocklist clear failed',
    ],
    'authenticated core client': [
        'maxCoreResponseBytes', 'CLEAR_BLOCKLIST', 'VERIFY_EMPTY',
        'hmac.Equal', 'io.LimitReader',
    ],
    'privileged core': [
        'blocked: HashSet<Target>', 'fn clear_blocklist', '["CLEAR_BLOCKLIST"]',
        '["VERIFY_EMPTY"] if core.blocked.is_empty()',
    ],
    'runtime settings': [
        'EnabledRuleModules', 'CustomRules', 'regexp.Compile', 'len(settings.CustomRules) > 64',
    ],
    'XDR rules': ['OperatorDefined', 'ResponseScore'],
}
texts={
    'release controller': release,
    'authenticated core client': core_client,
    'privileged core': core,
    'runtime settings': settings,
    'XDR rules': rules,
}
missing=[]
for component, anchors in required.items():
    missing.extend(f'{component}: {anchor}' for anchor in anchors if anchor not in texts[component])
if missing:
    raise SystemExit('verified fail-safe/configurable-rule anchors missing:\n'+'\n'.join(missing))
if re.search(r'(?m)^\s*maxCoreResponseBytes\s*=\s*4096\s*$', core_client) is None:
    raise SystemExit('authenticated core response limit is not exactly 4096 bytes')
if '_ = r.reconcileLocked("observe")' in release or '_ = r.policy.Persist' in release:
    raise SystemExit('release fail-safe still discards reconciliation or policy errors')
PY
pass 'verified authoritative kernel fail-safe and alert-only custom rule boundaries present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
text=(root/'gedefense.toml').read_text(encoding='utf-8')
for line in text.splitlines():
    stripped=line.strip()
    if stripped.startswith('source') or stripped.startswith('url'):
        if 'http://' in stripped.lower():
            raise SystemExit('non-HTTPS threat-feed source in gedefense.toml: '+stripped)
feeds=(root/'control'/'feeds.go').read_text(encoding='utf-8')
required=[
    'Proxy: nil', 'validateFeedSourceURL', 'DialContext', 'IsLoopback()', 'IsPrivate()',
    'IsLinkLocalUnicast()', 'IsLinkLocalMulticast()', 'IsUnspecified()', 'IsMulticast()',
]
missing=[x for x in required if x not in feeds]
if missing:
    raise SystemExit('SSRF hardening anchors missing: '+', '.join(missing))
PY
pass 'HTTPS-only feeds with proxy disabled and dial-time local/private IP rejection'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
gw=(root/'gateway'/'main.go').read_text(encoding='utf-8')
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
if missing:
    raise SystemExit('gateway trust-boundary anchors missing: '+', '.join(missing))
PY
pass 'login/session/CSRF/Host checks and reverse-proxy header scrubbing present'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
gw=(root/'gateway'/'main.go').read_text(encoding='utf-8')
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
ledger=(root/'control'/'evidence_ledger.go').read_text(encoding='utf-8')
for anchor in [
    'ed25519.Sign', 'ed25519.Verify', '"evidence-record"', '"evidence-head"',
    'evidence checkpoint does not match verified ledger head',
    'evidence ledger size changed outside the trusted writer',
    'file.Sync()', 'atomicWriteFile',
]:
    if anchor not in ledger:
        raise SystemExit('Evidence Ledger v2 anchor missing: '+anchor)
server=(root/'control'/'server.go').read_text(encoding='utf-8')
for anchor in [
    'GET /api/v1/evidence', 'GET /api/v1/evidence/verify',
    'operator.mutation.intent', 'mandatory evidence commit failed',
    'POST /api/v1/fim/scan', 'POST /api/v1/fim/baseline',
]:
    if anchor not in server:
        raise SystemExit('mandatory mutation evidence gate missing: '+anchor)
fim=(root/'control'/'fim.go').read_text(encoding='utf-8')
for anchor in [
    'fimMaxFiles       = 8192', 'fimMaxTotalBytes', 'file identity changed while hashing',
    'e.storage.Encrypt(e.baselinePath, fimPurpose, generation, plaintext)',
    'unencrypted FIM baseline is rejected',
]:
    if anchor not in fim:
        raise SystemExit('hardened FIM anchor missing: '+anchor)
xdr=(root/'control'/'xdr.go').read_text(encoding='utf-8')
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
server=(root/'control'/'server.go').read_text(encoding='utf-8')
for anchor in [
    'POST /api/v1/transactions/preview',
    'POST /api/v1/transactions/{id}/apply',
    'POST /api/v1/transactions/{id}/reverse',
]:
    if anchor not in server:
        raise SystemExit('transaction API route missing: '+anchor)
broker=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
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
broker=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
quarantine=(root/'rust'/'gedefense-core'/'src'/'quarantine.rs').read_text(encoding='utf-8')
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
    'unencrypted case history is rejected', 'case history integrity unavailable',
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
malware=(root/'rust'/'gedefense-core'/'src'/'malware.rs').read_text(encoding='utf-8')
core=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
control=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
xdr=(root/'control'/'xdr.go').read_text(encoding='utf-8')
server=(root/'control'/'server.go').read_text(encoding='utf-8')
web=(root/'control'/'web'/'index.html').read_text(encoding='utf-8')
app=(root/'control'/'web'/'app.js').read_text(encoding='utf-8')
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
server=(root/'control'/'server.go').read_text(encoding='utf-8')
for anchor in [
    "script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
    'Origin-Agent-Cluster', 'X-Permitted-Cross-Domain-Policies', 'i18n.js',
]:
    if anchor not in server:
        raise SystemExit('control-plane browser hardening anchor missing: '+anchor)
login=(root/'gateway'/'main.go').read_text(encoding='utf-8')
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

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
ebpf=(root/'rust'/'gedefense-ebpf'/'src'/'main.rs').read_text(encoding='utf-8')
core=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
xdr=(root/'control'/'xdr.go').read_text(encoding='utf-8')
ipc=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
packages=(root/'control'/'package_integrity_linux.go').read_text(encoding='utf-8')
server=(root/'control'/'server.go').read_text(encoding='utf-8')
required={
    'eBPF exec sensor': ['#[tracepoint]', 'gedefense_exec', 'EXEC_EVENTS.output::<ExecEvent>'],
    'eBPF egress enforcement': [
        '#[cgroup_skb(egress)]', 'gedefense_egress',
        'EGRESS_EVENTS.output::<EgressDropEvent>', 'BLOCKLIST_V4', 'BLOCKLIST_V6',
    ],
    'eBPF GaiaCells LSM enforcement': [
        '#[lsm(hook = "socket_create")]', 'gedefense_cell_socket_create',
        'CELL_LSM_POLICIES', 'CELL_LSM_EVENTS.output::<CellLsmDenyEvent>', 'Ok(-EPERM)',
    ],
    'privileged event broker': ['TracePoint', 'sched_process_exec', 'RingBuf<MapData>', '["EXEC_EVENTS"]'],
    'privileged egress broker': [
        'CgroupSkbAttachType::Egress', 'CgroupAttachMode::AllowMultiple',
        '["EGRESS_EVENTS"]', 'take_egress_events',
    ],
    'privileged GaiaCells LSM broker': [
        'Btf::from_sys_fs()', 'program.load("socket_create", &btf)',
        '["CELL_POLICY_EPOCH"]', '["CELL_POLICY_SET", cgroup_id, flags]',
        '["CELL_POLICY_DEL", cgroup_id]', '["CELL_LSM_EVENTS"]',
        'flag("require-bpf-lsm")',
    ],
    'authenticated event client': ['func (c *CoreClient) ExecEvents()', 'parseCoreExecEvents'],
    'authenticated egress client': [
        'func (c *CoreClient) EgressEvents()', 'parseCoreEgressDropEvents',
    ],
    'authenticated GaiaCells LSM client': [
        'func (c *CoreClient) CellPolicyEpoch()',
        'func (c *CoreClient) CellPolicySet(',
        'func (c *CoreClient) CellPolicyDelete(',
        'func (c *CoreClient) CellLSMEvents()',
        'parseCoreCellLSMDenyEvents',
    ],
    'XDR event pipeline': ['ebpf-exec+procfs-fallback', 'readExecProcess', 'xdr.exec_sensor_fallback'],
    'XDR egress pipeline': [
        'cgroup-egress+procfs-bounded-fallback', 'xdr.egress_blocked',
        'xdr.egress_sensor_fallback',
    ],
    'XDR GaiaCells LSM pipeline': [
        'syncCellLSMPolicies', 'recordCellLSMDeny',
        'xdr.cell_lsm_policy_unavailable', 'xdr.cell_lsm_event_unavailable',
        'CELL.LSM_SOCKET_DENY',
    ],
    'package integrity scanner': [
        'gzip.NewReader', 'sha256.New', 'syscall.O_NOFOLLOW',
        'packageIntegrityMaxTotalBytes', 'package path parent escaped jail',
    ],
    'package integrity API': [
        'GET /api/v1/package-integrity', 'POST /api/v1/package-integrity/scan',
        'packageIntegrityPostureCheck',
    ],
}
texts={
    'eBPF exec sensor': ebpf,
    'eBPF egress enforcement': ebpf,
    'eBPF GaiaCells LSM enforcement': ebpf,
    'privileged event broker': core,
    'privileged egress broker': core,
    'privileged GaiaCells LSM broker': core,
    'authenticated event client': ipc,
    'authenticated egress client': ipc,
    'authenticated GaiaCells LSM client': ipc,
    'XDR event pipeline': xdr,
    'XDR egress pipeline': xdr,
    'XDR GaiaCells LSM pipeline': xdr,
    'package integrity scanner': packages,
    'package integrity API': server,
}
missing=[]
for component, anchors in required.items():
    missing.extend(f'{component}: {anchor}' for anchor in anchors if anchor not in texts[component])
if missing:
    raise SystemExit('local EDR/package-integrity anchors missing:\n'+'\n'.join(missing))
PY
pass 'kernel exec EDR, GaiaCells BPF-LSM and signed-package integrity controls present'

if [[ -f "$ROOT/dist/gedefense-ebpf" ]]; then
  ebpf_sections=$(llvm-objdump -h "$ROOT/dist/gedefense-ebpf")
  ebpf_symbols=$(llvm-objdump -t "$ROOT/dist/gedefense-ebpf")
  grep -Eq '[[:space:]]lsm/socket_create[[:space:]]' <<<"$ebpf_sections" ||
    fail 'built eBPF object has no socket_create LSM section'
  for symbol in gedefense_cell_socket_create CELL_LSM_POLICIES CELL_LSM_EVENTS; do
    grep -Fq -- "$symbol" <<<"$ebpf_symbols" ||
      fail "built eBPF object is missing ${symbol}"
  done
  pass 'built eBPF object contains the GaiaCells socket LSM and policy maps'
fi

printf 'SECURITY AUDIT PASS\n'
