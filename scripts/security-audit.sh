#!/usr/bin/env bash
set -Eeuo pipefail
umask 0022

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
fail(){ printf 'SECURITY AUDIT FAIL: %s\n' "$*" >&2; exit 1; }
pass(){ printf '  PASS  %s\n' "$*"; }

for cmd in python3 grep find; do command -v "$cmd" >/dev/null 2>&1 || fail "missing tool: $cmd"; done
cd "$ROOT"

echo 'VGT GeDefense V6 static security regression audit'

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

python3 - "$ROOT" <<'PYI18N'
from pathlib import Path
import json, re, sys
root=Path(sys.argv[1])
i18n=(root/'control'/'web'/'i18n.js').read_text(encoding='utf-8')
marker='export const catalogs = Object.freeze('
end_marker=');\n\nlet activeLanguage'
start=i18n.find(marker)
end=i18n.find(end_marker,start+len(marker))
if start < 0 or end < 0:
    raise SystemExit('i18n catalog structure missing')
try:
    catalogs=json.loads(i18n[start+len(marker):end])
except json.JSONDecodeError as exc:
    raise SystemExit(f'i18n catalog JSON invalid: {exc}')
expected=('de','en','ru','zh-CN')
if tuple(catalogs) != expected:
    raise SystemExit('i18n languages mismatch: '+', '.join(catalogs))
base=set(catalogs['de'])
for language in expected:
    keys=set(catalogs[language])
    if keys != base:
        raise SystemExit(f'{language} catalog parity mismatch')
    for key,value in catalogs[language].items():
        if not isinstance(value,str) or not value.strip():
            raise SystemExit(f'{language} empty translation: {key}')
        expected_tokens=sorted(re.findall(r'\{([a-zA-Z0-9_]+)\}',catalogs['de'][key]))
        actual_tokens=sorted(re.findall(r'\{([a-zA-Z0-9_]+)\}',value))
        if actual_tokens != expected_tokens:
            raise SystemExit(f'{language} placeholder mismatch: {key}')
used=set()
web=root/'control'/'web'
for file in [web/'index.html', *sorted(web.glob('*.js'))]:
    if file.name == 'i18n.js':
        continue
    text=file.read_text(encoding='utf-8')
    used.update(re.findall(r'data-i18n(?:-placeholder|-aria|-title)?=["\']([^"\']+)',text))
    used.update(re.findall(r"\bt\(\s*['\"]([^'\"]+)['\"]",text))
for language in expected:
    missing=sorted(used-set(catalogs[language]))
    if missing:
        raise SystemExit(f'{language} translation coverage missing: '+', '.join(missing))
html=(web/'index.html').read_text(encoding='utf-8')
if '<option value="zh-CN">简体中文</option>' not in html:
    raise SystemExit('Simplified Chinese selector option missing')
current_ver=(root/'VERSION').read_text(encoding='utf-8').strip()
for value in [
    'GeDefense', 'VisionGaiaTechnology', 'paypal.me/dergoldenelotus',
    'bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm', '0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85',
]:
    if value not in html:
        raise SystemExit('dashboard branding/support anchor missing: '+value)
if current_ver in html or 'UI 20261022-V5' in html:
    raise SystemExit('unauthenticated shell must not disclose version/build before login')
if 'id="versionText"' not in html or 'id="uiBuild"' not in html:
    raise SystemExit('placeholder version/build slots missing')
PYI18N
pass 'DE/EN/RU/zh-CN catalog parity, translation coverage, branding/support anchors and no unauth version/build disclosure'

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

if grep -RInE --include='*.go' --exclude='*_test.go' '(^|[[:space:]\"])(os/exec|exec\.Command|syscall\.Exec)([[:space:]\"]|$)' control gateway; then
  fail 'runtime command execution primitive found in network-facing Go services'
fi
# Shell/command sinks are forbidden in the shipped Rust daemons and eBPF code. Test-only
# helpers legitimately spawn child processes to prove non-root behaviour; therefore
# #[cfg(test)] items are stripped before scanning so a test fixture can never mask a
# production execution sink (and cannot satisfy this gate by itself either).
if ! python3 - "$ROOT" <<'PYRUSTEXEC'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
patterns = [
    r'std::process::Command',
    r'\bCommand::new\b',
    r'libc::exec[a-z_]*',
    r'libc::system\b',
    r'/bin/(?:ba)?sh\b',
    r'["\'`]bash["\'`]',
    r'["\'`]sh["\'`]\s+-c',
]
marker = re.compile(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]')
# A module file may declare itself test-only with the inner attribute
# `#![cfg(test)]` (e.g. an ignored real-kernel smoke harness). The compiler
# excludes such a file from every production build, so it is stripped as a
# whole. This can never mask a production execution sink and cannot satisfy the
# gate by itself (the gate only forbids patterns).
file_marker = re.compile(r'(?m)^\s*#!\[\s*cfg\s*\(\s*test\s*\)\s*\]')


def strip_cfg_test(source):
    """Drop every '#[cfg(test)]' item, including nested blocks, before scanning."""
    out = source
    while True:
        match = marker.search(out)
        if not match:
            return out
        start = match.start()
        cursor = match.end()
        brace = out.find('{', cursor)
        semicolon = out.find(';', cursor)
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            out = out[:start] + (out[semicolon + 1:] if semicolon >= 0 else '')
            continue
        depth = 0
        index = brace
        while index < len(out):
            char = out[index]
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    break
            index += 1
        out = out[:start] + out[index + 1:]


hits = []
for base in ('rust/gedefense-common', 'rust/gedefense-core', 'rust/gedefense-ebpf'):
    for path in sorted((root / base).rglob('*.rs')):
        try:
            source = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        production = '' if file_marker.match(source) else strip_cfg_test(source)
        for number, line in enumerate(production.splitlines(), 1):
            if any(re.search(pattern, line) for pattern in patterns):
                hits.append(f'{path.relative_to(root)}:{number}: {line.strip()[:160]}')
if hits:
    print('\n'.join(hits))
    raise SystemExit(1)
PYRUSTEXEC
then
  fail 'runtime command/shell execution primitive found in Rust core or eBPF source'
fi
pass 'no shell/command execution primitives in Go control/gateway or Rust core/eBPF'

python3 - "$ROOT" <<'PYL7'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
control_mod=(root/'control'/'go.mod').read_text(encoding='utf-8')
for directive in ('require ', 'replace ', 'exclude ', 'retract ', 'tool '):
    if re.search(rf'(?m)^\s*{re.escape(directive)}', control_mod):
        raise SystemExit('control-plane dependency directive introduced: '+directive.strip())

l7_sources=[p for p in (root/'control').glob('l7*.go') if not p.name.endswith('_test.go')]
if not l7_sources:
    raise SystemExit('native L7 source set missing')
third_party=[]
for path in l7_sources:
    text=path.read_text(encoding='utf-8')
    if re.search(r'\bpanic\s*\(', text) or 'regexp.MustCompile' in text or 'log.Fatal' in text:
        raise SystemExit('panic/fatal static initializer found in '+str(path.relative_to(root)))
    imports=[]
    import_block=re.search(r'(?ms)^import\s*\((.*?)\)', text)
    if import_block:
        imports += re.findall(r'"([^"]+)"', import_block.group(1))
    imports += re.findall(r'(?m)^import\s+"([^"]+)"', text)
    for imp in imports:
        first=imp.split('/',1)[0]
        if '.' in first:
            third_party.append(f'{path.relative_to(root)}: {imp}')
if third_party:
    raise SystemExit('third-party import in native L7 plane:\n'+'\n'.join(third_party))

integration=root/'integration'/'nginx'
if not integration.is_dir():
    raise SystemExit('native nginx integration directory missing')
for path in integration.rglob('*'):
    if path.is_file() and path.suffix.lower() in {'.js','.mjs','.cjs','.lua','.wasm'}:
        raise SystemExit('scripting/runtime artifact present in nginx integration: '+str(path.relative_to(root)))
conf=(integration/'gedefense-l7.conf.example').read_text(encoding='utf-8')
for directive in ('js_', 'lua_', 'perl_'):
    if directive in conf:
        raise SystemExit('non-native nginx scripting directive present: '+directive)

required={
    root/'control'/'l7_engine.go': ['admissionSlots', 'inspectionSlots', 'context.Context', 'validateL7EngineConfig'],
    root/'control'/'l7_normalize.go': ['ErrL7ResourceLimit', 'gzip.NewReader', 'zlib.NewReader'],
    root/'control'/'l7_candidates.go': ['CandidateBudgetExceeded', 'isL7JSONMediaType', 'isL7XMLMediaType', 'l7FormEntryCount'],
    root/'control'/'l7_edge.go': ['Proxy: nil', 'X-Gedefense-Client-Ip', 'l7PeerCredentialsFromConn'],
    root/'control'/'config.go': ['ip == nil || !ip.IsLoopback()', 'u.Scheme != "http"', 'u.Scheme == "unix"'],
    root/'control'/'xdr_l7.go': ['AlertOnly: true', 'ResponseScore: 0'],
    root/'control'/'xdr_rules.go': ['!m.OperatorDefined && !m.AlertOnly'],
}
for path, anchors in required.items():
    text=path.read_text(encoding='utf-8')
    missing=[x for x in anchors if x not in text]
    if missing:
        raise SystemExit(f'{path.relative_to(root)} missing L7 hardening anchors: '+', '.join(missing))

arch=(root/'packaging'/'arch'/'PKGBUILD').read_text(encoding='utf-8')
for token in ('.js"', '.lua"', '.wasm"'):
    if token in arch and 'integration/nginx/' in arch:
        raise SystemExit('Arch package references a scripting artifact for the native L7 integration')

installer=(root/'scripts'/'oneclick-installer-header.sh').read_text(encoding='utf-8')
for anchor in (
    'groupadd --system gedefense-l7',
    'install -d -o gedefense -g gedefense-l7 -m 0750 "$L7_RUNTIME_DIR"',
    'systemd-tmpfiles --create "$L7_TMPFILES_CONFIG"',
):
    if anchor not in installer:
        raise SystemExit('one-click L7 runtime provisioning invariant missing: '+anchor)
PYL7
pass 'native L7 plane is stdlib-only, panic-free, runtime-bounded and dependency-free at the integration boundary'

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
required={
    root/'control'/'security_fuzz_test.go': [
        'FuzzCoreResponseParser', 'FuzzPolicyDocumentParser', 'FuzzEncryptedEnvelopeParser',
    ],
    root/'control'/'xdr_linux_fuzz_test.go': ['FuzzProcStatParser'],
    root/'control'/'l7_fuzz_test.go': ['FuzzL7NormalizerNeverPanics', 'FuzzL7ResponseInspectionPreservesWireBytes', 'FuzzL7InlineUpstreamParserNeverEscapesLocalHost'],
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
if re.search(r'(?m)^\s*maxCoreResponseBytes\s*=\s*64\s*<<\s*10\s*$', core_client) is None:
    raise SystemExit('authenticated core response limit is not the V6.2 64 KiB bound')
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
ledger=(root/'control'/'evidence_ledger.go').read_text(encoding='utf-8')
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
malware=(root/'rust'/'gedefense-core'/'src'/'malware.rs').read_text(encoding='utf-8')
core=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
control=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
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

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
ebpf=(root/'rust'/'gedefense-ebpf'/'src'/'main.rs').read_text(encoding='utf-8')
core=(root/'rust'/'gedefense-core'/'src'/'main.rs').read_text(encoding='utf-8')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
ipc=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
packages=(root/'control'/'package_integrity_linux.go').read_text(encoding='utf-8')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
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
        'CgroupSkbAttachType::Egress', 'CgroupAttachMode', 'AllowMultiple',
        '["EGRESS_EVENTS"]', 'take_egress_events',
    ],
    'privileged GaiaCells LSM broker': [
        'Btf::from_sys_fs()', 'attach_cell_socket_lsm',
        'program.load("socket_create", btf)?',
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

# POINT 3 (P3-T6, docs/POINT3-EGRESS-BEACON.md): mandatory anchors for the
# per-cgroup egress enforcement and the beacon/exfiltration detector. Every
# anchor pins a definition, a decision or a default - never a bare comment or a
# test fixture - so removing a control cannot be compensated elsewhere.
python3 - "$ROOT" <<'PYSTYX'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

common_lib=read('rust/gedefense-common/src/lib.rs')
common_flow=read('rust/gedefense-common/src/styx_flow.rs')
ebpf=read('rust/gedefense-ebpf/src/main.rs')
core=read('rust/gedefense-core/src/main.rs')
core_flow=read('rust/gedefense-core/src/styx_flow.rs')
ipc=read('control/coreipc.go')
beacon=read('control/styx_beacon.go')
# The Go StyX policy/sync anchors live across the VGT line-limit split
# (styx_settings.go, styx_policy_plan.go, styx_syncer.go,
# styx_syncer_status.go, styx_policy.go). Concatenate every production
# control/styx_*.go file so the anchors stay pinned to the whole subsystem and a
# future split into even more files cannot silently satisfy the gate with an
# empty file set.
styx_sources=sorted((root/'control').glob('styx_*.go'))
styx_sources=[path for path in styx_sources if not path.name.endswith('_test.go')]
if 'styx_policy.go' not in {path.name for path in styx_sources}:
    missing.append('go-policy: control/styx_policy.go missing from the StyX source set')
policy='\n'.join(path.read_text(encoding='utf-8') for path in styx_sources)
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
runtime=read('control/runtime_settings.go')
schema=read('control/fabric_schema.go')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))

# ABI-1: one shared, exactly 104-byte FlowEvent contract with a rejecting decoder.
need('rust-common', common_lib, 'mod styx_flow;')
need('rust-common', common_lib, 'pub use styx_flow::*;')
need('rust-common', common_flow, 'pub const STYX_FLOW_EVENT_WIRE_BYTES: usize = 104;')
need('rust-common', common_flow, '#[repr(C)]')
need('rust-common', common_flow, 'pub struct FlowEvent {')
need('rust-common', common_flow, 'pub fn decode_styx_flow_event(bytes: &[u8]) -> Option<FlowEvent> {')
need('rust-common', common_flow, 'if bytes.len() != STYX_FLOW_EVENT_WIRE_BYTES {')
need('rust-common', common_flow, 'verdict > STYX_VERDICT_DEFAULT_DENY')
need('rust-common', common_flow, 'pub const STYX_MODE_OFF: u8 = 0;')
need('rust-common', common_flow, 'pub const STYX_FLAG_LOG_FLOWS: u8 = 1 << 6;')

# ABI-2: the egress hook keeps the legacy verdict/event path and adds the StyX maps.
need('rust-ebpf', ebpf, '#[cgroup_skb(egress)]')
need('rust-ebpf', ebpf, 'pub fn gedefense_egress(ctx: SkBuffContext) -> i32 {')
need('rust-ebpf', ebpf, 'EGRESS_EVENTS.output::<EgressDropEvent>(&event, 0);')
need('rust-ebpf', ebpf, 'static CELL_EGRESS_MODE: HashMap<u64, u8> =')
need('rust-ebpf', ebpf, 'static STYX_GLOBAL: Array<u64> = Array::with_max_entries(1, 0);')
need('rust-ebpf', ebpf, 'static STYX_RESOLVED: LruHashMap<u64, [u8; 16]> =')
need('rust-ebpf', ebpf, 'static FLOW_AGG_V4: LruPerCpuHashMap<[u8; 16], [u8; 40]> =')
need('rust-ebpf', ebpf, 'static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(')
need('rust-ebpf', ebpf, 'FLOW_EVENTS.reserve::<FlowEvent>(0)')
need('rust-ebpf', ebpf, 'entry.submit(0);')
need('rust-ebpf', ebpf, 'let global = match STYX_GLOBAL.get(STYX_GLOBAL_INDEX) {')
need('rust-ebpf', ebpf, 'increment_counter(&FLOW_RING_DROPS);')
need('rust-ebpf', ebpf, 'STYX_VERDICT_METADATA_VETO')
need('rust-ebpf', ebpf, 'STYX_VERDICT_DNS_PIN')
need_match('rust-ebpf', ebpf,
           'default-off shortcut returns the byte-identical 5.2.0 verdict path',
           r'if global_mode == STYX_MODE_OFF && \(global_flags & STYX_FLAG_LOG_FLOWS\) == 0 \{.*?return legacy_inspect_egress\(ctx\);')

# Rust core: validate before one map write, seed the mandatory veto, drain honestly.
need('rust-core', core, 'mod styx_flow;')
need('rust-core', core, 'ebpf.take_map("STYX_GLOBAL").ok_or("STYX_GLOBAL missing")?')
need('rust-core', core, 'ebpf.take_map("FLOW_EVENTS").ok_or("FLOW_EVENTS missing")?')
need('rust-core', core, 'seed_styx_mandatory_veto(&mut styx_block_v4, &mut styx_block_v6)?;')
need('rust-core', core, 'encode_styx_global(styx_epoch as u32, STYX_MODE_OFF, 0)')
need('rust-core', core, 'CgroupAttachMode::AllowOverride')
need('rust-core', core, '["STYX_VERSION"] => core.styx_version(),')
need('rust-core', core, '["STYX_GLOBAL", args @ ..] => core.styx_set_global(args),')
need('rust-core', core, '["STYX_MODE_SET", args @ ..] => core.styx_mode_set(args),')
need('rust-core', core, '["STYX_FLOW_EVENTS"] => core.styx_take_flow_events(),')
need('rust-core', core, '["STYX_FLOW_HEALTH"] => core.styx_flow_health(),')
need('rust-core', core, 'let Some(event) = decode_styx_flow_event(&item) else {')
need('rust-core', core, 'self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);')
need('rust-core', core_flow, 'pub const STYX_GLOBAL_FLAG_LOG_FLOWS: u8 = 1 << 0;')
need('rust-core', core_flow, 'Ok(if flags & STYX_GLOBAL_FLAG_LOG_FLOWS != 0 { STYX_FLAG_LOG_FLOWS } else { 0 })')
need('rust-core', core_flow, 'pub fn encode_styx_global(epoch: u32, mode: u8, flags: u8) -> u64 {')
need('rust-core', core_flow, 'pub fn encode_styx_flow_event_text(event: &FlowEvent) -> Option<String> {')

# Go: capability-gated commands, all-or-nothing parser, beacon detector, syncer.
need('go-ipc', ipc, 'func parseCoreStyxFlowEvents(response string) ([]CoreStyxFlowEvent, uint64, error) {')
need('go-ipc', ipc, '"STYX_VERSION"')
need('go-ipc', ipc, '"STYX_GLOBAL"')
need('go-ipc', ipc, '"STYX_MODE_SET"')
need('go-ipc', ipc, '"STYX_FLOW_EVENTS"')
need('go-ipc', ipc, 'ErrStyxUnavailable')
need_match('go-ipc', ipc, 'batch and payload limits pinned on the control-plane side',
           r'maxStyxFlowEventsPerResponse = 64.*?maxStyxFlowPayloadBytes = 16 << 10')
need('go-beacon', beacon, 'type StyxBeaconEngine struct {')
need('go-beacon', beacon, 'CausalEdge: EdgeEgressAttempted')
need_match('go-beacon', beacon, 'signal 3 can never fire without a DNS capability (no fake)',
           r'if b\.cfg\.DNSObservationAvailable && !aggregate\.lastDNSSeen')
need_match('go-beacon', beacon, 'a degraded sensor suppresses incidents instead of claiming absence',
           r'if b\.degraded \{\s*b\.suppressed\+\+\s*return false')
need_match('go-beacon', beacon, 'a repeated overflow poll series degrades the sensor',
           r'b\.overflowPolls\+\+.*?if b\.overflowPolls >= 3 \{\s*b\.degraded = true')
need('go-policy', policy, 'type styxPolicySyncer struct {')
need('go-policy', policy, 'func (s *styxPolicySyncer) SyncIfDue(ctx context.Context) StyxSyncStatus {')
need('go-policy', policy, 's.core.StyxGlobal(0, 0)')
need('go-policy', policy, 's.core.StyxModeSet(cell.CgroupID, cell.Mode, cell.Flags)')
need_match('go-policy', policy, 'default namespace is disabled and off (no behaviour change)',
           r'func defaultStyxFabricSettings\(\) StyxFabricSettings \{.*?Enabled:\s+false,.*?Mode:\s+StyxModeOff,')
need('go-policy', policy, 'IPv6 cell rules cannot carry port/protocol restrictions in phase 1')
need('go-policy', policy, 'a port rule requires a host CIDR (/32 or /128)')
need('go-policy', policy, 'port range must be a single port or 0-65535')
need('go-xdr', xdr, 'e.styxBeacon = NewStyxBeaconEngine(StyxBeaconConfig{')
need('go-xdr', xdr, 'e.styxPolicy = NewStyxPolicySyncer(core, state, runtime)')
need('go-xdr', xdr, 'events, dropped, flowErr := e.core.StyxFlowEvents()')
need('go-xdr', xdr, 'e.recordStyxFlowBatch(events, dropped, now)')
need('go-xdr', xdr, 'noteVerificationFailure("styx_flow_sensor"')
need('go-settings', runtime, 'Styx *StyxFabricSettings `json:"styx,omitempty"`')
need('go-settings', runtime, 'styX namespace added with enabled=false and mode=off')
need('go-schema', schema, '{module: "styx", group: "Kernel Egress Enforcement", key: "enabled"')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/styx/status", s.auth(s.styxKernelStatus))')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/styx/beacons", s.auth(s.styxBeacons))')

if missing:
    raise SystemExit('Point 3 egress/beacon anchors missing:\n'+'\n'.join(missing))
PYSTYX
pass 'Point 3 per-cgroup egress, flow telemetry, beacon detector, policy syncer and default-off guards present'

# POINT 1 (P1-T6, docs/POINT1-TITAN-EXEC-GATE.md): mandatory anchors for the
# Titan eBPF-LSM exec/library gate. Every anchor pins a definition, a decision, a
# fail-safe default or an honest-status boundary - never a bare comment or a test
# fixture - so removing a control cannot be compensated elsewhere. The ELF gate
# below additionally proves the shipped object carries both LSM hooks and maps.
python3 - "$ROOT" <<'PYP1'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

common_lib=read('rust/gedefense-common/src/lib.rs')
common_titan=read('rust/gedefense-common/src/titan_exec.rs')
ebpf=read('rust/gedefense-ebpf/src/main.rs')
core=read('rust/gedefense-core/src/main.rs')
core_titan=read('rust/gedefense-core/src/titan_exec.rs')
btf=read('rust/gedefense-core/src/btf_offsets.rs')
ipc=read('control/coreipc.go')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
settings=read('control/titan_exec_settings.go')
syncer=read('control/titan_exec_syncer.go')
syncer_status=read('control/titan_exec_syncer_status.go')
events=read('control/titan_exec_events.go')
runtime=read('control/runtime_settings.go')
schema=read('control/fabric_schema.go')
server=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
state=read('control/state.go')

# ABI-1: one shared, exactly 88-byte TitanExecEvent contract with a rejecting decoder.
need('rust-common', common_lib, 'mod titan_exec;')
need('rust-common', common_lib, 'pub use titan_exec::*;')
need('rust-common', common_titan, 'pub const TITAN_EXEC_EVENT_WIRE_BYTES: usize = 88;')
need('rust-common', common_titan, '#[repr(C)]')
need('rust-common', common_titan, 'pub struct TitanExecEvent {')
need('rust-common', common_titan, 'pub fn decode_titan_exec_event(bytes: &[u8]) -> Option<TitanExecEvent> {')
need('rust-common', common_titan, 'if bytes.len() != TITAN_EXEC_EVENT_WIRE_BYTES {')
need('rust-common', common_titan, 'reason > TITAN_EXEC_REASON_MAX')
need('rust-common', common_titan, 'pub fn encode_titan_exec_event(event: &TitanExecEvent) -> [u8; TITAN_EXEC_EVENT_WIRE_BYTES] {')
need('rust-common', common_titan, 'TITAN_EXEC_MODE_STRICT: u8 = 3;')

# ABI-2: both LSM hooks, the five maps/ring and the direct-reservation event write.
need('rust-ebpf', ebpf, '#[lsm(hook = "bprm_check_security")]')
need('rust-ebpf', ebpf, '#[lsm(hook = "mmap_file")]')
need('rust-ebpf', ebpf, 'pub fn gedefense_titan_exec_bprm(ctx: LsmContext) -> i32 {')
need('rust-ebpf', ebpf, 'pub fn gedefense_titan_exec_mmap(ctx: LsmContext) -> i32 {')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_STATE: Array<u64> = Array::with_max_entries(1, 0);')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_OFFSETS: Array<u32> = Array::with_max_entries(TITAN_EXEC_OFFSETS_ENTRIES, 0);')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_MODE: HashMap<u64, u8> =')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_POLICY: HashMap<[u8; 16], [u8; 16]> =')
need('rust-ebpf', ebpf, 'static TITAN_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(TITAN_EXEC_EVENT_RING_BYTES, 0);')
need('rust-ebpf', ebpf, 'TITAN_EXEC_EVENTS.reserve::<TitanExecEvent>(0)')
need('rust-ebpf', ebpf, 'entry.submit(0);')
need('rust-ebpf', ebpf, 'core::ptr::addr_of_mut!((*event).f_flags).write(0);')
need('rust-ebpf', ebpf, 'bpf_probe_read_kernel(address).ok()')
need('rust-ebpf', ebpf, 'increment_counter(&TITAN_EXEC_EVENTS_EMITTED);')
need('rust-ebpf', ebpf, 'increment_counter(&TITAN_EXEC_RING_DROPS);')
# The kernel-side gate must never grow a userland command/shell execution sink.
for forbidden in ('std::process::Command', 'Command::new', 'libc::exec', 'libc::system', '/bin/sh', '/bin/bash'):
    if forbidden in ebpf:
        missing.append(f'rust-ebpf: forbidden execution primitive {forbidden}')

# Rust core: active-LSM probe, validated BTF/arity, both attaches, honest status,
# reject-not-repair IPC arms and the fail-closed enforcement-unavailable path.
need('rust-core', core, 'let bpf_lsm_active = match titan_exec::bpf_lsm_active_from_sys_fs() {')
need('rust-core', core_titan, 'pub fn bpf_lsm_active_from_list(list: &str) -> bool {')
need('rust-core', core_titan, 'pub fn bpf_lsm_active_from_sys_fs() -> Result<bool, String> {')
need('rust-core', core_titan, 'pub const ENFORCEMENT_UNAVAILABLE: &str = "enforcement-unavailable";')
need('rust-core', core, 'fn attach_titan_exec_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {')
need('rust-core', core, '("gedefense_titan_exec_bprm", "bprm_check_security"),')
need('rust-core', core, '("gedefense_titan_exec_mmap", "mmap_file"),')
need('rust-core', core, '["TITAN_EXEC_VERSION"] => core.titan_exec.version(),')
need('rust-core', core, '["TITAN_EXEC_SET_GLOBAL", mode, flags] => core.titan_exec.set_global(mode, flags),')
need('rust-core', core, '["TITAN_EXEC_ALLOW_ADD", path] => core.titan_exec.allow_add(path),')
need('rust-core', core, '["TITAN_EXEC_EVENTS"] => core.titan_exec.take_events(),')
need('rust-core', core, 'let Some(event) = decode_titan_exec_event(&item) else {')
need('rust-core', core, 'self.rejected_events = self.rejected_events.saturating_add(1);')
need('rust-core', core, 'fn enforcement_available(&self) -> bool {')
need('rust-core', core, 'if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {')
need('rust-core', core, 'return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());')
need('rust-core', core, 'ebpf.take_map("TITAN_EXEC_STATE").ok_or("TITAN_EXEC_STATE missing")?')
# P1-T3 moved the hard attach shape out of `btf_offsets::matches_ebpf_slots` into
# the core predicate `titan_exec_offsets_match_ebpf_slots` (main.rs). Read both
# core files so the gate survives such a move, and pin the 1/4 arity condition
# itself: the looser 3..=5 BTF plausibility range is deliberately NOT the attach
# shape (only bprm=1/mmap=4 may ever be attached).
core_btf = core + '\n' + btf
need_match('rust-core', core_btf, 'the eBPF slot/arity predicate exists in a core file',
           r'fn\s+\w*(?:match|matches)_ebpf_slots\w*\s*\([^)]*\)\s*->\s*bool\s*\{')
need_match('rust-core', core_btf, 'the hard attach shape pins bprm arity 1 and mmap arity 4',
           r'bprm_nargs\s*==\s*1[\s\S]{0,200}?mmap_nargs\s*==\s*4')
need('rust-core', core, 'titan_exec_offsets_match_ebpf_slots(&offsets)')
need('rust-core', btf, 'u16::from_le_bytes')
need('rust-core', btf, 'u32::from_le_bytes')
need('rust-core', btf, 'pub const MAX_VMLINUX_BTF_BYTES: usize = 64 * 1024 * 1024;')
need_match('rust-core', core, 'Titan hooks attach only on active BPF LSM, valid offsets and supported hook arity',
           r'if titan_exec\.offsets_valid && titan_slots_supported && bpf_lsm_active \{.*?attach_titan_exec_lsm\(&mut ebpf, btf\)')
# P3 fix in the core: `attached` is only true after an active-LSM attach, and
# `+bpf-lsm-cell`/`cell_lsm=attached` are gated on that boolean.
need('rust-core', core, 'if cell_lsm_attached {')
need_match('rust-core', core, 'the bpf-lsm-cell PING token is gated on the real attach',
           r'if cell_lsm_attached \{\s*mode\.push_str\("\+bpf-lsm-cell"\);')
need('rust-core', core, '"BPF LSM is not active (or its BTF is missing); Gaia Cell host socket reinforcement optional-unavailable, bpf-lsm-cell not claimed"')
need('rust-core', core, 'fn require_cell_lsm(&self) -> Result<(), BoxError> {')

# Go control plane: settings namespace (v14, default off), read-only status/event
# API, strict parsers, capability sentinel and the fail-closed enforcement gate.
need('go-ipc', ipc, 'var ErrTitanExecUnavailable = errors.New("titan-exec capability unavailable")')
need('go-ipc', ipc, 'func (c *CoreClient) TitanExecEvents() (string, error) {')
need('go-ipc', ipc, 'func (c *CoreClient) TitanExecStatus() (TitanExecCoreStatus, error) {')
need('go-ipc', ipc, 'func parseTitanExecCoreStatus(payload string) (TitanExecCoreStatus, error) {')
need('go-events', events, 'func parseCoreTitanExecEvents(payload string) (events []CoreTitanExecEvent, dropped uint64, err error) {')
need('go-settings', settings, 'func defaultTitanExecFabricSettings() TitanExecFabricSettings {')
need_match('go-settings', settings, 'titan_exec defaults are disabled and off',
           r'func defaultTitanExecFabricSettings\(\) TitanExecFabricSettings \{.*?Enabled:\s+false,.*?Mode:\s+TitanExecModeOff,')
# POINT 2 (P2-T3) raised the settings schema to v15 (parser_cells namespace);
# the P1 anchor must follow the current schema version instead of pinning 14,
# otherwise a legitimate v15 upgrade fails the P1 gate. The titan_exec migration
# note below still proves the P1 namespace migration exists in v15.
need_match('go-settings', runtime, 'settings schema version is at least v15 (P2 parser_cells migration)',
           r'const fabricSettingsVersion = (?:1[5-9]|[2-9][0-9])')
need('go-settings', runtime, 'titan_exec namespace added with enabled=false and mode=off')
need('go-schema', schema, '{module: "titan_exec", group: "Kernel Exec Gate", key: "enabled"')
need('go-syncer', syncer, 'type titanExecPolicySyncer struct {')
need('go-syncer', syncer, 'func NewTitanExecPolicySyncer(')
need('go-syncer', syncer_status, 'func titanExecEnforcementUnavailable(plan titanExecPolicyPlan, status TitanExecCoreStatus) (reason, state string, unavailable bool) {')
need('go-syncer', syncer_status, 'if plan.Mode == 0 {')
need('go-syncer', syncer_status, 'BPF-LSM is not active in the running kernel; add bpf to the lsm= kernel command line and reboot before enforcing')
need('go-syncer', syncer_status, 'func (s *titanExecPolicySyncer) finishEnforcementUnavailable(')
need('go-syncer', syncer_status, 'TitanExecSyncStateInactive')
need('go-xdr', xdr, 'func (e *XDREngine) TitanExecPolicyStatus() TitanExecSyncStatus {')
need('go-xdr', xdr, 'e.titanExec = NewTitanExecPolicySyncer(titanExecCore, state, runtime, titanExecPlanDeps{})')
need('go-xdr', xdr, 'func (e *XDREngine) titanExecSensorState() string {')
need('go-xdr', xdr, 'case errors.Is(drainErr, ErrTitanExecUnavailable):')
need_match('go-state', state, 'status snapshot carries the bounded titan_exec field',
           r'TitanExec\s+\*TitanExecStatus')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/titan/exec/status", s.auth(s.titanExecStatus))')
need('go-api', server, 'mux.HandleFunc("GET /api/v1/titan/exec/events", s.auth(s.titanExecEvents))')
# P3 activation fix in the control plane: a configured Cell LSM is reported as
# `cell-lsm-unavailable`, never as a working `bpf-lsm-cell`.
need('go-xdr', xdr, 'mode = "cell-lsm-unavailable+" + mode')
need('go-xdr', xdr, 'mode = "bpf-lsm-cell+" + mode')

if missing:
    raise SystemExit('Point 1 Titan exec-gate anchors missing:\n'+'\n'.join(missing))
PYP1
pass 'Point 1 Titan exec-gate ABI, LSM attach gate, fail-closed status and P3 claim fix present'

# POINT 1 T7-FAIL fix (2026-11-15): modern kernels store inode ctime as split
# `i_ctime_sec`/`i_ctime_nsec`; the core publishes the real nsec width via
# OFFSETS[28] and keeps the legacy timespec64 pair as fallback, while the hook
# reads 4/8 bytes accordingly and saturates the sum (never a fake match).
python3 - "$ROOT" <<'PYP1CTIME'
from pathlib import Path
import sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

ebpf=read('rust/gedefense-ebpf/src/main.rs')
core=read('rust/gedefense-core/src/main.rs')
btf=read('rust/gedefense-core/src/btf_offsets.rs')

need('rust-core', btf, 'pub const OFF_INODE_I_CTIME_NSEC_WIDTH: usize = 28;')
need('rust-core', btf, 'self.field_ref(inode, &["i_ctime_sec"])')
need('rust-core', btf, 'self.field_ref(inode, &["i_ctime", "tv_sec"])')
need('rust-core', core, 'table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH] = offsets.inode_i_ctime_nsec_width;')
need('rust-ebpf', ebpf, 'const TITAN_OFF_INODE_CTIME_NSEC_WIDTH: u32 = 28;')
need('rust-ebpf', ebpf, 'let nsec: u64 = if offsets.ctime_nsec_width == TITAN_CTIME_NSEC_WIDTH_32 {')
need('rust-ebpf', ebpf, 'seconds_ns.saturating_add(nsec)')

if missing:
    raise SystemExit('Point 1 T7 ctime anchors missing:\n'+'\n'.join(missing))
PYP1CTIME
pass 'Point 1 T7 fix (a): split-inode ctime layout, real nsec width and saturating compare present'

# POINT 1 T7-Befund fix (b) + precision (c) (2026-11-15): the kernel task name is
# process-controlled (PR_SET_NAME), so the parser accepts every raw byte sequence
# and only enforces the NUL-padding shape; hostile names must never suppress a
# batch and are sanitised only for output. The inert-policy ban applies to an
# ENABLED namespace whose mode is off; a disabled draft stays allowed.
python3 - "$ROOT" <<'PYP1COMM'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
missing=[]

def read(relative):
    return (root/relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

events=read('control/titan_exec_events.go')
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
settings=read('control/titan_exec_settings.go')

need('go-events', events, 'func decodeTitanExecComm(field string) (string, error) {')
need('go-events', events, 'sanitizeTitanExecComm(decoded[:end])')
need('go-xdr', xdr, 'func sanitizeTitanExecComm(raw []byte) string {')
need_match('go-settings', settings, 'enabled mode=off policies with rules are rejected (drafts stay allowed)',
           r'if in\.Enabled && mode == 0 &&[\s\S]{0,220}?len\(in\.ExecRoots\) > 0')

if missing:
    raise SystemExit('Point 1 T7 comm/inert-policy anchors missing:\n'+'\n'.join(missing))
PYP1COMM
pass 'Point 1 T7 fix (b/c): raw-comm contract and enabled-only inert-policy ban present'

# POINT 2 (docs/POINT2-PARSER-CELLS.md): ephemeral "parser-ephemeral" Gaia cells.
# Additive gate only - every pre-existing Point 1/Point 3 anchor above stays
# unchanged. It pins the privilege split (only the Rust helper spawns/executes),
# the VGTGC2 auth protocol, fail-closed/default-off behaviour and the packaging
# boundary (unit sandbox, tmpfiles, provisioning, installer/release/deployment).
python3 - "$ROOT" <<'PYP2'
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

# --- L1: privileged Rust helper crate (only spawner and only execve sink) ---
workspace = read('rust/Cargo.toml')
helper_cargo = read('rust/gedefense-cell-helper/Cargo.toml')
need('rust-workspace', workspace, '"gedefense-cell-helper",')
need('helper-cargo', helper_cargo, 'name = "gedefense-cell-helper"')
for forbidden_dependency in ('serde', 'toml'):
    if forbidden_dependency in helper_cargo:
        missing.append(f'helper-cargo: forbidden dependency {forbidden_dependency} (offline text contract)')

helper_sources = {}
for source_path in sorted((root / 'rust' / 'gedefense-cell-helper' / 'src').glob('*.rs')):
    helper_sources[source_path.name] = source_path.read_text(encoding='utf-8')
for required in ('main.rs', 'protocol.rs', 'config.rs', 'lifecycle.rs', 'export.rs', 'types.rs', 'sandbox.rs', 'seccomp.rs'):
    if required not in helper_sources:
        missing.append(f'helper-crate: missing source {required}')
sandbox = helper_sources.get('sandbox.rs', '')
seccomp = helper_sources.get('seccomp.rs', '')
protocol = helper_sources.get('protocol.rs', '')
config = helper_sources.get('config.rs', '')
export = helper_sources.get('export.rs', '')
lifecycle = helper_sources.get('lifecycle.rs', '')
types = helper_sources.get('types.rs', '')
main = helper_sources.get('main.rs', '')

# Sandbox contract (spec §4): namespaces, tmpfs/read-only mounts, credential and
# capability drop, no_new_privs and a single pinned execve as the last child step.
for anchor in (
    'libc::CLONE_NEWNS', 'libc::CLONE_NEWPID', 'libc::CLONE_NEWIPC', 'libc::CLONE_NEWUTS', 'libc::CLONE_NEWNET',
    'libc::MS_REC | libc::MS_PRIVATE', 'c"tmpfs"', 'hidepid=2',
    'libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC', 'libc::MS_RDONLY', 'libc::chroot',
    'libc::setgroups(0, std::ptr::null())', 'libc::setresgid', 'libc::setresuid',
    'libc::PR_CAPBSET_DROP', 'PR_CAP_AMBIENT', 'libc::PR_SET_NO_NEW_PRIVS',
    'libc::PR_SET_PDEATHSIG', 'libc::umask(0o077)',
    'libc::execve(plan.binary.as_ptr()', 'display_unavailable',
    'GEDEFENSE_INPUT_FD', 'GEDEFENSE_EXPORT_FD',
):
    need('helper-sandbox', sandbox, anchor)
need_match('helper-sandbox', sandbox, 'X11 display variables are always refused', r'XAUTHORITY')
for reserved in ('HOME', 'USER', 'LOGNAME', 'PATH', 'TMPDIR', 'XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'PIPEWIRE_REMOTE'):
    need('helper-sandbox', sandbox, f'"{reserved}"')

# Seccomp contract (§4.4): arch check, no_new_privs before install, exact deny
# list with EPERM (not ENOSYS) and AF_UNIX-only sockets.
for anchor in (
    'pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;', 'SECCOMP_SET_MODE_FILTER',
    'libc::PR_SET_NO_NEW_PRIVS', 'libc::SYS_seccomp', 'libc::AF_UNIX', 'RET_ERRNO | libc::EPERM as u32',
):
    need('helper-seccomp', seccomp, anchor)
for denied in (
    'ptrace', 'process_vm_readv', 'process_vm_writev', 'bpf', 'perf_event_open', 'userfaultfd',
    'io_uring_setup', 'io_uring_enter', 'io_uring_register', 'mount', 'umount2', 'pivot_root',
    'chroot', 'unshare', 'setns', 'clone', 'clone3', 'fork', 'vfork', 'keyctl', 'add_key',
    'request_key', 'kexec_load', 'init_module', 'finit_module', 'delete_module',
    'open_by_handle_at', 'name_to_handle_at',
):
    need('helper-seccomp', seccomp, f'libc::SYS_{denied}')

# VGTGC2 wire contract (§3): HMAC-SHA256, SO_PEERCRED, bounded timestamp/replay,
# size limits and exactly one SCM_RIGHTS FD.
for anchor in (
    'VGTGC2', 'VGTGC2R', 'fn verify_mac', 'fn parse_request', 'libc::SO_PEERCRED',
    'libc::SCM_RIGHTS', 'REPLAY_CACHE_CAPACITY', 'MAX_REQUEST_BYTES', 'MAX_REQUESTS_PER_CONNECTION',
):
    need('helper-protocol', protocol, anchor)
need_match('helper-protocol', protocol, 'timestamp window is bounded to +-30s', r'abs_diff\(ts\) > TIME_WINDOW_SECS')
need('helper-protocol', protocol, 'pub fn parse_response')
need('helper-protocol', protocol, 'fn encode_line')

# Profile/input/export validation (§4): root-owned 0640 config, O_NOFOLLOW,
# 32-byte key, sha256-pinned binaries, bounded staging, sealed memfd broker.
for anchor in (
    'pub const KEY_FILE_LEN: u64 = 32;', 'pub const MAX_PROFILE_FILE_BYTES: u64 = 256 * 1024;',
    'md.mode() & 0o777 != 0o640', 'libc::O_NOFOLLOW', 'pub fn validate_staging_dirs',
    'pub fn validate_input', 'pub fn validate_export_dir',
):
    need('helper-config', config, anchor)
need_match('helper-config', config, 'parser binaries are sha256-pinned', r'sha256')
need('helper-export', export, 'create_new(true)')
for anchor in ('libc::F_SEAL_WRITE', 'libc::F_SEAL_GROW', 'libc::F_SEAL_SHRINK', 'libc::SYS_memfd_create', 'copy_bounded'):
    need('helper-export', export, anchor)
for anchor in (
    'pub const CGROUP_PREFIX: &str = "parser-";', 'memory.max', 'pids.max', 'cpu.max',
    'cgroup.freeze', 'cgroup.kill', 'sweep_orphans', 'pub const LEDGER_MAX_BYTES',
):
    need('helper-lifecycle', lifecycle, anchor)
for code in (
    'bad-request', 'bad-mac', 'stale', 'replay', 'unknown-command', 'capability-missing',
    'profile-unknown', 'profile-invalid', 'input-invalid', 'input-missing', 'sandbox-unavailable',
    'cell-limit', 'unknown-cell', 'stale-generation', 'export-missing', 'export-overflow',
    'burn-failed', 'internal',
):
    need('helper-types', types, f'"{code}"')
# T5-Fix (P2-T1): capability self-check + non-root cgroup probe. The helper must
# never probe the kernel root cgroup for cgroup.kill (CFTYPE_NOT_ON_ROOT); it
# probes a throwaway child under the CLI cgroup-root and fails closed with clear
# diagnostic codes when the capability or cgroup support is missing.
need('helper-types', types, 'REQUIRED_CAPABILITIES')
need('helper-types', types, '("CAP_CHOWN", 0)')
need('helper-types', types, 'pub fn missing_capabilities')
need('helper-main', main, 'static CGROUP_PROBE_OK')
need('helper-main', main, 'fn probe_cgroup_root')
need('helper-main', main, '"cgroup-root-missing"')
need('helper-main', main, '"cgroup-unavailable"')
need('helper-main', main, 'caps={}/{}')
need('helper-main', main, 'probe_cgroup_root(&cli.cgroup_root)')
need('helper-main', main, 'capability-check-failed missing=')
if 'Path::new("/sys/fs/cgroup/cgroup.kill")' in main:
    missing.append('helper-main: cgroup.kill must be probed in a child of the CLI cgroup-root, not the kernel root cgroup')
need('helper-main', main, 'VGTGC2 listener')

# execve may only exist in sandbox.rs; no helper module other than sandbox.rs may
# contain a shell/command sink (the pre-existing daemon gate above is untouched).
for name, source in helper_sources.items():
    if name == 'sandbox.rs':
        continue
    if 'libc::execve' in source:
        missing.append(f'helper-crate: libc::execve outside sandbox.rs: {name}')
for name, source in helper_sources.items():
    body = re.sub(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', '', source)
    for pattern in (r'std::process::Command', r'\bCommand::new\b', r'libc::system\b', r'["\'`]/bin/(?:ba)?sh\b'):
        if re.search(pattern, body):
            missing.append(f'helper-crate: forbidden execution primitive in {name}: {pattern}')

# --- Go control plane: VGTGC2 client, manager, settings, API, host layers ----
client = read('control/parser_cells_client.go')
manager = read('control/parser_cells_manager.go')
manager_ops = read('control/parser_cells_manager_ops.go')
settings = read('control/parser_cells_settings.go')
kernel = read('control/parser_cells_kernel.go')
api = read('control/parser_cells_api.go')
runtime_settings = read('control/runtime_settings.go')
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
guard = read('control/cell_guard.go')
bootstrap = read('control/config.go')
for anchor in (
    'parserCellFrameTag          = "VGTGC2"', 'parserCellResponseTag       = "VGTGC2R"',
    'parserCellTimestampSkewSecs = 30', 'syscall.SO_PEERCRED', 'syscall.Recvmsg',
    'syscall.ParseUnixRights', 'syscall.CmsgSpace', 'ErrParserCellsRuntimeUnavailable',
    'ErrParserCellsPeer', '"capability-missing"', '"sandbox-unavailable"', '"export-overflow"',
):
    need('go-client', client, anchor)
need_match('go-client', client, 'exactly one export FD is accepted for CELL_EXPORT_READ only',
           r'len\(fds\) == 1 && command != parserCellCommandExportRead')
need('go-client', client, 'parserCellCloseFDs')
for anchor in (
    'type ParserCellManager struct {', 'parserCellKindBurnIntent  = "cells.parser.burn.intent"',
    'state.RecordEvidence', 'Helper: "disabled"', 'capability-missing', 'parserCellStateBurned',
):
    need('go-manager', manager, anchor)
need('go-manager', manager_ops, 'm.evidence(EvidenceRecord{Severity: "high", Kind: kind')
need('go-settings', settings, 'parserCellsClassEphemeral = "parser-ephemeral"')
need_match('go-settings', settings, 'parser_cells defaults to disabled', r'Enabled:\s+false,')
# POINT 5 (P5-T3) raised the schema to v16 (lockdown namespace). This P2 anchor
# must follow the current schema version instead of pinning 15, exactly like the
# P1 anchor above; the parser_cells migration proof below is unchanged.
need_match('go-runtime', runtime_settings, 'settings schema version is at least v16 (POINT 5 lockdown migration)',
           r'const fabricSettingsVersion = (?:1[6-9]|[2-9][0-9])')
need('go-runtime', runtime_settings, 'parser_cells namespace added with enabled=false')
for anchor in (
    'CELL_POLICY_SET(cgroup, DENY_NON_UNIX_SOCKET)', 'StyxModeSet', 'TitanExecScopeSet',
    'parserCellLayerUnavailable + ":bpf-lsm-inactive"', 'parserCellLayerUnavailable + ":styx-disabled"',
):
    need('go-kernel', kernel, anchor)
need('go-api', api, 'request.Confirm != "BURN "+uuid')
need('go-api', api, 'parserCellListLimit')
need('go-api', api, 'Content-Disposition')
need('go-api', api, 'X-Content-Type-Options')
need('go-api', api, '"nosniff"')
for route in (
    'mux.HandleFunc("GET /api/v1/parser-cells/status", s.auth(s.parserCellsStatus))',
    'mux.HandleFunc("GET /api/v1/parser-cells", s.auth(s.parserCellsList))',
    'mux.HandleFunc("POST /api/v1/parser-cells/inputs", s.auth(s.parserCellsInput))',
    'mux.HandleFunc("POST /api/v1/parser-cells/open", s.auth(s.parserCellsOpen))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/burn", s.auth(s.parserCellsBurn))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/freeze", s.auth(s.parserCellsFreeze))',
    'mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/unfreeze", s.auth(s.parserCellsUnfreeze))',
    'mux.HandleFunc("GET /api/v1/parser-cells/{uuid}/export", s.auth(s.parserCellsExport))',
):
    need('go-server', server, route)
need('go-guard', guard, 'manager.BurnForIncident(cgroupID, score, incidentID,')
need('go-guard', guard, 'parser-ephemeral cell burned instead of frozen')
need('go-bootstrap', bootstrap, '"/run/vgt-gedefense/cell-helper.sock"')
need('go-bootstrap', bootstrap, '"/etc/vgt/gedefense/secrets/cell-helper.key"')
need('go-bootstrap', bootstrap, 'PeerUID:              0')
# T5-Fixes (P2-T3): control-owned import sink, adopt-reassert, route-scoped body
# limit and the Wayland capability boundary.
need('go-bootstrap', bootstrap, 'ImportsDir:')
need('go-bootstrap', bootstrap, '"/var/lib/vgt/gedefense/parser-imports"')
need('go-manager-ops', manager_ops, 'm.cfg.ImportsDir')
need('go-manager-ops', manager_ops, 'durable copy is written to the control-owned parser-imports root')
need('go-manager-ops', manager_ops, 'No stored claim without the mandatory evidence record')
need('go-kernel', kernel, 'func (k *parserCellKernel) Reassert(settings RuntimeSettings, active []uint64)')
need('go-supervision', read('control/parser_cells_supervision.go'), 'm.kernel.Reassert(m.runtimeSettings(), activeCgroups)')
need('go-api', api, 'parserCellInputBodyLimit int64 = 12 << 20')
need('go-api', api, '12 MiB base64 request bound')
need('go-client', client, 'Wayland')
need('go-client-codec', read('control/parser_cells_client_codec.go'), 'parseParserCellCapabilitiesPayload')

# --- packaging/deployment boundary ------------------------------------------
unit = read('packaging/systemd/gedefense-cell-helper.service')
for directive in (
    'ConditionPathExists=@RELEASE@/libexec/gedefense-cell-helper',
    'User=root', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
    'PrivateTmp=yes', 'RestrictAddressFamilies=AF_UNIX', 'RestrictNamespaces=mnt pid ipc uts net',
    'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN',
    'ReadWritePaths=/var/lib/vgt/gedefense/parser-inputs /var/lib/vgt/gedefense/parser-exports',
    'ReadWritePaths=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl',
    'IPAddressDeny=any', 'UMask=0077', 'Restart=on-failure', 'StartLimitIntervalSec=120',
    'SystemCallFilter=@system-service @mount seccomp',
):
    need('systemd-helper-unit', unit, directive)
if 'ProtectControlGroups=yes' in unit:
    missing.append('systemd-helper-unit: ProtectControlGroups=yes would block the dedicated cgroup subtree')
# T5 fix: the control-plane-owned parser-imports directory must never be in the
# helper unit's writable set - the helper only writes inputs/exports/ledger.
if 'parser-imports' in unit:
    missing.append('systemd-helper-unit: parser-imports must not be a helper ReadWritePath (control-owned import copy)')
tmpfiles = read('packaging/tmpfiles/vgt-gedefense.conf')
for line in (
    'd /var/lib/vgt/gedefense/parser-inputs 0730 gedefense gedefense -',
    'd /var/lib/vgt/gedefense/parser-exports 0750 root gedefense -',
    'd /var/lib/vgt/gedefense/parser-imports 0750 gedefense gedefense -',
    'f /var/lib/vgt/gedefense/parser-burn-ledger.jsonl 0640 root gedefense -',
    'C /etc/vgt/gedefense/parser-profiles.conf 0640 root root - /usr/share/gedefense/parser-profiles.conf',
):
    need('tmpfiles', tmpfiles, line)
provision = read('packaging/scripts/gedefense-provision')
need('provision', provision, 'ensure_raw_key "${SECRETS_DIR}/cell-helper.key" 0640 root "${CONTROL_GROUP}"')
need('provision', provision, '"/var/lib/vgt/gedefense/parser-inputs:0730:${CONTROL_USER}:${CONTROL_GROUP}"')
need('provision', provision, '"/var/lib/vgt/gedefense/parser-imports:0750:${CONTROL_USER}:${CONTROL_GROUP}"')
need('provision', provision, 'ensure_parser_profile')
templates = read('packaging/templates/parser-profiles.conf')
if re.search(r'(?m)^\[profile ', templates):
    missing.append('parser-profiles template: packaged default must not invent an active parser profile')
pkgbuild = read('packaging/arch/PKGBUILD')
need('pkgbuild', pkgbuild, 'packaging/systemd/gedefense-cell-helper.service')
need('pkgbuild', pkgbuild, 'dist/gedefense-cell-helper')
need('makefile', read('Makefile'), 'rust-helper')
need('release-build', read('scripts/package-artifacts.sh'), 'gedefense-cell-helper')
installer = read('scripts/oneclick-installer-header.sh')
for anchor in (
    'readonly HELPER_SHA256="__HELPER_SHA256__"',
    '--artifact-file "gedefense-cell-helper=$PAYLOAD/bin/gedefense-cell-helper"',
    'libexec/gedefense-cell-helper',
    'cell-helper.key',
    'parser-profiles.conf',
    'gedefense-cell-helper.service',
):
    need('installer-prebuilt', installer, anchor)
source_bootstrap = read('scripts/oneclick-source-bootstrap-header.sh')
for anchor in (
    'packaging/systemd/gedefense-cell-helper.service',
    'packaging/templates/parser-profiles.conf',
    '__HELPER_SHA256__/source-built',
):
    need('installer-source', source_bootstrap, anchor)
need('install-smoke', read('packaging/tests/install-smoke.sh'), 'gedefense-cell-helper.service')
need('validate-systemd', read('scripts/validate-systemd.sh'), 'gedefense-cell-helper.service')
installed_gate = read('scripts/validate-installed-linux-host.sh')
need('installed-host-gate', installed_gate, 'release-manifest.signed.json')
need('installed-host-gate', installed_gate, 'deployment drift detected')
need('installed-host-gate', installed_gate, 'parser_cells enabled but runtime unavailable')
need('installed-host-gate', installed_gate, 'PARSER_CELLS_LSM_WARNING')
need('astraeaos-provision', read('integration/astraeaos/gedefense-astraeaos-provision'), 'CELL_HELPER_KEY')
need('astraeaos-contract', read('integration/astraeaos/contract.json'), 'ephemeral_parser_cells')

if missing:
    raise SystemExit('Point 2 parser-cell anchors missing:\n' + '\n'.join(missing))
PYP2
pass 'Point 2 parser-cell helper boundary, VGTGC2 control integration, default-off and packaging gates present'

# POINT 5 (docs/POINT5-LOCKDOWN.md §3-§9, §12): Emergency Lockdown /
# anti-physical-extraction. Additive gate only - every pre-existing Point 1/2/3
# anchor above stays unchanged. It pins the shared ABI, the OFF/fail-safe eBPF
# fastpath in all three hooks, the core LOCKDOWN_* dispatch/state/re-arm, the
# honest phase and unsupported vocabulary, the default-off authenticated Go
# latch/API, and the exact unit grant set (no capability/address-family/syscall
# widening). Source-only anchors are paired with the shipped-object readelf
# check below.
python3 - "$ROOT" <<'PYP5'
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

# --- ABI-1: shared constants, epoch/flag word and the 64-byte event (§3) -----
common_lib = read('rust/gedefense-common/src/lib.rs')
common = read('rust/gedefense-common/src/lockdown.rs')
if 'mod lockdown;' not in common_lib or 'pub use lockdown::*;' not in common_lib:
    missing.append('rust-common-lib: lockdown module is not exported')
for anchor in (
    'pub const LOCKDOWN_STATE_MAGIC: u8 = 0x4C;', 'pub const LOCKDOWN_STATE_ABI: u8 = 1;',
    'pub const LOCKDOWN_FLAG_DROP_ALL: u8 = 1 << 0;', 'pub const LOCKDOWN_FLAG_ALLOW_LOOPBACK: u8 = 1 << 1;',
    'pub const LOCKDOWN_FLAG_HARDENING_APPLIED: u8 = 1 << 3;',
    'pub const LOCKDOWN_FLAG_USB_LOCKED: u8 = 1 << 4;', 'pub const LOCKDOWN_FLAG_TB_LOCKED: u8 = 1 << 5;',
    'pub const fn encode_lockdown_word(epoch: u32, mode: u8, flags: u8) -> u64 {',
    'pub const fn decode_lockdown_word(word: u64) -> Option<LockdownWord> {',
    'pub const LOCKDOWN_EVENT_WIRE_BYTES: usize = 64;',
    'pub const LOCKDOWN_REASON_POLICY: u8 = 8;', 'pub const LOCKDOWN_SOURCE_TIMER: u8 = 4;',
    'pub const LOCKDOWN_PHASE_DM: u8 = 8;', 'pub const LOCKDOWN_OUTCOME_PARTIAL: u8 = 5;',
    'pub reserved: [u8; 24],',
    'assert!(core::mem::size_of::<LockdownEvent>() == LOCKDOWN_EVENT_WIRE_BYTES);',
    'assert!(core::mem::offset_of!(LockdownEvent, reserved) == 40);',
):
    need('rust-common-lockdown', common, anchor)

# --- ABI-2: eBPF fastpath in XDP, TC-ingress and cgroup egress (§4) ----------
# Default word 0 = OFF; a foreign magic/ABI/mode or a zero word returns None so
# the pre-existing verdict path stays byte-identical (fail-safe, no claim).
ebpf = read('rust/gedefense-ebpf/src/main.rs')
for anchor in (
    'static LOCKDOWN_STATE: Array<u64> = Array::with_max_entries(1, 0);',
    'static LOCKDOWN_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);',
    'static LOCKDOWN_WITNESS_PASSES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);',
    'if magic != LOCKDOWN_STATE_MAGIC || abi != LOCKDOWN_STATE_ABI || mode != LOCKDOWN_MODE_ARMED {',
    'fn lockdown_drop_active() -> bool {',
    'fn lockdown_egress_verdict(ctx: &SkBuffContext) -> Option<i32> {',
    'fn lockdown_loopback_packet(ctx: &SkBuffContext) -> Option<bool> {',
    'increment_counter(&LOCKDOWN_DROPS);', 'increment_counter(&LOCKDOWN_WITNESS_PASSES);',
    'src[0] == 127 && dst[0] == 127',
):
    need('rust-ebpf', ebpf, anchor)
need_match('rust-ebpf', ebpf, 'XDP drops before the pre-existing inspect pipeline',
           r'pub fn gedefense_xdp\(ctx: XdpContext\) -> u32 \{.*?if lockdown_drop_active\(\) \{.*?return xdp_action::XDP_DROP;.*?match inspect\(&ctx\)')
need_match('rust-ebpf', ebpf, 'TC-ingress shots before the pre-existing policy pipeline',
           r'pub fn gedefense_tc_ingress\(ctx: TcContext\) -> i32 \{.*?if lockdown_drop_active\(\) \{.*?return TC_ACT_SHOT;.*?match inspect_tc_ingress\(&ctx\)')
need_match('rust-ebpf', ebpf, 'cgroup egress consults the lockdown verdict before the Point 3 policy',
           r'pub fn gedefense_egress\(ctx: SkBuffContext\) -> i32 \{.*?if let Some\(verdict\) = lockdown_egress_verdict\(&ctx\) \{.*?match inspect_egress\(&ctx\)')

# --- ABI-3: core LOCKDOWN_* command family, state file and re-arm (§5) -------
core = read('rust/gedefense-core/src/main.rs')
lockdown = read('rust/gedefense-core/src/lockdown.rs')
usb = read('rust/gedefense-core/src/lockdown_usb.rs')
uevent = read('rust/gedefense-core/src/lockdown_uevent.rs')
hardening = read('rust/gedefense-core/src/lockdown_hardening.rs')
brokers = read('rust/gedefense-core/src/lockdown_brokers.rs')
for command in (
    '["LOCKDOWN_VERSION"] => Ok(core.version().to_owned()),',
    '["LOCKDOWN_EPOCH"] => Ok(format!("{:08x}", core.epoch())),',
    '["LOCKDOWN_STATUS"] => Ok(lockdown_status(core)),',
    '["LOCKDOWN_ARM", mode, reason, flags] => {',
    '["LOCKDOWN_TRIGGER", source, reason, flags] => {',
    '["LOCKDOWN_CLEAR", expected_epoch, reason] => {',
    '["LOCKDOWN_SET_MODE", mode] => {',
    '["LOCKDOWN_EVENTS"] => lockdown_events(core),',
    '["LOCKDOWN_HEALTH"] => lockdown_health(core),',
    '["LOCKDOWN_PHASE", phase, state] => {',
):
    need('rust-core', core, command)
need('rust-core', core, '[command, ..] if command.starts_with("LOCKDOWN_") => {')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_STATE").ok_or("LOCKDOWN_STATE missing")?')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_DROPS").ok_or("LOCKDOWN_DROPS missing")?')
need('rust-core', core, 'ebpf.take_map("LOCKDOWN_WITNESS_PASSES").ok_or("LOCKDOWN_WITNESS_PASSES missing")?')
need('rust-core', core, 'let lockdown_state_path = arg("lockdown-state", lockdown::DEFAULT_STATE_FILE);')
for anchor in (
    'pub(crate) const VERSION: &str = "lockdown-v1";',
    'pub(crate) const DEFAULT_STATE_FILE: &str = "/var/lib/vgt/gedefense/LOCKDOWN.state";',
    'pub(crate) const DELEGATED: u8 = 0x80;',
    'pub(crate) const REASON_SESSIONS: &str = "no-dbus-session-lock";',
    'pub(crate) const REASON_DM: &str = "no-device-mapper";',
    'pub(crate) fn startup_rearm(&mut self) -> Result<String, String> {',
    'self.epoch = new_epoch(self.epoch)?;',
    'fn new_epoch(previous: u32) -> Result<u32, String> {',
    'pub(crate) fn state_text(&self) -> &\'static str {',
    'LOCKDOWN_PHASE_CELLS => (DELEGATED, "delegated-to-control"),',
):
    need('rust-core-lockdown', lockdown, anchor)
need('rust-core', core, 'fn write_lockdown_state_atomic(path: &Path, content: &str) -> Result<(), String> {')
need('rust-core', core, '.mode(0o640)')
need('rust-core', core, 'fn load_lockdown_state(path: &Path) -> LockdownStateLoad {')
need('rust-core', core, 'if core.phase_outcome(LOCKDOWN_PHASE_CELLS) == lockdown::DELEGATED {')
need('rust-core', core, '[LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_DM]')
need('rust-core', core, 'const LOCKDOWN_KERNEL_LOCKDOWN_REASON: &str = "boot-parameter-immutable";')

# --- USB/Thunderbolt policy + lossy uevent handling + rescan (§6.2) ---------
for anchor in (
    'self.sys_root.join("bus/usb/drivers_autoprobe")',
    'self.sys_root.join("bus/thunderbolt/devices")',
    'const CLASS_HID: u8 = 0x03;', 'const CLASS_HUB: u8 = 0x09;',
    'fn is_power_only(',
    'let Some(count) = num_interfaces else { return false };',
    'count as usize != ifaces.len()',
    'fn parent_device_devpath(',
    'DevicePolicy::PowerOnly', 'DevicePolicy::Console',
    'pub(crate) fn apply_usb(paths: &UsbPaths) -> PolicyReport {',
    'pub(crate) fn release_usb(paths: &UsbPaths) -> PolicyReport {',
    'pub(crate) fn apply_tb_device(paths: &UsbPaths, devpath: &str) -> Result<(), &\'static str> {',
):
    need('rust-core-usb', usb, anchor)
for anchor in (
    'pub(crate) const UEVENT_GROUP: u32 = 1;',
    'Some(libc::ENOBUFS) => Poll::Rescan,',
    'fn rescan(shared: &LockdownShared, usb_paths: &lockdown_usb::UsbPaths) {',
    'Poll::Rescan => rescan(shared, usb_paths),',
    'if shared.auto_network_drop().is_err() {',
):
    need('rust-core-uevent', uevent, anchor)

# --- Hardening: observation always, opt-in writes, modules_disabled never auto
for anchor in (
    'pub(crate) fn hardening_phase(&mut self, explicit: bool) -> (u8, &\'static str) {',
    'modules-disabled-auto-forbidden',
    'pub(crate) fn modules_disabled_auto_state() -> &\'static str {',
    'paths.kexec()', 'paths.sysrq()', 'paths.modules()',
    'Write::Blocked',
):
    need('rust-core-hardening', hardening, anchor)

# --- Broker freeze: reversible SIGSTOP/SIGCONT, honest frozen-not-locked -----
for anchor in (
    'pub(crate) const BROKER_STATUS: &str = "frozen-not-locked";',
    'pub(crate) const BROKER_NAMES: &[&str] =',
    'pub(crate) const BROKER_TTL: Duration = Duration::from_secs(300);',
    'libc::SIGSTOP', 'libc::SIGCONT', 'pidfd_signal',
):
    need('rust-core-brokers', brokers, anchor)
need('rust-core', core, 'fn lockdown_modules_never_use_shell_or_kill_primitives() {')

# --- Go control plane: default-off settings, latch, triggers, API (§7) --------
settings = read('control/lockdown_settings.go')
runtime_settings = read('control/runtime_settings.go')
engine = read('control/lockdown.go')
engine_ops = read('control/lockdown_engine.go')
phases = read('control/lockdown_phases.go')
triggers = read('control/lockdown_triggers.go')
api = read('control/lockdown_api.go')
status = read('control/lockdown_status.go')
coreipc = read('control/coreipc.go')
server = ''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('server*.go')) if not p.name.endswith('_test.go'))
xdr=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('xdr*.go')) if not p.name.endswith('_test.go'))
main = read('control/main.go')
state = read('control/state.go')
schema = read('control/fabric_schema.go')
fabric_settings = read('control/fabric_settings.go')
need_match('go-settings', settings, 'lockdown defaults are disabled and disarmed (inert upgrade)',
           r'func defaultLockdownFabricSettings\(\) LockdownFabricSettings \{.*?Enabled:\s+false,.*?AutoArm:\s+false,')
need_match('go-settings', settings, 'the panic loopback drop is opt-in and hardening is off by default',
           r'DropLoopback:\s+false,.*?HardeningApply:\s+false,')
for anchor in (
    'func validateLockdownFabricSettings(', 'func cloneLockdownFabricSettings(',
    'func effectiveLockdownSettings(',
    'lockdownConfirmationTrigger = "TRIGGER LOCKDOWN"',
    'lockdownConfirmationClear   = "CLEAR:LOCKDOWN"',
    'lockdownMaxRequireSources   = 4', 'lockdownMaxTargetsCap',
):
    need('go-settings', settings, anchor)
need_match('go-runtime', runtime_settings, 'settings schema version is at least v16 (lockdown namespace)',
           r'const fabricSettingsVersion = (?:1[6-9]|[2-9][0-9])')
need('go-runtime', runtime_settings, 'Lockdown *LockdownFabricSettings `json:"lockdown,omitempty"`')
need('go-runtime', runtime_settings, 'if settings.Lockdown == nil {')
need('go-runtime', runtime_settings, 'settings.Migrations = append(settings.Migrations, lockdownMigrationNote)')
need('go-runtime', runtime_settings, 'if err := validateLockdownFabricSettings(&lockdown); err != nil {')
for anchor in (
    'type LockdownEngine struct {', 'func NewLockdownEngine(',
    'lockdownEngineStatePath = "/var/lib/vgt/gedefense/lockdown-engine.state"',
    'lockdownEnginePurpose = "lockdown-engine"',
    'e.storage.Decrypt(e.path, lockdownEnginePurpose, raw, nil)',
    'e.storage.Encrypt(e.path, lockdownEnginePurpose, e.doc.Revision, plaintext)',
    'e.addEvent("critical", "lockdown.state.corrupt",',
    'errLockdownCapabilityMiss',
):
    need('go-engine', engine, anchor)
for anchor in (
    'func (e *LockdownEngine) Arm(', 'func (e *LockdownEngine) Trigger(',
    'func (e *LockdownEngine) Clear(',
    'lockdown.trigger.intent', 'lockdown.trigger.outcome',
    'lockdown.clear.intent', 'lockdown.clear.outcome',
    '"lockdown.phase."+phase.Phase',
    'lockdown.state.persist_failed',
    'engine.Reverse(id, "REVERSE "+id)',
    'lockdown.cells.resume_failed', 'lockdown.cells.resumed',
    'func lockdownCoreFlags(settings LockdownFabricSettings) uint8 {',
):
    need('go-engine', engine_ops, anchor)
for anchor in (
    'lockdownPhaseUnsupported', 'lockdownPhaseNameSessions', 'lockdownPhaseNameDM',
    'lockdownPhaseNameKernelLockdown', 'uid-0 process excluded by settings',
    'func (e *LockdownEngine) runCorePhases(',
):
    need('go-phases', phases, anchor)
for anchor in (
    'func lockdownIncidentCandidate(', 'func lockdownCanaryUnauthorizedProbe(',
    'func lockdownFingerprint(', 'func (e *LockdownEngine) applyTriggerGuards(',
    'errLockdownCooldown', 'errLockdownSourcesPending',
    'func (e *LockdownEngine) reconcileBootTrust(',
    'func (e *LockdownEngine) pollDuress(',
):
    need('go-triggers', triggers, anchor)
need('go-api', api, 'POST /api/v1/lockdown/trigger  {confirmation: "TRIGGER LOCKDOWN", reason, source?}')
need('go-api', api, 'strings.TrimSpace(in.Confirmation) != lockdownConfirmationTrigger')
need('go-api', api, 'strings.TrimSpace(in.Confirmation) != lockdownConfirmationClear')
need('go-api', api, 'view := s.lockdown.StatusView()')
for route in (
    'mux.HandleFunc("GET /api/v1/lockdown/status", s.auth(s.lockdownStatus))',
    'mux.HandleFunc("POST /api/v1/lockdown/arm", s.auth(s.lockdownArm))',
    'mux.HandleFunc("POST /api/v1/lockdown/trigger", s.auth(s.lockdownTrigger))',
    'mux.HandleFunc("POST /api/v1/lockdown/clear", s.auth(s.lockdownClear))',
):
    need('go-server', server, route)
need('go-server', server, '"/api/v1/lockdown/trigger",')
need('go-server', server, '"/api/v1/lockdown/clear":')
need('go-server', server, 's.lockdownLimiter = NewRateLimiter(1, 1)')
need('go-server', server, 'snapshot.Lockdown = &lockdownView')
need('go-state', state, 'Lockdown       *LockdownStatusView `json:"lockdown,omitempty"`')
need('go-xdr', xdr, 'func (e *XDREngine) AttachLockdown(engine *LockdownEngine) {')
need('go-xdr', xdr, 'e.lockdown.ObserveIncident(incident)')
need('go-main', main, 'lockdownEngine, lockdownErr := NewLockdownEngine(LockdownEngineConfig{')
need('go-main', main, 'lockdownEngine.AttachBootTrust(srv.bootTrustVerdict)')
need('go-main', main, 'go lockdownEngine.Run(xdrCtx)')
need('go-schema', schema, '{module: "lockdown", group: "Emergency Lockdown", key: "enabled"')
need('go-fabric-settings', fabric_settings, 'case "lockdown":')
for anchor in (
    'var ErrLockdownUnavailable = errors.New("lockdown capability unavailable")',
    'func (c *CoreClient) LockdownStatus() (CoreLockdownStatus, error) {',
    'func (c *CoreClient) LockdownTrigger(source, reason string, flags uint8) (CoreLockdownTriggerResult, error) {',
    'func (c *CoreClient) LockdownClear(expectedEpoch, reason string) (string, error) {',
    'func parseCoreLockdownStatus(payload string) (CoreLockdownStatus, error) {',
    'lockdownPhaseNameCells',
):
    need('go-coreipc', coreipc, anchor)
need('go-triggers', triggers, 'func parseCoreLockdownEvents(payload string) ([]CoreLockdownEvent, uint64, error) {')

# --- packaging boundary: exact grants, unchanged cap/af/syscall contract -----
# /sys/devices is required in addition to the bus paths because
# /sys/bus/usb/devices and /sys/bus/thunderbolt/devices are sysfs symlinks: a
# per-device "authorized" write resolves into /sys/devices/** and would be
# EROFS with a bus-only grant (fail-safe but ineffective).
unit = read('packaging/systemd/gedefense-core.service')
for directive in (
    'ReadWritePaths=-/sys/bus/usb -/sys/bus/thunderbolt/devices -/sys/devices',
    'ReadWritePaths=-/proc/sys/kernel/kexec_load_disabled -/proc/sys/kernel/sysrq -/proc/sys/kernel/modules_disabled',
    'ReadWritePaths=/var/lib/vgt/gedefense',
    'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL',
    'AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_KILL',
    'RestrictAddressFamilies=AF_UNIX AF_NETLINK',
    'SystemCallFilter=@system-service bpf perf_event_open pidfd_open pidfd_send_signal fanotify_init fanotify_mark',
):
    need('systemd-core-unit', unit, directive)
# No further /sys node may be granted: the complete writable sysfs set is the
# pre-existing bpffs mount plus the three reviewed lockdown nodes.
sys_grants = set()
for line in unit.splitlines():
    if not line.startswith('ReadWritePaths='):
        continue
    for token in line.split('=', 1)[1].split():
        token = token.lstrip('-')
        if token == '/sys' or token.startswith('/sys/'):
            sys_grants.add(token)
if sys_grants != {'/sys/bus/usb', '/sys/bus/thunderbolt/devices', '/sys/devices', '/sys/fs/bpf'}:
    missing.append('systemd-core-unit: unexpected writable sysfs set: ' + ', '.join(sorted(sys_grants)))
if len(re.findall(r'(?m)^CapabilityBoundingSet=', unit)) != 1:
    missing.append('systemd-core-unit: CapabilityBoundingSet must stay one reviewed line')
if re.search(r'(?m)^CapabilityBoundingSet=.*(?:CAP_SYS_PTRACE|CAP_SYS_MODULE|CAP_DAC_READ_SEARCH|CAP_SYS_RAWIO)', unit):
    missing.append('systemd-core-unit: lockdown must not widen the capability set (ptrace/module/DAC/rawio)')
if re.search(r'(?m)^RestrictAddressFamilies=.*(?:AF_INET|AF_PACKET|AF_BLUETOOTH)', unit):
    missing.append('systemd-core-unit: lockdown must not widen the address families')
if re.search(r'ReadWritePaths=(?:[^\n]*\s)?/sys(?:\s|$)', unit):
    missing.append('systemd-core-unit: /sys must not be granted writable as a whole (lockdown grants exact bus paths only)')
tmpfiles = read('packaging/tmpfiles/vgt-gedefense.conf')
need('tmpfiles', tmpfiles, 'd /var/lib/vgt/gedefense 1770 root gedefense -')
need('pkgbuild', read('packaging/arch/PKGBUILD'), '"${_source_root}/packaging/systemd/gedefense-core.service"')
need('validate-systemd', read('scripts/validate-systemd.sh'), 'POINT 5')
need('install-smoke', read('packaging/tests/install-smoke.sh'), 'POINT 5')

if missing:
    raise SystemExit('Point 5 lockdown anchors missing:\n' + '\n'.join(missing))
PYP5
pass 'Point 5 lockdown ABI, fail-safe eBPF fastpath, core state/re-arm, Go latch/API and packaging grants present'

# POINT 4 (P4-T3, docs/POINT4-WITNESS.md §3-§8, §11): mandatory anchors for the
# Out-of-Band Witness. Additive gate only - every pre-existing Point 1/2/3/5
# anchor above stays unchanged. Each anchor pins a definition, a decision, a
# hard bound or an honest capability boundary (never a bare comment or a test
# fixture), so removing a control cannot be compensated elsewhere. The witness is
# unprivileged Go control: it ships no daemon, no unit and no new
# capability/address-family/syscall contract, and the external witness server is
# deliberately not part of the repository (Phase 2, no fake server).
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
ledger = read('control/evidence_ledger.go')
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
runtime_settings = read('control/runtime_settings.go')
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
need('go-state', read('control/state.go'), 'Witness *WitnessStatus `json:"witness,omitempty"`')
main_go = read('control/main.go')
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
pass 'Point 4 witness epoch/checkpoint, hardened client, receipts, bounded outbox, export/import, equivocation, v17 default-off and privacy/no-server boundaries present'

# V6.3.0 (AP-0/AP-1/AP-2): sensor self-protection, executable-inode trust gate
# and the attach-time eBPF guard. Every anchor pins a definition, a decision or a
# default - never a bare comment. The observe-only contract and the unchanged
# kill gate are pinned as explicit negatives, and the musl release gate is
# pinned in the Makefile and in CI.
python3 - "$ROOT" <<'PYV63'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-0: eBPF pin manifest, synthetic canary self-test and the bounded queue.
self_defense = read('rust/gedefense-core/src/self_defense.rs')
for anchor in [
    'const TAMPER_QUEUE_CAPACITY', 'const PIN_VERIFY_INTERVAL_MS',
    'const CANARY_TEST_INTERVAL_MS', 'fn install_pins(',
    'fn verify_pins(', 'fn pin_one(', 'fn inspect_pin(',
    'KIND_PIN_MISSING', 'KIND_PIN_REPLACED', 'KIND_CANARY_DEAD',
    'DECOY_CANARY_TYPE', 'const CRITICAL_MAPS',
]:
    need('self-defence', self_defense, anchor)
selfguard_go = read('control/xdr_selfguard.go')
for anchor in [
    'selfGuardRuleID = "XDR.SELF_TAMPER"',
    'selfGuardSBCFamily = "SBC-EVID-08"',
    'func (e *XDREngine) pollSelfGuard',
    'func (e *XDREngine) watchSelfGuardRingDrops',
    'func (e *XDREngine) recordSelfTamperFact',
]:
    need('xdr-selfguard', selfguard_go, anchor)
need_match('xdr-selfguard', selfguard_go, 'self-tamper incidents are evidence-first and alert-only',
           r'Decision:\s*"degrade"[\s\S]{0,200}?Action:\s*"none"')
forbid('xdr-selfguard', selfguard_go, r'\bKillEligible\s*:\s*true', 'kill-eligible self-tamper rule')
forbid('xdr-selfguard', selfguard_go, r'Decision:\s*"kill"', 'self-tamper kill decision')
selfguard_ipc = read('control/coreipc_selfguard.go')
for anchor in ['ErrSelfGuardUnavailable', 'func (c *CoreClient) SelfTamperEvents()',
               'func parseCoreSelfTamperEvents']:
    need('selfguard-ipc', selfguard_ipc, anchor)
need('selfguard-fuzz', read('control/coreipc_selfguard_test.go'), 'func FuzzCoreSelfGuardParser')
makefile = read('Makefile')
for anchor in ['rust-core-musl', 'rust-check', 'readelf -d',
               'statically linked', 'FuzzCoreSelfGuardParser',
               'FuzzCoreExecInodeParser', 'FuzzCoreBpfGuardParser']:
    need('makefile-v63', makefile, anchor)
ci = read('.github/workflows/ci.yml')
for anchor in ['x86_64-unknown-linux-musl', 'readelf -d', 'statically linked']:
    need('ci-musl', ci, anchor)

# AP-1: executable-inode trust gate (primary) with audited comm fallback.
common_exec = read('rust/gedefense-common/src/exec_inode.rs')
for anchor in ['EXEC_INODE_STATE_MAGIC', 'EXEC_INODE_ALLOW_CRED_READ',
               'EXEC_INODE_ALLOW_RANSOM_FULL', 'EXEC_INODE_ALLOW_RANSOM_POOL_META',
               'EXEC_INODE_EVENT_WIRE_BYTES', 'decode_exec_inode_event',
               'EXEC_INODE_OFFSETS_TABLE_LEN']:
    need('exec-inode-ab', common_exec, anchor)
ebpf_exec = read('rust/gedefense-ebpf/src/exec_inode.rs')
for anchor in ['static TRUSTED_EXEC_INODES', 'static MALWARE_TTL_INODES',
               'static EXEC_INODE_EVENTS', 'fn current_exec_trust',
               'fn ttl_inode_denied', 'fn emit_exec_inode_fallback_once']:
    need('exec-inode-ebpf', ebpf_exec, anchor)
ebpf_cred = read('rust/gedefense-ebpf/src/credential_guard.rs')
for anchor in ['current_exec_trust()', 'CRED_GUARD_ACTION_DENY_INODE',
               'emit_exec_inode_fallback_once', 'EXEC_INODE_CRED_FLAG']:
    need('exec-inode-credguard', ebpf_cred, anchor)
need_match('exec-inode-credguard', ebpf_cred,
           'the inode gate is the primary credential decision',
           r'let Some\(\(exe_identity, trust_flags\)\) = current_exec_trust\(\) else \{')
ebpf_ransom = read('rust/gedefense-ebpf/src/ransom.rs')
for anchor in ['current_exec_trust()', 'exec_inode_trust_tier',
               'EXEC_INODE_RANSOM_FULL_FLAG', 'EXEC_INODE_RANSOM_POOL_META_FLAG']:
    need('exec-inode-ransom', ebpf_ransom, anchor)
btf = read('rust/gedefense-core/src/btf_offsets.rs')
for anchor in ['pub struct ExecInodeOffsets', 'pub fn resolve_exec_inode',
               'task_struct.mm', 'mm_struct.exe_file']:
    need('exec-inode-btf', btf, anchor)
need('exec-inode-btf-validate', read('rust/gedefense-core/src/btf_validate.rs'),
     'fn validate_exec_inode_offsets')
core_exec = read('rust/gedefense-core/src/exec_inode.rs')
for anchor in ['RESOLVE_NO_SYMLINKS', 'libc::SYS_openat2',
               'fn resolve_executable_identity', 'fn parse_ttl_token',
               'MALWARE_TTL_INODES', 'AUTH_EXEC_PATHS', 'POOL_SERVICE_PATHS']:
    need('exec-inode-core', core_exec, anchor)
exec_ipc = read('control/coreipc_execinode.go')
for anchor in ['ErrExecInodeUnavailable', 'func parseCoreExecInodeStatus',
               'func parseCoreExecInodeEvents', 'func (c *CoreClient) ExecInodeEvents()',
               'func (c *CoreClient) ExecInodeAllowDelete',
               'func (c *CoreClient) MalwareInodeLock']:
    need('exec-inode-ipc', exec_ipc, anchor)
need('exec-inode-fuzz', read('control/coreipc_execinode_test.go'), 'func FuzzCoreExecInodeParser')
xdr_exec = read('control/xdr_execinode.go')
for anchor in ['func (e *XDREngine) pollExecInode', '"XDR.NAME_PATH_MISMATCH"']:
    need('xdr-exec-inode', xdr_exec, anchor)
forbid('xdr-exec-inode', xdr_exec, r'\bKillEligible\s*:\s*true', 'kill-eligible inode mismatch rule')
need('exec-inode-credguard-label', read('control/coreipc_credguard.go'), 'CredGuardActionDenyInode')

# AP-2: attach-time eBPF guard / helper-risk bitmap.
common_bpf = read('rust/gedefense-common/src/bpf_guard.rs')
for anchor in ['BPF_GUARD_EVENT_WIRE_BYTES', 'HELPER_BIT_PROBE_WRITE_USER',
               'HELPER_BIT_OVERRIDE_RETURN', 'HELPER_BIT_SEND_SIGNAL',
               'decode_bpf_guard_event', 'BPF_GUARD_MAX_HELPER_ID']:
    need('bpf-guard-abi', common_bpf, anchor)
ebpf_bpf = read('rust/gedefense-ebpf/src/bpf_guard.rs')
for anchor in ['#[lsm(hook = "bpf_prog")]', '#[tracepoint]', '#[kprobe]',
               'gedefense_bpf_prog_guard', 'gedefense_bpf_syscall',
               'gedefense_check_helper_call', 'static BPF_GUARD_HELPER_BITMAP',
               'static BPF_GUARD_EVENTS']:
    need('bpf-guard-ebpf', ebpf_bpf, anchor)
core_bpf = read('rust/gedefense-core/src/bpf_guard.rs')
for anchor in ['check_helper_call', '/proc/kallsyms', 'BPF_GUARD_EVENTS',
               'BPF_GUARD_HELPER_BITMAP']:
    need('bpf-guard-core', core_bpf, anchor)
bpf_ipc = read('control/coreipc_bpf_guard.go')
for anchor in ['ErrBpfGuardUnavailable', 'func (c *CoreClient) BpfGuardEvents()',
               'func parseCoreBpfGuardEvents']:
    need('bpf-guard-ipc', bpf_ipc, anchor)
need('bpf-guard-fuzz', read('control/coreipc_bpfguard_test.go'), 'func FuzzCoreBpfGuardParser')
xdr_bpf = read('control/xdr_bpfguard.go')
for anchor in ['func (e *XDREngine) pollBpfGuard', 'func (e *XDREngine) bpfGuardEventTolerated',
               '"XDR.BPF_ANOMALY"', '"XDR.BPF_ROOTKIT_HELPER"']:
    need('xdr-bpf-guard', xdr_bpf, anchor)
forbid('xdr-bpf-guard', xdr_bpf, r'\bKillEligible\s*:\s*true', 'kill-eligible BPF guard rule')
need_match('xdr-bpf-guard', xdr_bpf, 'BPF guard incidents never derive an active response',
           r'Decision:\s*"alert"[\s\S]{0,160}?Action:\s*"none"')
need('bpf-guard-tolerated', xdr_bpf, 'bpftrace')

# Unchanged kill gate and sandbox invariants (regression pins).
need('kill-gate', read('control/xdr_rules.go'),
     'responseScore >= 120 && len(killCategories) >= 2')
core_unit = read('packaging/systemd/gedefense-core.service')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*PrivateTmp\s*=\s*true',
       'private tmp hiding host drop paths')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*CapabilityBoundingSet=.*CAP_DAC_OVERRIDE',
       'broad DAC override')
forbid('systemd-core-unit', core_unit, r'(?m)^\s*ProtectSystem\s*=\s*(?:no|false|off)',
       'weakened ProtectSystem')

if missing:
    raise SystemExit('V6.3.0 AP-0/AP-1/AP-2 anchors missing:\n' + '\n'.join(missing))
PYV63
pass 'V6.3.0 AP-0 self-protection, AP-1 executable-inode trust and AP-2 attach-time eBPF guard anchors present'

# V6.3.0 round 2 (AP-3 cross-view, AP-4 io_uring/LKM hooks, AP-5 persistence &
# peripheral integrity, AP-9 S09 TUF feed anti-poisoning). Every anchor pins a
# definition, a decision or a default; observe-only, the unchanged kill gate and
# the boot/package TOLERATED paths are pinned as explicit negatives.
python3 - "$ROOT" <<'PYV63R2'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
missing = []

def read(relative):
    return (root / relative).read_text(encoding='utf-8')

def need(component, text, anchor):
    if anchor not in text:
        missing.append(f'{component}: {anchor}')

def need_match(component, text, label, pattern):
    if re.search(pattern, text, re.S) is None:
        missing.append(f'{component}: {label}')

def forbid(component, text, pattern, label):
    if re.search(pattern, text) is not None:
        missing.append(f'{component}: forbidden {label}')

# AP-3: 8-domain cross-view verifier.
cross_common = read('rust/gedefense-common/src/cross_view.rs')
for anchor in ['CROSS_VIEW_EVENT_WIRE_BYTES', 'CROSS_VIEW_MAX_BPF_PROBES',
               'CROSS_VIEW_SCAN_BUDGET_MS', 'CROSS_VIEW_DOMAIN_EBPF_ID_GAP',
               'CROSS_VIEW_DOMAIN_SOCKET_VIEW',
               'decode_cross_view_event']:
    need('cross-view-abi', cross_common, anchor)
cross_ebpf = read('rust/gedefense-ebpf/src/iter.rs')
for anchor in ['#[lsm(hook = "socket_create")]',
               '#[lsm(hook = "socket_setsockopt")]', '#[kprobe]',
               'gedefense_crossview_socket_create',
               'gedefense_crossview_socket_setsockopt',
               'gedefense_crossview_sk_attach_filter',
               'static CROSS_VIEW_STATE', 'static CROSS_VIEW_EVENTS']:
    need('cross-view-ebpf', cross_ebpf, anchor)
cross_core = read('rust/gedefense-core/src/cross_view.rs')
for anchor in ['BPF_CMD_PROG_GET_NEXT_ID', 'BPF_CMD_PROG_GET_FD_BY_ID',
               'BPF_CMD_MAP_GET_FD_BY_ID', 'BPF_CMD_LINK_GET_FD_BY_ID',
               'NETLINK_SOCK_DIAG', 'PACKET_SHOW_FILTER',
               'fn report(', 'fn take_events(']:
    need('cross-view-core', cross_core, anchor)
cross_ipc = read('control/coreipc_crossview.go')
for anchor in ['ErrCrossViewUnavailable', 'func parseCoreCrossViewEvents',
               'func (c *CoreClient) CrossViewReport()',
               'func (c *CoreClient) CrossViewEvents()']:
    need('cross-view-ipc', cross_ipc, anchor)
need('cross-view-fuzz', read('control/coreipc_crossview_test.go'),
     'func FuzzCoreCrossViewParser')
cross_xdr = read('control/xdr_crossview.go')
for anchor in ['func (e *XDREngine) pollCrossView',
               '"XDR.HIDDEN_BPF_PROG"', '"XDR.HIDDEN_SOCKET"',
               '"XDR.PORTLESS_RAW_TAP"', '"XDR.HIDDEN_PROCESS"',
               '"XDR.LKM_HIDDEN"', '"XDR.FTRACE_HOOK_ANOMALY"',
               'crossViewToleratedRawTaps']:
    need('xdr-cross-view', cross_xdr, anchor)
forbid('xdr-cross-view', cross_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible cross-view rule')
forbid('xdr-cross-view', cross_xdr, r'Decision:\s*"kill"', 'cross-view kill decision')

# AP-4: io_uring tracepoints/LSM hooks and pre-stealth LKM capture.
kh_common = read('rust/gedefense-common/src/kernel_hooks.rs')
for anchor in ['KERNEL_HOOK_EVENT_WIRE_BYTES', 'KERNEL_HOOK_KIND_IO_URING_CREATE',
               'KERNEL_HOOK_KIND_MODULE_LOAD', 'decode_kernel_hook_event',
               'KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD']:
    need('kernel-hooks-abi', kh_common, anchor)
kh_ebpf = read('rust/gedefense-ebpf/src/kernel_hooks.rs')
for anchor in ['gedefense_io_uring_create', 'gedefense_io_uring_register',
               'gedefense_io_uring_submit_req', 'gedefense_module_load',
               'gedefense_init_module', 'gedefense_finit_module',
               'gedefense_delete_module', 'gedefense_lsm_uring_override_creds',
               'gedefense_lsm_uring_sqpoll', 'gedefense_lsm_uring_cmd',
               'static KERNEL_HOOK_STATE', 'static KERNEL_HOOK_EVENTS',
               'static KERNEL_HOOK_OFFSETS']:
    need('kernel-hooks-ebpf', kh_ebpf, anchor)
kh_core = read('rust/gedefense-core/src/kernel_hooks.rs')
for anchor in ['/proc/kallsyms', 'KERNEL_HOOK_OFFSETS', 'fn epoch(',
               'fn take_events(']:
    need('kernel-hooks-core', kh_core, anchor)
kh_ipc = read('control/coreipc_kernel_hooks.go')
for anchor in ['ErrKernelHooksUnavailable', 'func parseCoreKernelHookEvents',
               'func (c *CoreClient) KernelHookEvents()']:
    need('kernel-hooks-ipc', kh_ipc, anchor)
need('kernel-hooks-fuzz', read('control/coreipc_kernel_hooks_test.go'),
     'func FuzzCoreKernelHookParser')
kh_xdr = read('control/xdr_kernel_hooks.go')
for anchor in ['func (e *XDREngine) pollKernelHooks', '"XDR.LKM_LOAD"',
               '"XDR.IO_URING_ANOMALY"', 'kernelHookModuleTolerated',
               'kernelHookIoUringTolerated']:
    need('xdr-kernel-hooks', kh_xdr, anchor)
forbid('xdr-kernel-hooks', kh_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible kernel-hook rule')
hardening = read('control/hardening_sysctl.go')
for anchor in ['kernel.io_uring_disabled', 'vm.memfd_noexec',
               'sysctlControlReservedMaskBits', '1 << 22', '1 << 23',
               '2 disables io_uring entirely']:
    need('hardening-ap4', hardening, anchor)
core_main = read('rust/gedefense-core/src/main.rs')
for anchor in ['0x00df_ffff', '(1 << 22, &[("kernel.io_uring_disabled", "1")])',
               '(1 << 23, &[("vm.memfd_noexec", "2")])',
               '["KERNEL_HOOK_EVENTS"]', '["CROSS_VIEW_REPORT"]',
               '["PERSIST_GUARD_EVENTS"]', '["PERSIST_BASELINE"]',
               '"kernel.io_uring_disabled" =>', '"vm.memfd_noexec" =>']:
    need('core-v63-seams', core_main, anchor)
forbid('core-v63-seams', core_main, r'HARDENING_CUSTOM_MASK: u32 = 0x001f_ffff',
       'stale 21-bit hardening mask (AP-4 opt-in bits missing)')

# AP-5: persistence/peripheral integrity guard.
pers_common = read('rust/gedefense-common/src/persistence.rs')
for anchor in ['PERSIST_EVENT_WIRE_BYTES', 'PERSIST_CLASS_LD_PRELOAD',
               'PERSIST_CLASS_PAM', 'PERSIST_CLASS_DEVICE_CAMERA',
               'PERSIST_CLASS_SECRET_SSH', 'decode_persistence_event',
               'encode_persistence_event']:
    need('persistence-abi', pers_common, anchor)
pers_ebpf = read('rust/gedefense-ebpf/src/persistence.rs')
for anchor in ['gedefense_persistence_file_open', 'gedefense_persistence_mmap',
               'gedefense_persistence_ptrace', 'gedefense_process_vm_readv',
               'gedefense_process_vm_writev', 'static PERSIST_GUARD_STATE',
               'static PERSIST_GUARD_PATHS', 'static PERSIST_GUARD_EXECS',
               'static PERSIST_GUARD_EVENTS']:
    need('persistence-ebpf', pers_ebpf, anchor)
pers_core = read('rust/gedefense-core/src/persistence.rs')
for anchor in ['RESOLVE_NO_SYMLINKS', 'libc::SYS_openat2',
               '/var/lib/dpkg/info', '/var/lib/pacman/local',
               'PERSIST_IDLEHINT_UNAVAILABLE', 'PERSIST_GUARD_EXECS',
               'fn baseline(', 'fn take_events(']:
    need('persistence-core', pers_core, anchor)
pers_ipc = read('control/coreipc_persistence.go')
for anchor in ['ErrPersistenceUnavailable',
               'func parseCorePersistenceEvents',
               'func (c *CoreClient) PersistenceBaseline()']:
    need('persistence-ipc', pers_ipc, anchor)
need('persistence-fuzz', read('control/coreipc_persistence_test.go'),
     'func FuzzCorePersistenceParser')
pers_xdr = read('control/xdr_persistence.go')
for anchor in ['func (e *XDREngine) pollPersistence',
               'XDR.LD_PRELOAD_INTEGRITY', 'XDR.LINKER_HOOK',
               'XDR.PERSISTENCE_ENTRY_DRIFT', 'XDR.PERIPHERAL_BG_ACCESS',
               'XDR.EVDEV_KEYLOG_PROBE', 'XDR.MEMORY_SCRAPE_PROBE',
               'XDR.SECRET_STORE_ACCESS', 'persistenceQualityTemporal',
               'persistenceIntegrityTolerated']:
    need('xdr-persistence', pers_xdr, anchor)
forbid('xdr-persistence', pers_xdr, r'\bKillEligible\s*:\s*true',
       'kill-eligible persistence rule')
forbid('xdr-persistence', pers_xdr, r'Decision:\s*"kill"', 'persistence kill decision')

# AP-9 / S09: TUF-grade threshold feed anti-poisoning + semantic guard + HWR.
tuf_manifest = read('control/tuf_manifest.go')
for anchor in ['vgt-gedefense-tuf-manifest-v1', 'vgt-gedefense-tuf-role-v1',
               'tufSignatureThreshold = 2', 'TUFReasonSignatureThreshold',
               'TUFReasonExpired', 'TUFReasonEpochRollback',
               'TUFReasonContentBinding', 'TUFReasonDiffBudget',
               'TUFReasonImmutableZone', 'TUFReasonGlobalAllow',
               'TUFReasonRegexComplexity', 'TUFReasonSystemPathInject']:
    need('tuf-manifest', tuf_manifest, anchor)
tuf_verify = read('control/tuf_manifest_verify.go')
for anchor in ['func verifyTUFManifestEnvelope',
               'func parseTUFManifestEnvelope', 'ed25519.Verify']:
    need('tuf-verify', tuf_verify, anchor)
tuf_guard = read('control/tuf_guard.go')
for anchor in ['func', 'immutable', '0.0.0.0/0']:
    need('tuf-guard', tuf_guard, anchor)
tuf_epoch = read('control/tuf_epoch.go')
for anchor in ['vgt-gedefense-tuf-high-water-v1', 'tuf-high-water.json',
               'tuf-high-water.key', 'hmac', '0600']:
    need('tuf-epoch', tuf_epoch, anchor)
tuf_shadow = read('control/tuf_shadow.go')
for anchor in ['r5_isolation=shadow', 'r5_helper_isolation=helper-pending']:
    need('tuf-shadow', tuf_shadow, anchor)
feeds = read('control/feeds.go')
for anchor in ['TUF TUFSecurityStatus', 'tufFeedProtectionSnapshot',
               'SetTUFEventSink', 'feed.poisoning_blocked']:
    need('feeds-tuf-gate', feeds, anchor)
need_match('feeds-tuf-gate', feeds, 'TUF gate runs before Last-Known-Good promotion',
           r'tufGate := m\.tufPrepareSyncGateLocked\(now\)[\s\S]{0,400}?tufGuardBlocked')
tuf_tests = (read('control/tuf_manifest_test.go') + read('control/tuf_guard_test.go')
             + read('control/tuf_epoch_test.go') + read('control/tuf_integration_test.go'))
for anchor in ['TestTufManifestRejectsInsufficientThreshold',
               'TestTufManifestRejectsExpiredAndAbsurdSnapshot',
               'TestTufManifestEpochStrictlyMonotonic',
               'TestTufGuardDiffBudget', 'TestTufGuardImmutableZoneDeletion',
               'TestTufGuardGlobalAllow', 'TestTufGuardRegexComplexity',
               'TestTufGuardSystemPathInject',
               'TestTufFeedBoundaryRejectsPoisonedValidlySignedUpdate',
               'TestTufHighWaterStoreCorruptionsFailClosed']:
    need('tuf-tests', tuf_tests, anchor)
forbid('tuf-verify', tuf_verify, r'tufSignatureThreshold\s*=\s*1', 'single-signature TUF threshold')

if missing:
    raise SystemExit('V6.3.0 round-2 anchors missing:\n' + '\n'.join(missing))
PYV63R2
pass 'V6.3.0 AP-3 cross-view, AP-4 io_uring/LKM hooks, AP-5 persistence/peripheral integrity and AP-9 S09 TUF anti-poisoning anchors present'

# V6.3.0 round 3 (AP-6 StyX phase 2 / DNS tunnelling / GIEF v1.0 + SBC fusion and
# AP-7 PermitV1 / review queue / QUARANTINE_PRUNE / explainability). Anchors pin
# definitions, decisions and defaults; observe-only, metadata-only and the
# unchanged kill gate are pinned as explicit negatives.
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
permit_tests = read('control/permit_broker_test.go')
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
prune_rust = read('rust/gedefense-core/src/quarantine.rs')
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
core_main = read('rust/gedefense-core/src/main.rs')
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
need('ap8-chameleon-seam', read('control/main.go'), 'NewChameleonProfile(chameleonManifestPath)')
need('ap8-chameleon-flag', read('control/main.go'), 'chameleon-manifest')
need('ap8-chameleon-load', read('rust/gedefense-core/src/main.rs'), 'chameleon::ManagedEbpf::new')
need('ap8-chameleon-arg', read('rust/gedefense-core/src/main.rs'), '"chameleon-manifest"')
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
                'rust/gedefense-ebpf/src/main.rs']:
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

printf 'SECURITY AUDIT PASS\n'
