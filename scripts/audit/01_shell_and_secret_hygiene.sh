#!/usr/bin/env bash
# V6.3.0 refactoring wave 5: security-audit stage 1 (original lines 13-362).
# Sourced by scripts/security-audit.sh in lexical order; ROOT/pass/fail
# are provided by the runner. Content is verbatim.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
files=sorted(
    p for p in (list((root/'control'/'web').rglob('*.js'))+list((root/'control'/'web').rglob('*.html')))
    if 'vendor' not in p.relative_to(root/'control'/'web').parts
)
forbidden={
    'innerHTML': re.compile(r'\binnerHTML\b'),
    'outerHTML': re.compile(r'\bouterHTML\b'),
    'insertAdjacentHTML': re.compile(r'\binsertAdjacentHTML\b'),
    'document.write': re.compile(r'\bdocument\s*\.\s*write\s*\('),
    'eval': re.compile(r'(?<![\w.])eval\s*\('),
    'Function constructor': re.compile(r'\bnew\s+Function\s*\('),
    'javascript URL': re.compile(r'javascript\s*:', re.I),
    'srcdoc': re.compile(r'\bsrcdoc\s*=', re.I),
    'inline event handler (HTML)': re.compile(r'\son[a-z]{3,}\s*=', re.I),
    'inline event handler (DOM)': re.compile(r'\bsetAttribute\s*\(\s*[\'"]on[a-z]{3,}', re.I),
}
findings=[]
for path in files:
    text=path.read_text(encoding='utf-8')
    for label, pattern in forbidden.items():
        if label == 'inline event handler (HTML)' and path.suffix != '.html':
            continue
        if label == 'inline event handler (DOM)' and path.suffix != '.js':
            continue
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
i18n_dir=root/'control'/'web'/'i18n'
marker='export const catalog = Object.freeze('
expected=('de','en','ru','zh-CN')
catalogs={}
for language in expected:
    path=i18n_dir/(language+'.js')
    if not path.is_file():
        raise SystemExit('i18n catalogue file missing: '+language)
    text=path.read_text(encoding='utf-8')
    start=text.find(marker)
    if start < 0:
        raise SystemExit('i18n catalogue structure missing: '+language)
    try:
        catalogs[language]=json.loads(text[start+len(marker):text.rfind(');')])
    except json.JSONDecodeError as exc:
        raise SystemExit(f'i18n catalogue JSON invalid ({language}): {exc}')
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
i18n_module=(root/'control'/'web'/'i18n.js').read_text(encoding='utf-8')
for anchor in ("export const catalogs = Object.freeze(", "export function t(", "export function initializeI18n("):
    if anchor not in i18n_module:
        raise SystemExit('i18n translator module contract missing: '+anchor)
used=set()
web=root/'control'/'web'
for file in [web/'index.html', *[p for p in sorted(web.rglob('*.js')) if 'i18n' not in p.parts]]:
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
release=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('release*.go')) if not p.name.endswith('_test.go'))
core_client=(root/'control'/'coreipc.go').read_text(encoding='utf-8')
core=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'rust'/'gedefense-core'/'src').rglob('*.rs')) if p.is_file() and (not p.name.endswith('_tests.rs') or p.name == 'main_tests.rs' or 'main_tests' in p.parts))
settings=''.join(p.read_text(encoding='utf-8') for p in sorted((root/'control').glob('runtime_settings*.go')) if not p.name.endswith('_test.go'))
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

