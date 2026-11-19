// STATUS: DIAMANT VGT SUPREME
'use strict';

// GeDefense 6.1.0 — Guided First-Start Setup Wizard & Offline AGENTS.md Blueprint.
// Security invariant: never exposes or simulates any remote AI control API.
// All recommendations are rendered statically or derived from read-only status APIs.
import { api } from './api.js';
import { t } from './i18n.js';
import { toast } from './render.js';

const STORAGE_DISMISSED = 'vgt.gedefense.wizard.dismissed.v61';

const AGENT_MD_BLUEPRINT = `# AGENTS.md — Autonomous Host Onboarding & Hardening Guide for GeDefense 6.1.0

> **Security Model:** GeDefense deliberately exposes **NO** inbound AI control channel or prompt API.
> An administrator runs a trusted CLI coding agent (Codex, Antigravity, Claude Code) directly via SSH
> with host operator privileges, evaluates the server read-only first, decides per module whether
> **Enforce**, **Observe**, or **Disabled** is safe for running workloads, applies configuration via
> the local GeDefense control plane (\`/api/v1/settings/{module}\`), and verifies before enabling Full Enforce.

---

## Phase 1 · Read-Only Host & Service Discovery
Run these commands first. Do NOT modify firewall/service state yet:
\`\`\`bash
uname -a
ss -tulpn
ps -eo pid,ppid,user:16,comm,args --sort=comm | head -n 120
systemctl list-units --type=service --state=running
ls -la /etc/nginx/ /www/server/nginx/conf/ /www/server/panel/vhost/nginx/ 2>/dev/null || true
ls -la /etc/systemd/system/gedefense*
systemctl status gedefense-core gedefense-capture-helper gedefense-control gedefense-access --no-pager
\`\`\`

## Phase 2 · Query Live GeDefense State (Read-Only)
Authenticate locally against \`127.0.0.1\` / gateway socket using operator token and inspect every module:
- \`GET /api/v1/status\` (Release phase, Core connection, Protection effective & gaps, XDR/L7/FIM health)
- \`GET /api/v1/overview/situation\` (Correlated traffic light, 6 protection planes)
- \`GET /api/v1/web-exposure/status\` (Web server ELF flags, HTTP/2 & HTTP/3 QUIC reachability, Advisories)
- \`GET /api/v1/worker-guard/status\` (Worker processes, shared master cgroups, crash storms)
- \`GET /api/v1/tls-sensor/status\` & \`/api/v1/tls-sensor/flows\` (AF_PACKET capture, ALPN, SNI, control-storm budget)
- \`GET /api/v1/lpe-guard/status\` (LSM socket_create deny matrix, ASLR sysctl, StyX web-ingress profile)
- \`GET /api/v1/edge-proxy/status\` (Check listener \`127.0.0.1:8443\` vs already-occupied ports before enabling!)
- \`GET /api/v1/styx/status\` & \`/api/v1/titan/exec/status\` & \`/api/v1/parser-cells/status\`
- \`GET /api/v1/boot-trust\`, \`/api/v1/hardening/posture\`, \`/api/v1/fim\`, \`/api/v1/witness/status\`, \`/api/v1/lockdown/status\`
- \`GET /api/v1/settings/schema\` (Exact schema, defaults & bounds for all 18+ namespaces)

## Phase 3 · Decision Matrix (Observe vs Enforce vs Disabled)
1. **Management Allowlist (MANDATORY FIRST):** Always confirm admin SSH/VPN/monitoring IPs in \`POST /api/v1/allowlist\` BEFORE transitioning \`canary\` -> \`enforce\`. Never lock yourself out.
2. **Webserver & L7 Traffic Guard:**
   - Only enable \`l7.mode = "enforce"\` once Nginx/Apache \`auth_request\` or VGT include snippet routes HTTP checks to GeDefense L7 socket without breaking static/panel vhosts (keep \`observe\` first for 15–30 min and inspect \`GET /api/v1/l7/findings\`).
3. **Module A · Web Exposure (\`web_exposure\`):**
   - Enable \`enabled = true\`, \`probe_loopback = true\`.
   - Ensure \`gedefense-control\` can inspect vhost config directories or note ACLs if panel uses \`0600 root:root\`.
4. **Module B · Worker Integrity (\`worker_guard\`):**
   - Enable \`enabled = true\` to detect \`SIGSEGV\`/\`SIGBUS\` crash storms (CVE-2026-123007 style).
   - Inspect \`skipped_cgroups\`! If \`nginx\` workers share the systemd unit cgroup with the master process, KEEP \`auto_apply_strict = false\` unless workers are isolated in a separate cgroup; otherwise strict \`JIT_ALLOW=0\`/\`NO_EXEC\` could affect reloads.
5. **Module C · TLS / ALPN Sensor (\`tls_sensor\`):**
   - Verify \`gedefense-capture-helper.service\` is \`active\` (\`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\`).
   - Enable \`enabled = true\`, \`ports = [443, 8443]\` (plus any custom TLS ports from \`ss -tulpn\`). Keep \`storm_action = "alert"\` initially; move to \`throttle\` only after observing normal upload/burst baselines.
6. **Module D · LPE Guard (\`lpe_guard\`):**
   - Safe on most hosts: \`enabled = true\`, ASLR sysctl (\`kernel.randomize_va_space = 2\`), socket policy. Before applying StyX \`web-ingress-only\`, verify no legitimate web app requires outbound raw sockets (\`AF_PACKET\` / \`AF_TIPC\` / \`SCTP\` / \`RDS\`).
7. **Module E · Edge Proxy (\`edge_proxy\`):**
   - Keep \`enabled = false\` unless you explicitly terminate TLS through GeDefense Edge (\`TLS 1.3\` + strict RFC-9113 HTTP/2 bounds). Check \`ss -tulpn\` so \`listen\` (default \`:8443\`) and \`upstream\` (\`:8080\`) do NOT collide with existing services (e.g. control panels or Go backends).
8. **Kinetic XDP, Threat Intel, XDR, StyX, Titan Exec, Parser Cells:**
   - Check \`GET /api/v1/kinetic/status\` \`ingress_mode\` (\`native\` / \`generic\` / \`tc\`). Start auto-ban safely after allowlist sync.
   - Run **XDR** & **StyX** in \`observe\` until process/behavior profiles warm up (\`profiles_warm\`), then promote to \`enforce\`.
   - Enable **Titan Exec-Gate** cautiously on production servers: audit allowed interpreter/compiler paths first before blocking unknown binaries.
   - Keep **Parser Cells** active if helper \`gedefense-cell-helper.service\` is healthy.
9. **FIM, Boot Trust, Witness, Lockdown:**
   - After every upgrade or settings/unit update, run \`POST /api/v1/fim/baseline\` (\`{"scope":"release"}\`) and verify \`GET /api/v1/fim\` shows \`health: "verified"\`.
   - Optionally configure remote **Witness** checkpoint push and duress/cooldown on **Emergency Lockdown** (\`arm\` only when ready).

## Phase 4 · Apply & Verify Safely
Always use preview -> apply:
1. \`POST /api/v1/settings/{module}/preview\` with current \`revision\`.
2. \`PUT /api/v1/settings/{module}\` once diff is clean.
3. Re-check \`GET /api/v1/overview/situation\`: confirm \`level\` improves without unintended HTTP 5xx or worker stalls, then promote Release \`observe -> canary -> enforce\`.
`;

const WIZARD_STEPS = [
  {
    id: 'agents',
    num: '00',
    titleKey: 'wizard.step.agents.title',
    subtitleKey: 'wizard.step.agents.sub',
    descKey: 'wizard.step.agents.desc',
    targetView: 'overview',
    targetTab: '',
    statusFn: () => ({ label: 'AGENTS.md READY', tone: 'good' }),
    checks: [
      { titleKey: 'wizard.chk.agents.1.t', detailKey: 'wizard.chk.agents.1.d' },
      { titleKey: 'wizard.chk.agents.2.t', detailKey: 'wizard.chk.agents.2.d' }
    ],
    codeTitleKey: 'wizard.code.agents',
    code: AGENT_MD_BLUEPRINT,
    isAgentDoc: true
  },
  {
    id: 'allowlist',
    num: '01',
    titleKey: 'wizard.step.allowlist.title',
    subtitleKey: 'wizard.step.allowlist.sub',
    descKey: 'wizard.step.allowlist.desc',
    targetView: 'protection',
    targetTab: '',
    statusFn: s => s.snap?.allowlist_ready
      ? { label: `ALLOWLIST SYNC (${(s.snap?.blocks || []).length})`, tone: 'good' }
      : { label: 'CHECK ALLOWLIST', tone: 'warn' },
    checks: [
      { titleKey: 'wizard.chk.allow.1.t', detailKey: 'wizard.chk.allow.1.d' },
      { titleKey: 'wizard.chk.allow.2.t', detailKey: 'wizard.chk.allow.2.d' }
    ],
    codeTitleKey: 'wizard.code.allow',
    code: `# SSH / Admin connections\nss -tnp | grep ':22'\nwho -a\n\n# Verify active services\nsystemctl status gedefense-core gedefense-control gedefense-access --no-pager`
  },
  {
    id: 'l7',
    num: '02',
    titleKey: 'wizard.step.l7.title',
    subtitleKey: 'wizard.step.l7.sub',
    descKey: 'wizard.step.l7.desc',
    targetView: 'l7',
    targetTab: 'settings',
    statusFn: s => s.snap?.l7?.enabled
      ? { label: String(s.snap.l7.mode || 'active').toUpperCase(), tone: s.snap.l7.mode === 'enforce' ? 'good' : 'warn' }
      : { label: 'DISABLED', tone: 'muted' },
    checks: [
      { titleKey: 'wizard.chk.l7.1.t', detailKey: 'wizard.chk.l7.1.d' },
      { titleKey: 'wizard.chk.l7.2.t', detailKey: 'wizard.chk.l7.2.d' }
    ],
    codeTitleKey: 'wizard.code.l7',
    code: `# NGINX /etc/nginx/conf.d/gedefense-l7.conf\nlocation = /_vgt_l7_auth {\n    internal;\n    proxy_pass http://unix:/run/gedefense/l7.sock:/check;\n    proxy_pass_request_body off;\n    proxy_set_header Content-Length "";\n    proxy_set_header X-Original-URI $request_uri;\n    proxy_set_header X-Real-IP $remote_addr;\n}`
  },
  {
    id: 'web-tls',
    num: '03',
    titleKey: 'wizard.step.webtls.title',
    subtitleKey: 'wizard.step.webtls.sub',
    descKey: 'wizard.step.webtls.desc',
    targetView: 'web-exposure',
    targetTab: 'settings',
    statusFn: s => {
      const cap = s.tls?.capture === 'active';
      const srv = Number(s.exposure?.summary?.servers || 0);
      return cap ? { label: `TLS ACTIVE · ${srv} WEB`, tone: 'good' } : { label: `${srv} WEB · TLS ${s.tls?.capture || 'off'}`, tone: 'warn' };
    },
    checks: [
      { titleKey: 'wizard.chk.webtls.1.t', detailKey: 'wizard.chk.webtls.1.d' },
      { titleKey: 'wizard.chk.webtls.2.t', detailKey: 'wizard.chk.webtls.2.d' },
      { titleKey: 'wizard.chk.webtls.3.t', detailKey: 'wizard.chk.webtls.3.d' }
    ],
    codeTitleKey: 'wizard.code.webtls',
    code: `# Capture helper (CAP_NET_RAW + CAP_NET_ADMIN)\nsystemctl status gedefense-capture-helper --no-pager\nss -xp | grep capture.sock || true\n\n# Listening web ports\nss -tulpn | grep -E ':(80|443|8080|8188|8289|8443)\\b'`
  },
  {
    id: 'lpe-edge',
    num: '04',
    titleKey: 'wizard.step.lpeedge.title',
    subtitleKey: 'wizard.step.lpeedge.sub',
    descKey: 'wizard.step.lpeedge.desc',
    targetView: 'lpe-guard',
    targetTab: 'settings',
    statusFn: s => {
      const lpeOn = Boolean(s.lpe?.enabled);
      const edgeRun = s.edge?.state === 'running';
      return { label: `LPE ${lpeOn ? 'ON' : 'OFF'} · EDGE ${edgeRun ? 'RUN' : 'OFF'}`, tone: lpeOn ? 'good' : 'muted' };
    },
    checks: [
      { titleKey: 'wizard.chk.lpe.1.t', detailKey: 'wizard.chk.lpe.1.d' },
      { titleKey: 'wizard.chk.lpe.2.t', detailKey: 'wizard.chk.lpe.2.d' }
    ],
    codeTitleKey: 'wizard.code.lpe',
    code: `# Kernel ASLR & LPE socket modules\nsysctl kernel.randomize_va_space\nlsmod | grep -E 'sctp|dccp|rds|tipc' || echo "clean"\n\n# Port conflict check for Edge Proxy\nss -ltn | grep -E ':(8443|8080)\\b' || echo "Ports 8443 & 8080 free"`
  },
  {
    id: 'kinetic-feeds',
    num: '05',
    titleKey: 'wizard.step.kinetic.title',
    subtitleKey: 'wizard.step.kinetic.sub',
    descKey: 'wizard.step.kinetic.desc',
    targetView: 'kinetic',
    targetTab: 'settings',
    statusFn: s => {
      const mode = s.snap?.kinetic?.ingress_mode || 'offline';
      const vectors = Number(s.snap?.feed_vectors || 0);
      return { label: `${mode.toUpperCase()} · ${vectors} FEEDS`, tone: s.snap?.core_connected ? 'good' : 'warn' };
    },
    checks: [
      { titleKey: 'wizard.chk.kin.1.t', detailKey: 'wizard.chk.kin.1.d' },
      { titleKey: 'wizard.chk.kin.2.t', detailKey: 'wizard.chk.kin.2.d' }
    ],
    codeTitleKey: 'wizard.code.kin',
    code: `ip -d link show | grep -E '^[0-9]+:|xdp'\nbpftool prog show | grep -i gedefense || true`
  },
  {
    id: 'xdr-styx-titan',
    num: '06',
    titleKey: 'wizard.step.xdr.title',
    subtitleKey: 'wizard.step.xdr.sub',
    descKey: 'wizard.step.xdr.desc',
    targetView: 'styx',
    targetTab: 'settings',
    statusFn: s => {
      const styx = s.styx?.sensor_state || 'off';
      const titan = s.titanExec?.state || 'off';
      return { label: `STYX ${styx.toUpperCase()} · TITAN ${titan.toUpperCase()}`, tone: styx === 'active' ? 'good' : 'warn' };
    },
    checks: [
      { titleKey: 'wizard.chk.xdr.1.t', detailKey: 'wizard.chk.xdr.1.d' },
      { titleKey: 'wizard.chk.xdr.2.t', detailKey: 'wizard.chk.xdr.2.d' },
      { titleKey: 'wizard.chk.xdr.3.t', detailKey: 'wizard.chk.xdr.3.d' }
    ],
    codeTitleKey: 'wizard.code.xdr',
    code: `systemctl status nginx php*-fpm mariadb --no-pager 2>/dev/null | head -n 40`
  },
  {
    id: 'cells-fim',
    num: '07',
    titleKey: 'wizard.step.cells.title',
    subtitleKey: 'wizard.step.cells.sub',
    descKey: 'wizard.step.cells.desc',
    targetView: 'integrity',
    targetTab: '',
    statusFn: s => {
      const health = s.snap?.fim?.health || 'unknown';
      return { label: `FIM ${String(health).toUpperCase()}`, tone: health === 'verified' ? 'good' : 'warn' };
    },
    checks: [
      { titleKey: 'wizard.chk.cells.1.t', detailKey: 'wizard.chk.cells.1.d' },
      { titleKey: 'wizard.chk.cells.2.t', detailKey: 'wizard.chk.cells.2.d' }
    ],
    codeTitleKey: 'wizard.code.cells',
    code: `systemctl status gedefense-cell-helper --no-pager\nsysctl kernel.kptr_restrict kernel.dmesg_restrict fs.protected_symlinks`
  },
  {
    id: 'witness-lockdown',
    num: '08',
    titleKey: 'wizard.step.witness.title',
    subtitleKey: 'wizard.step.witness.sub',
    descKey: 'wizard.step.witness.desc',
    targetView: 'witness',
    targetTab: 'settings',
    statusFn: s => {
      const w = s.witness?.healthy ? 'WITNESS OK' : 'WITNESS OFF';
      const l = s.lockdown?.armed ? 'LOCKDOWN ARMED' : 'LOCKDOWN IDLE';
      return { label: `${w} · ${l}`, tone: s.witness?.healthy ? 'good' : 'muted' };
    },
    checks: [
      { titleKey: 'wizard.chk.wit.1.t', detailKey: 'wizard.chk.wit.1.d' },
      { titleKey: 'wizard.chk.wit.2.t', detailKey: 'wizard.chk.wit.2.d' },
      { titleKey: 'wizard.chk.wit.3.t', detailKey: 'wizard.chk.wit.3.d' }
    ],
    codeTitleKey: 'wizard.code.wit',
    code: `systemctl is-active gedefense-core gedefense-control gedefense-access gedefense-capture-helper\ncurl -sk https://127.0.0.1:9843/gateway/livez`
  }
];

const wizardState = {
  stepIndex: 0,
  live: null,
  bound: false
};

const byId = id => document.getElementById(id);

function makeEl(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== '' && text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

function isDismissed() {
  try {
    return globalThis.localStorage?.getItem(STORAGE_DISMISSED) === '1';
  } catch (_) {
    return false;
  }
}

function setDismissed(flag) {
  try {
    if (flag) globalThis.localStorage?.setItem(STORAGE_DISMISSED, '1');
    else globalThis.localStorage?.removeItem(STORAGE_DISMISSED);
  } catch (_) { /* ignore private storage errors */ }
  const banner = byId('overviewFirstRunWizard');
  if (banner) banner.hidden = Boolean(flag);
}

async function copyText(text, successKey) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast(t(successKey), 'good');
  } catch (_) {
    toast(t('wizard.copyFailed'), 'warning');
  }
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function fetchLiveState() {
  const settled = await Promise.allSettled([
    api('/api/v1/status'),
    api('/api/v1/web-exposure/status'),
    api('/api/v1/tls-sensor/status'),
    api('/api/v1/lpe-guard/status'),
    api('/api/v1/edge-proxy/status'),
    api('/api/v1/styx/status'),
    api('/api/v1/titan/exec/status'),
    api('/api/v1/witness/status'),
    api('/api/v1/lockdown/status')
  ]);
  const pickVal = i => (settled[i]?.status === 'fulfilled' ? settled[i].value : null);
  wizardState.live = {
    snap: pickVal(0),
    exposure: pickVal(1),
    tls: pickVal(2),
    lpe: pickVal(3),
    edge: pickVal(4),
    styx: pickVal(5),
    titanExec: pickVal(6),
    witness: pickVal(7),
    lockdown: pickVal(8)
  };
}

function navigateToTarget(view, tab) {
  const navBtn = document.querySelector(`[data-view="${view}"]`);
  if (navBtn) navBtn.click();
  if (tab === 'settings') {
    setTimeout(() => {
      const section = document.querySelector(`[data-page="${view}"]`);
      const settingsBtn = section?.querySelector('[data-fabric-tab="settings"]');
      if (settingsBtn) settingsBtn.click();
    }, 80);
  }
}

function renderWizard() {
  const nav = byId('wizardStepsNav');
  const main = byId('wizardMainCard');
  if (!nav || !main) return;

  nav.replaceChildren();
  WIZARD_STEPS.forEach((step, idx) => {
    const btn = makeEl('button', `wizard-step-btn${idx === wizardState.stepIndex ? ' active' : ''}`);
    btn.type = 'button';
    btn.append(
      makeEl('span', 'wizard-step-index', step.num),
      makeEl('span', 'wizard-step-label', t(step.titleKey))
    );
    if (wizardState.live) {
      const st = step.statusFn(wizardState.live);
      const dot = makeEl('span', `status-pill ${st.tone}`, idx === 0 ? 'MD' : st.tone === 'good' ? 'OK' : '!');
      btn.append(dot);
    }
    btn.addEventListener('click', () => {
      wizardState.stepIndex = idx;
      renderWizard();
    });
    nav.append(btn);
  });

  const step = WIZARD_STEPS[wizardState.stepIndex] || WIZARD_STEPS[0];
  main.replaceChildren();

  const header = makeEl('div', 'v61-panel-head');
  const headLeft = document.createElement('div');
  headLeft.append(
    makeEl('p', 'eyebrow m-0', t(step.subtitleKey)),
    makeEl('h3', 'm-0 mt-xs', `${step.num} · ${t(step.titleKey)}`),
    makeEl('p', 'fs-sm text-muted mt-xs', t(step.descKey))
  );
  const headRight = makeEl('div', 'v61-actions');
  if (wizardState.live) {
    const st = step.statusFn(wizardState.live);
    headRight.append(makeEl('span', `status-pill ${st.tone}`, st.label));
  }
  if (step.targetView && step.targetView !== 'overview') {
    const jumpBtn = makeEl('button', 'button button-primary', t('wizard.openModule'));
    jumpBtn.type = 'button';
    jumpBtn.addEventListener('click', () => navigateToTarget(step.targetView, step.targetTab));
    headRight.append(jumpBtn);
  }
  header.append(headLeft, headRight);
  main.append(header);

  const list = makeEl('ul', 'wizard-checklist');
  for (const item of step.checks) {
    const li = makeEl('li', 'wizard-check-item');
    const txt = document.createElement('div');
    txt.append(makeEl('strong', '', t(item.titleKey)), makeEl('small', '', t(item.detailKey)));
    li.append(txt);
    list.append(li);
  }
  main.append(list);

  const codeBox = makeEl('div', 'wizard-code-box');
  const codeHead = makeEl('div', 'wizard-code-head');
  codeHead.append(makeEl('span', '', t(step.codeTitleKey)));
  const codeActions = makeEl('div', 'v61-actions');
  const copyBtn = makeEl('button', 'button button-quiet', t('wizard.copyBtn'));
  copyBtn.type = 'button';
  copyBtn.addEventListener('click', () => void copyText(step.code, 'wizard.copied'));
  codeActions.append(copyBtn);
  if (step.isAgentDoc) {
    const dlBtn = makeEl('button', 'button button-secondary', t('wizard.downloadAgents'));
    dlBtn.type = 'button';
    dlBtn.addEventListener('click', () => {
      downloadFile('AGENTS.md', AGENT_MD_BLUEPRINT);
      toast(t('wizard.agentsDownloaded'), 'good');
    });
    const promptBtn = makeEl('button', 'button button-primary', t('wizard.copyAgentPrompt'));
    promptBtn.type = 'button';
    promptBtn.addEventListener('click', () => {
      void copyText(t('wizard.agentPromptBody'), 'wizard.promptCopied');
    });
    codeActions.append(dlBtn, promptBtn);
  }
  codeHead.append(codeActions);
  const pre = makeEl('pre', 'wizard-code-pre', step.code);
  codeBox.append(codeHead, pre);
  main.append(codeBox);

  const footer = makeEl('div', 'wizard-footer-nav');
  const prevBtn = makeEl('button', 'button button-quiet', t('wizard.prevStep'));
  prevBtn.type = 'button';
  prevBtn.disabled = wizardState.stepIndex <= 0;
  prevBtn.addEventListener('click', () => {
    wizardState.stepIndex = Math.max(0, wizardState.stepIndex - 1);
    renderWizard();
  });

  const rightBtns = makeEl('div', 'v61-actions');
  const doneBtn = makeEl('button', 'button button-quiet', t('wizard.markComplete'));
  doneBtn.type = 'button';
  doneBtn.addEventListener('click', () => {
    setDismissed(true);
    toast(t('wizard.completedToast'), 'good');
  });

  const nextBtn = makeEl('button', 'button button-primary', wizardState.stepIndex >= WIZARD_STEPS.length - 1 ? t('wizard.finishBtn') : t('wizard.nextStep'));
  nextBtn.type = 'button';
  nextBtn.addEventListener('click', () => {
    if (wizardState.stepIndex < WIZARD_STEPS.length - 1) {
      wizardState.stepIndex += 1;
      renderWizard();
    } else {
      setDismissed(true);
      toast(t('wizard.completedToast'), 'good');
      navigateToTarget('overview', '');
    }
  });
  rightBtns.append(doneBtn, nextBtn);
  footer.append(prevBtn, rightBtns);
  main.append(footer);
}

export async function loadSetupWizard() {
  renderWizard();
  await fetchLiveState();
  renderWizard();
}

export function initSetupWizard() {
  if (wizardState.bound) return;
  wizardState.bound = true;

  const firstRunBanner = byId('overviewFirstRunWizard');
  if (firstRunBanner) firstRunBanner.hidden = isDismissed();

  byId('firstRunLaunchWizardBtn')?.addEventListener('click', () => {
    wizardState.stepIndex = 0;
    navigateToTarget('setup-wizard', '');
  });
  byId('firstRunDismissWizardBtn')?.addEventListener('click', () => {
    setDismissed(true);
  });
  byId('heroWizardBtn')?.addEventListener('click', () => {
    navigateToTarget('setup-wizard', '');
  });
  byId('wizardRefreshBtn')?.addEventListener('click', () => void loadSetupWizard());
  byId('wizardDownloadAgentsTopBtn')?.addEventListener('click', () => {
    downloadFile('AGENTS.md', AGENT_MD_BLUEPRINT);
    toast(t('wizard.agentsDownloaded'), 'good');
  });
  byId('wizardResetBannerBtn')?.addEventListener('click', () => {
    setDismissed(false);
    toast(t('wizard.bannerRestored'), 'good');
  });

  document.addEventListener('gedefense:language', () => {
    const view = document.querySelector('[data-page="setup-wizard"]');
    if (view && !view.hidden) renderWizard();
  });
}
