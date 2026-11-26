// STATUS: DIAMANT VGT SUPREME
'use strict';

// GeDefense 6.3.0 — Guided First-Start Setup Wizard & Offline AGENTS.md Blueprint.
// Security invariant: never exposes or simulates any remote AI control API.
// All recommendations are rendered statically or derived from read-only status APIs.
import { api } from './api.js';
import { t } from './i18n.js';
import { toast } from './render.js';

const STORAGE_DISMISSED = 'vgt.gedefense.wizard.dismissed.v63';
const STORAGE_DISMISSED_LEGACY = 'vgt.gedefense.wizard.dismissed.v61';

const AGENT_MD_BLUEPRINT = `# AGENTS.md — Autonomous Host Onboarding & Hardening Guide for GeDefense 6.3.0

> **Security Model:** GeDefense V6.3.0 deliberately exposes **NO** inbound AI control channel or prompt API.
> An administrator runs a trusted CLI coding agent (Codex, Antigravity, Claude Code) directly via SSH
> or locally on a hardened workstation/laptop with host operator privileges, inspects the machine read-only
> first, tunes every module cleanly for **Server** or **Desktop/Workstation** workloads via the local
> control plane (\`/api/v1/settings/{module}\` preview -> apply), and verifies every protection plane before Enforce.

---

## Phase 1 · Read-Only Host, Kernel & Role Discovery
Run these commands first. Identify whether the target is a **Server** (NGINX/Apache/Caddy/Docker/DB) or **Desktop/Workstation** (Wayland/X11/browsers/dev toolchains/Flatpak). Do NOT mutate firewall or service state yet:
\`\`\`bash
uname -a
ldd --version 2>/dev/null || true
file /opt/vgt/gedefense/bin/gedefense-core 2>/dev/null || file /usr/local/bin/gedefense-core 2>/dev/null || true
ss -tulpn
ps -eo pid,ppid,user:16,comm,args --sort=comm | head -n 120
systemctl list-units --type=service --state=running
ls -la /etc/nginx/ /www/server/nginx/conf/ /www/server/panel/vhost/nginx/ 2>/dev/null || true
ls -la /etc/systemd/system/gedefense*
systemctl status gedefense-core gedefense-capture-helper gedefense-cell-helper gedefense-control gedefense-access --no-pager
bpftool feature probe kernel 2>/dev/null | head -n 40 || true
cat /sys/kernel/security/lsm 2>/dev/null || true
\`\`\`

---

## Phase 2 · Query Live GeDefense V6.3.0 State (Read-Only)
Authenticate locally against \`127.0.0.1\` or \`/run/vgt-gedefense/\` using the operator token (note: V6.3.0 enforces RBAC Observer vs Operator vs Critical Step-Up + Gateway HMAC binding) and inspect EVERY protection surface:
- \`GET /api/v1/status\` (Release phase, \`ui_build\`, Core connection, XDR/L7/FIM health, Coverage, Protection gaps)
- \`GET /api/v1/overview/situation\` (Correlated host threat verdict across 6 planes)
- \`GET /api/v1/antispyware/status\` (**NEW V6.3.0 Unified Antispyware Telemetry:** \`self_guard\`, \`exec_inode\`, \`bpf_guard\`, \`cross_view\`, \`kernel_hooks\`, \`persistence\`, \`dns\`, \`styx_phase2\`, \`sbc_fusion\`, \`sec_crit\`, \`credential_guard\`, \`ransom\`, \`titan_exec\`, \`chameleon\`, \`lpe_guard\`)
- \`GET /api/v1/xdr/sbc\`, \`GET /api/v1/xdr/sec-crit\`, \`GET /api/v1/xdr/permits\`, \`GET /api/v1/xdr/review\`
- \`GET /api/v1/chameleon/status\` (Verify standard vs opt-in Chameleon install identity + BPF pin root)
- \`GET /api/v1/web-exposure/status\` & \`GET /api/v1/worker-guard/status\` & \`GET /api/v1/tls-sensor/status\`
- \`GET /api/v1/lpe-guard/status\` (\`mode\`: \`disabled|observe|enforce\`, \`capability\`: \`inactive|active\`, \`socket_policy\`, \`styx_profile\`)
- \`GET /api/v1/edge-proxy/status\` (Check listener \`:8443\` vs existing services before enabling!)
- \`GET /api/v1/styx/status\` & \`/api/v1/styx/beacons\` & \`GET /api/v1/titan/exec/status\` & \`GET /api/v1/parser-cells/status\`
- \`GET /api/v1/boot-trust\`, \`GET /api/v1/hardening/posture\`, \`GET /api/v1/fim\`, \`GET /api/v1/witness/status\`, \`GET /api/v1/lockdown/status\`
- \`GET /api/v1/settings/schema\` (Schema, bounds & defaults for every administrable namespace)

---

## Phase 3 · V6.3.0 Architecture & Antispyware Decision Matrix (Server vs Desktop)
Understand which layers co-activate and what they trigger before switching Release to \`enforce\`:
1. **Management Allowlist & RBAC Step-Up (MANDATORY FIRST):**
   - Add SSH/admin/monitoring IPs to \`POST /api/v1/allowlist\` BEFORE switching \`canary\` -> \`enforce\`.
   - Critical mutations (\`/api/v1/xdr/permits\`, \`/api/v1/quarantine/prune\`, \`/api/v1/chameleon/reveal\`, \`/api/v1/xdr/update-window/override\`) require an Operator password Step-Up proof (\`POST /gateway/step-up\` or \`POST /api/v1/auth/step-up\`). Never disable pinned release manifest verification (\`/etc/vgt/gedefense/release-public.key\`) during upgrades.
2. **AP-0 Core Self-Protection & Static musl Binary:**
   - Ensure \`gedefense-core\` is statically linked (musl, immune to \`LD_PRELOAD\` Symbiote/OrBit hooks) and \`self_guard\` shows \`bpffs_ok=true\`, \`pins_ok=true\`, \`canary_ok=true\`. Any unlinked BPF pin or tampered self-daemon inode fires \`XDR.SELF_TAMPER\` (\`SBC-EVID-08\`).
3. **AP-1 BTF \`exec_inode\` + CredentialGuard + \`PermitV1\`:**
   - Verify \`exec_inode\` BTF offsets match the kernel. Under \`enforce\`, **CredentialGuard** co-activates to deny unauthorized reads of \`/etc/shadow\`, SSH private keys, and runtime secrets with kernel \`-EACCES\` based on real \`(dev, inode, ctime)\` (immune to \`argv[0]\`/\`comm\` spoofing).
   - For legitimate backup/monitoring agents needing secret access, inspect \`GET /api/v1/xdr/review\` and issue scoped signed \`PermitV1\` objects (\`POST /api/v1/xdr/permits\`), NEVER disable CredGuard globally.
4. **AP-2 \`BPF_GUARD\` + AP-4 \`KernelHooks\` (\`io_uring\` / LKM) + AP-3 \`CrossView\` + AP-5 \`PersistenceGuard\`:**
   - These activate automatically with XDR/Core (\`observe\` -> \`enforce\`).
   - \`BPF_GUARD\` audits \`bpf_prog_load\`/\`attach\` & high-risk helpers (\`bpf_probe_write_user\`, \`override_return\`, \`send_signal\`).
   - \`CrossView\` cross-checks 8 kernel vs userland domains (\`tap\`, \`mods\`, \`procs\`, \`bpf\`, \`trace\`, \`pkgdb\`) to expose DKOM/LKM/unlinked ELF hiding.
   - \`PersistenceGuard\` watches \`/etc/ld.so.preload\`, systemd generators/drop-ins, cron, PAM, SSH keys, \`ptrace\`, and \`mmap\`/\`process_vm_writev\`.
5. **AP-6 \`StyX Phase-2\` + \`DNS Capture\` + \`SBC\` Cross-Domain Corroboration:**
   - \`StyX\` combines bidirectional TX+RX eBPF egress/ingress PCR (\`StyxPhase2Report\`), DNS tunneling entropy/NXDOMAIN capture (\`DNSReport\`), and C2 beacon periodicity (\`/api/v1/styx/beacons\`).
   - Always check \`POST /api/v1/settings/styx\` rules before strict block on hosts running VPNs, WireGuard, package mirrors, or telemetry agents.
6. **AP-7 / AP-8 / AP-9 \`Titan Exec\`, \`Parser Cells\`, \`Ransom Sensor\`, \`S12 SEC_CRIT\` & \`Fanotify\`:**
   - **On Servers:** Keep \`l7.mode = "block"\` (once NGINX/Apache \`auth_request\` snippet is wired), \`web_exposure.enabled = true\`, \`worker_guard.enabled = true\` (\`auto_apply_strict = false\` if workers share master cgroup), \`tls_sensor.enabled = true\` on external ports, and \`titan_exec\` / \`parser_cells\` / \`lpe_guard\` tuned to service binaries.
   - **On Desktops / Developer Workstations:** Keep \`l7\` / \`web_exposure\` / \`edge_proxy\` disabled unless hosting services; keep \`fanotify-exec\`, \`AP-0..AP-6\`, \`CredentialGuard\`, \`RansomSensor\`, \`Parser Cells\` (untrusted downloads/docs), and \`LPE Guard\` active, while allowing local IDE/compiler toolchains via \`titan_exec\` observe grace before strict exec blocking.
7. **After Upgrade or Package Update:**
   - Always run \`POST /api/v1/xdr/update-window/override\` (only with signed release manifest verified against pinned public key) OR \`POST /api/v1/fim/baseline\` after authorized updates, and confirm \`GET /api/v1/fim\` shows \`health: "verified"\`.

---

## Phase 4 · Safe Preview -> Apply -> Verify Workflow
1. \`POST /api/v1/settings/{module}/preview\` with current \`revision\`.
2. \`PUT /api/v1/settings/{module}\` after reviewing diff & warnings.
3. Verify \`GET /api/v1/status\`, \`GET /api/v1/antispyware/status\`, and \`GET /api/v1/overview/situation\` show zero unintended degradations before promoting \`observe -> canary -> enforce\`.
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
    statusFn: s => {
      const l7 = s.snap?.l7;
      if (!l7?.enabled) return { label: 'DISABLED', tone: 'muted' };
      const mode = String(l7.mode || 'observe').toLowerCase();
      const blocking = mode === 'block' || mode === 'enforce';
      const healthy = l7.healthy !== false;
      return {
        label: String(l7.mode || 'active').toUpperCase(),
        tone: blocking && healthy ? 'good' : 'warn'
      };
    },
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
      const srv = Number(s.exposure?.summary?.servers ?? (Array.isArray(s.exposure?.servers) ? s.exposure.servers.length : 0));
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
      const lpeMode = String(s.lpe?.mode || '').toLowerCase();
      const lpeCap = String(s.lpe?.capability || '').toLowerCase();
      const lpeOn = (lpeMode === 'enforce' || lpeMode === 'observe') && lpeCap === 'active';
      const lpeDegraded = (lpeMode === 'enforce' || lpeMode === 'observe') && !lpeOn;
      const edgeRun = s.edge?.state === 'running';
      const lpeLabel = lpeOn
        ? `LPE ${lpeMode.toUpperCase()}`
        : lpeDegraded
          ? 'LPE WAIT'
          : 'LPE OFF';
      return {
        label: `${lpeLabel} · EDGE ${edgeRun ? 'RUN' : 'OFF'}`,
        tone: lpeOn ? 'good' : lpeDegraded ? 'warn' : 'muted'
      };
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
      const styx = String(s.styx?.sensor_state || 'off');
      const titan = String(s.titanExec?.state || 'off');
      const styxOk = styx === 'active';
      const titanOk = titan === 'applied' || titan === 'inactive' || titan === 'active';
      return {
        label: `STYX ${styx.toUpperCase()} · TITAN ${titan.toUpperCase()}`,
        tone: styxOk && titanOk ? 'good' : 'warn'
      };
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
      return { label: `FIM ${String(health).toUpperCase()}`, tone: String(health).toLowerCase() === 'verified' ? 'good' : 'warn' };
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
      const w = s.witness?.healthy ? 'WITNESS OK' : s.witness?.enabled ? 'WITNESS WAIT' : 'WITNESS OFF';
      const l = (s.lockdown?.armed || s.lockdown?.latched) ? 'LOCKDOWN ARMED' : 'LOCKDOWN IDLE';
      const good = Boolean(s.witness?.healthy) || Boolean(s.lockdown?.armed);
      return { label: `${w} · ${l}`, tone: good ? 'good' : 'muted' };
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
    return globalThis.localStorage?.getItem(STORAGE_DISMISSED) === '1'
      || globalThis.localStorage?.getItem(STORAGE_DISMISSED_LEGACY) === '1';
  } catch (_) {
    return false;
  }
}

function setDismissed(flag) {
  try {
    if (flag) {
      globalThis.localStorage?.setItem(STORAGE_DISMISSED, '1');
    } else {
      globalThis.localStorage?.removeItem(STORAGE_DISMISSED);
      globalThis.localStorage?.removeItem(STORAGE_DISMISSED_LEGACY);
    }
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
