// STATUS: DIAMANT VGT SUPREME
'use strict';

import { getL7Findings, getStatus } from './api.js';
import { t } from './i18n.js';
import { byID, el, formatTime, text } from './render.js';

let selectedFinding = null;

export function initL7Module() {
  const drawer = byID('l7FindingDrawer');
  const closeBtn = byID('btnCloseL7Drawer');
  if (closeBtn && drawer) {
    closeBtn.addEventListener('click', () => closeFindingDrawer());
  }

  // Close drawer on Escape key
  document.addEventListener('keydown', evt => {
    if (evt.key === 'Escape' && drawer && !drawer.hidden) {
      closeFindingDrawer();
    }
  });

  const backdrop = byID('l7DrawerBackdrop');
  if (backdrop) {
    backdrop.addEventListener('click', () => closeFindingDrawer());
  }
}

export async function loadL7View(snap) {
  let snapshot = snap;
  if (!snapshot) {
    try {
      snapshot = await getStatus();
    } catch (_) {
      return;
    }
  }

  renderL7StatusHeader(snapshot);
  renderL7EffectiveBlocking(snapshot);
  renderL7KPIs(snapshot);

  try {
    const data = await getL7Findings(50);
    renderL7FindingsTable(data.findings || []);
    renderL7ThreatCategories(data.findings || []);
  } catch (err) {
    // Graceful fallback using snapshot incidents if endpoint fails
    const l7Incidents = (snapshot.incidents || []).filter(
      inc => inc.request_id || inc.http_host || String(inc.decision || '').startsWith('deny-http')
    );
    renderL7FindingsTable(l7Incidents);
    renderL7ThreatCategories(l7Incidents);
  }
}

function renderL7StatusHeader(snapshot) {
  const l7 = snapshot.l7 || {};

  text('l7StatusEngine', l7.healthy ? 'HEALTHY' : (l7.enabled ? 'DEGRADED' : 'DISABLED'));
  const enginePill = byID('l7StatusEnginePill');
  if (enginePill) {
    enginePill.className = `status-pill ${l7.healthy ? 'good' : (l7.enabled ? 'danger' : 'muted')}`;
  }

  text('l7StatusMode', (l7.mode || 'observe').toUpperCase());
  text('l7StatusInline', l7.inline_enabled ? (l7.inline_healthy ? 'ACTIVE' : 'ERROR') : 'INACTIVE');
  const inlinePill = byID('l7StatusInlinePill');
  if (inlinePill) {
    inlinePill.className = `status-pill ${l7.inline_enabled ? (l7.inline_healthy ? 'good' : 'danger') : 'muted'}`;
  }

  text('l7StatusSocket', l7.socket || '---');
  text('l7StatusLastInspection', l7.last_inspection ? formatTime(l7.last_inspection) : '---');
}

function renderL7EffectiveBlocking(snapshot) {
  const l7 = snapshot.l7 || {};
  const rel = snapshot.release || {};
  const globalPhase = String(rel.phase || 'observe').toLowerCase();

  const titleEl = byID('l7EffectiveTitle');
  const descEl = byID('l7EffectiveDesc');
  const pillEl = byID('l7EffectivePill');

  if (!l7.enabled) {
    if (titleEl) titleEl.textContent = 'Application Defense deaktiviert';
    if (descEl) descEl.textContent = 'L7-Inspektion ist in der Konfiguration deaktiviert.';
    if (pillEl) { pillEl.textContent = 'DISABLED'; pillEl.className = 'status-pill muted'; }
    return;
  }

  if (l7.mode === 'block') {
    if (globalPhase === 'canary' || globalPhase === 'enforce') {
      if (titleEl) titleEl.textContent = 'Effektives Blockieren: AKTIV';
      if (descEl) descEl.textContent = t('l7.effective.active');
      if (pillEl) { pillEl.textContent = 'ACTIVE'; pillEl.className = 'status-pill good'; }
    } else {
      if (titleEl) titleEl.textContent = 'Effektives Blockieren: SUSPENDIERT (Observe)';
      if (descEl) descEl.textContent = t('l7.effective.observe');
      if (pillEl) { pillEl.textContent = 'OBSERVE'; pillEl.className = 'status-pill warn'; }
    }
  } else {
    if (titleEl) titleEl.textContent = 'Effektives Blockieren: DEAKTIVIERT (Observe Modus)';
    if (descEl) descEl.textContent = t('l7.effective.observeConfig');
    if (pillEl) { pillEl.textContent = 'OBSERVE'; pillEl.className = 'status-pill muted'; }
  }
}

function renderL7KPIs(snapshot) {
  const l7 = snapshot.l7 || {};

  text('l7KpiInspected', Number(l7.requests_total || 0).toLocaleString());
  text('l7KpiFindings', Number(l7.findings_total || 0).toLocaleString());
  text('l7KpiBlocked', Number(l7.blocked_total || 0).toLocaleString());
  text('l7KpiRateLimited', Number(l7.rate_limited_total || 0).toLocaleString());
  text('l7KpiRejected', Number(l7.rejected_total || 0).toLocaleString());
  text('l7KpiResponseFindings', Number(l7.response_findings_total || 0).toLocaleString());

  text('l7SecActiveConnections', String(l7.active_connections || 0));
  text('l7SecUpstreamErrors', String(l7.inline_upstream_errors_total || 0));
  text('l7SecResponseErrors', String(l7.response_inspection_errors_total || 0));

  // Overview quick-card metrics
  text('overviewL7Inspected', Number(l7.requests_total || 0).toLocaleString());
  text('overviewL7Findings', Number(l7.findings_total || 0).toLocaleString());
  text('overviewL7Blocked', Number(l7.blocked_total || 0).toLocaleString());
}

function renderL7ThreatCategories(findings = []) {
  const root = byID('l7CategoryPills');
  if (!root) return;

  const counts = new Map();
  for (const f of findings) {
    const cats = f.categories || [];
    for (const cat of cats) {
      counts.set(cat, (counts.get(cat) || 0) + 1);
    }
  }

  if (counts.size === 0) {
    const empty = el('span', 'empty-tag', 'Noch keine Bedrohungen festgestellt');
    root.replaceChildren(empty);
    return;
  }

  const badges = Array.from(counts.entries()).map(([cat, count]) => {
    const tag = el('div', 'threat-category-tag');
    const name = el('span', 'cat-name', cat.toUpperCase());
    const cnt = el('span', 'cat-count', String(count));
    tag.append(name, cnt);
    return tag;
  });

  root.replaceChildren(...badges);
}

function renderL7FindingsTable(findings = []) {
  const root = byID('l7FindingsTableBody');
  if (!root) return;

  if (findings.length === 0) {
    const tr = el('tr');
    const td = el('td', 'empty-cell', t('l7.findings.empty'));
    td.colSpan = 8;
    tr.append(td);
    root.replaceChildren(tr);
    return;
  }

  const rows = findings.map(f => {
    const tr = el('tr', 'clickable-row');
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', `Finding ${f.rule_ids?.[0] || 'L7'} at ${f.path || '/'}`);

    const tdTime = el('td', 'mono', formatTime(f.time));
    const tdSev = el('td');
    const sevPill = el('span', `severity-badge ${f.severity || 'info'}`, (f.severity || 'info').toUpperCase());
    tdSev.append(sevPill);

    const tdScore = el('td', 'mono score-cell', `${f.score || 0} (${f.confidence || 0}%)`);
    const tdTarget = el('td', 'mono');
    tdTarget.textContent = `${f.method || 'REQ'} ${f.host || ''}${f.path || '/'}`;

    const tdIP = el('td', 'mono', f.remote_ip || f.remote || '---');
    const tdCategory = el('td');
    const catText = (f.categories || []).join(', ') || 'general';
    tdCategory.textContent = catText;

    const tdAction = el('td');
    const actionPill = el('span', f.action === 'deny-request' || f.decision === 'deny-http' ? 'status-pill danger' : 'status-pill muted');
    actionPill.textContent = (f.action || f.decision || 'observed').toUpperCase();
    tdAction.append(actionPill);

    const tdDetail = el('td');
    const btn = el('button', 'button button-quiet compact', 'Details');
    btn.type = 'button';
    btn.addEventListener('click', evt => {
      evt.stopPropagation();
      openFindingDrawer(f);
    });
    tdDetail.append(btn);

    tr.append(tdTime, tdSev, tdScore, tdTarget, tdIP, tdCategory, tdAction, tdDetail);
    tr.addEventListener('click', () => openFindingDrawer(f));
    tr.addEventListener('keydown', evt => {
      if (evt.key === 'Enter' || evt.key === ' ') {
        evt.preventDefault();
        openFindingDrawer(f);
      }
    });

    return tr;
  });

  root.replaceChildren(...rows);
}

export function openFindingDrawer(finding) {
  selectedFinding = finding;
  const drawer = byID('l7FindingDrawer');
  const backdrop = byID('l7DrawerBackdrop');
  if (!drawer) return;

  // Header & Severity
  text('drawerFindingRule', finding.rule_ids?.[0] || 'L7.THREAT.DETECTED');
  text('drawerFindingSummary', finding.summary || 'Bedrohung im HTTP-Datenstrom identifiziert.');

  const sevEl = byID('drawerFindingSeverity');
  if (sevEl) {
    sevEl.textContent = (finding.severity || 'info').toUpperCase();
    sevEl.className = `severity-badge ${finding.severity || 'info'}`;
  }

  text('drawerFindingScore', String(finding.score || 0));
  text('drawerFindingConfidence', `${finding.confidence || 0}%`);

  // Metadata
  text('drawerReqMethod', finding.method || finding.http_method || '---');
  text('drawerReqHost', finding.host || finding.http_host || '---');
  text('drawerReqPath', finding.path || finding.http_path || '---');
  text('drawerReqRemote', finding.remote_ip || finding.remote || '---');
  text('drawerReqID', finding.request_id || '---');
  text('drawerReqBodySHA', finding.body_sha256 || '---');

  // Decision & Action
  text('drawerDecision', finding.decision || 'observed');
  text('drawerAction', finding.action || 'none');
  text('drawerOutcome', finding.outcome || 'Keine destruktive Aktion ausgeführt.');

  // Attack Story / Correlation
  renderDrawerAttackStory(finding.attack_story || []);

  drawer.hidden = false;
  if (backdrop) backdrop.hidden = false;
  requestAnimationFrame(() => {
    drawer.classList.add('is-open');
    if (backdrop) backdrop.classList.add('is-open');
  });
}

function renderDrawerAttackStory(nodes = []) {
  const root = byID('drawerAttackStoryList');
  if (!root) return;

  if (!nodes.length) {
    const empty = el('div', 'empty-node', 'Keine zusätzliche Host-Korrelation erfasst (L7 Root Cause Isolation).');
    root.replaceChildren(empty);
    return;
  }

  const items = nodes.map((node, idx) => {
    const container = el('div', 'correlation-node');
    const header = el('div', 'node-header');
    const type = el('b', 'node-type', node.event_type || 'EVENT');
    const sev = el('span', `severity-badge ${node.severity || 'info'}`, node.severity || 'info');
    header.append(type, sev);

    const actor = el('div', 'node-actor mono', node.actor || '');
    const entity = el('div', 'node-entity mono', node.entity_id || '');
    const time = el('time', 'node-time', formatTime(node.timestamp));

    container.append(header, actor, entity, time);
    return container;
  });

  root.replaceChildren(...items);
}

export function closeFindingDrawer() {
  const drawer = byID('l7FindingDrawer');
  const backdrop = byID('l7DrawerBackdrop');
  if (!drawer) return;

  drawer.classList.remove('is-open');
  if (backdrop) backdrop.classList.remove('is-open');
  setTimeout(() => {
    drawer.hidden = true;
    if (backdrop) backdrop.hidden = true;
  }, 220);
}
