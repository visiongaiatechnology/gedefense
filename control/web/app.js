'use strict';

import {
  acknowledgeIncident,
  addAllowlist,
  addBlock,
  applyTransaction,
  APIError,
  clearEmergencyStop,
  createFIMBaseline,
  deleteBlock,
  exportForensics,
  emergencyStop,
  getProfiles,
  getQuarantine,
  getCases,
  getCells,
  getBootTrust,
  getEvidence,
  getFIM,
  getHardeningPosture,
  getPackageIntegrity,
  getRelease,
  getSettings,
  getStatus,
  getToken,
  getTransactions,
  previewTransaction,
  previewQuarantine,
  previewCellAction,
  removeAllowlist,
  reverseTransaction,
  scanFIM,
  scanMalware,
  scanPackageIntegrity,
  setToken,
  setCaseStatus,
  streamSnapshots,
  syncFeeds,
  transitionRelease,
  updateSettings,
  verifyEvidence
} from './api.js';
import { appendTraffic, drawTraffic } from './charts.js';
import { initializeI18n, locale, setLanguage, t } from './i18n.js';
import {
  badge,
  byID,
  formatRate,
  formatTime,
  formatUptime,
  renderEvents,
  renderIncidents,
  renderProfiles,
  renderReleaseBlockers,
  renderRules,
  text,
  toast
} from './render.js';

let snapshot = null;
let runtimeSettings = null;
let streamController = null;
let pollTimer = 0;
let selectedTransaction = null;

const configurableHardeningControls = new Set([
  'kernel.aslr',
  'kernel.kptr',
  'kernel.dmesg',
  'kernel.ptrace',
  'kernel.bpf',
  'filesystem.protected-links',
  'filesystem.suid-dumps',
  'network.syn-cookies',
  'network.ipv4-redirects',
  'network.ipv6-redirects'
]);

const viewMeta = {
  overview: ['view.overview.eyebrow', 'view.overview.title'],
  hardening: ['view.hardening.eyebrow', 'view.hardening.title'],
  integrity: ['view.integrity.eyebrow', 'view.integrity.title'],
  boot: ['view.boot.eyebrow', 'view.boot.title'],
  xdr: ['view.xdr.eyebrow', 'view.xdr.title'],
  network: ['view.network.eyebrow', 'view.network.title'],
  policy: ['view.policy.eyebrow', 'view.policy.title'],
  forensics: ['view.forensics.eyebrow', 'view.forensics.title'],
  release: ['view.release.eyebrow', 'view.release.title'],
  settings: ['view.settings.eyebrow', 'view.settings.title'],
  system: ['view.system.eyebrow', 'view.system.title']
};

function number(value) {
  return Number(value || 0).toLocaleString(locale());
}

function activateView(name) {
  const selected = Object.prototype.hasOwnProperty.call(viewMeta, name) ? name : 'overview';
  document.querySelectorAll('[data-page]').forEach(page => {
    const active = page.getAttribute('data-page') === selected;
    page.hidden = !active;
    page.classList.toggle('active', active);
  });
  document.querySelectorAll('[data-view]').forEach(button => {
    const active = button.getAttribute('data-view') === selected;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  text('viewEyebrow', t(viewMeta[selected][0]));
  text('viewTitle', t(viewMeta[selected][1]));
  { const url = new URL(location.href); url.hash = selected; history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`); }
  if (selected === 'overview') requestAnimationFrame(() => drawTraffic(byID('trafficChart')));
  if (selected === 'hardening') Promise.all([loadHardening(), loadTransactions()]).catch(handleActionError);
  if (selected === 'integrity') loadIntegrity().catch(handleActionError);
  if (selected === 'boot') loadBootTrust().catch(handleActionError);
  if (selected === 'settings') Promise.all([loadSettings(), loadTransactions()]).catch(handleActionError);
  if (selected === 'forensics') Promise.all([loadQuarantine(), loadCases()]).catch(handleActionError);
  if (selected === 'system') loadCells().catch(handleActionError);
}

function setChecked(id, value) {
  const element = byID(id);
  if (element) element.checked = Boolean(value);
}

function setValue(id, value) {
  const element = byID(id);
  if (element) element.value = value ?? '';
}

function renderAllowlist(items = []) {
  const body = byID('allowlistRows');
  if (!body) return;
  body.replaceChildren();
  if (!items.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 3;
    cell.className = 'empty-row';
    cell.textContent = t('dynamic.noManagement');
    row.append(cell);
    body.append(row);
    return;
  }
  for (const target of items) {
    const row = document.createElement('tr');
    const targetCell = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = target;
    targetCell.append(code);
    const statusCell = document.createElement('td');
    statusCell.textContent = snapshot?.allowlist_ready ? t('dynamic.synced') : t('dynamic.pending');
    const actionCell = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'button button-quiet table-action';
    button.textContent = t('dynamic.remove');
    button.addEventListener('click', async () => {
      try {
        await removeAllowlist(target);
        toast(t('dynamic.managementRemoved'), 'good');
        await loadSettings();
        await refresh();
      } catch (error) {
        handleActionError(error);
      }
    });
    actionCell.append(button);
    row.append(targetCell, statusCell, actionCell);
    body.append(row);
  }
}

const ruleModuleInputs = {
  baseline: 'moduleBaseline',
  command: 'moduleCommand',
  lineage: 'moduleLineage',
  masquerading: 'moduleMasquerading',
  origin: 'moduleOrigin',
  'threat-intel': 'moduleThreatIntel'
};

function renderCustomRules(rules = []) {
  const body = byID('customRuleRows');
  if (!body) return;
  if (!rules.length) {
    const row = document.createElement('tr');
    const message = document.createElement('td');
    message.colSpan = 6;
    message.className = 'empty-row';
    message.textContent = t('dynamic.noCustomRules');
    row.append(message);
    body.replaceChildren(row);
    return;
  }
  const rows = rules.map(rule => {
    const row = document.createElement('tr');
    const values = [rule.id, rule.category, rule.score, rule.pattern];
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '');
      if (value === rule.id || value === rule.pattern) cell.className = 'mono';
      row.append(cell);
    }
    const state = document.createElement('td');
    const stateBadge = document.createElement('span');
    stateBadge.className = `badge ${rule.enabled ? 'badge-good' : 'badge-muted'}`;
    stateBadge.textContent = rule.enabled ? 'ON' : 'OFF';
    state.append(stateBadge);
    const action = document.createElement('td');
    action.className = 'rule-actions';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'button button-quiet table-action';
    toggle.textContent = t(rule.enabled ? 'dynamic.disableAction' : 'dynamic.enableAction');
    toggle.addEventListener('click', async () => {
      try {
        const customRules = (runtimeSettings?.custom_rules || []).map(item =>
          item.id === rule.id ? { ...item, enabled: !item.enabled } : { ...item });
        const saved = await updateSettings(settingsPayload({ custom_rules: customRules }));
        applySettings(saved);
        toast(t('toast.customRuleSaved'), 'good');
      } catch (error) {
        handleActionError(error);
      }
    });
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button button-quiet table-action';
    remove.textContent = t('dynamic.remove');
    remove.addEventListener('click', async () => {
      try {
        const customRules = (runtimeSettings?.custom_rules || []).filter(item => item.id !== rule.id);
        const saved = await updateSettings(settingsPayload({ custom_rules: customRules }));
        applySettings(saved);
        toast(t('toast.customRuleRemoved'), 'good');
      } catch (error) {
        handleActionError(error);
      }
    });
    action.append(toggle, remove);
    row.append(state, action);
    return row;
  });
  body.replaceChildren(...rows);
}

function applySettings(settings) {
  if (!settings) return;
  runtimeSettings = {
    ...settings,
    management_allowlist: [...(settings.management_allowlist || [])],
    enabled_rule_modules: [...(settings.enabled_rule_modules || [])],
    custom_rules: (settings.custom_rules || []).map(rule => ({ ...rule }))
  };
  badge('settingsRevision', t('dynamic.revision', { value: number(settings.revision) }));
  setChecked('settingXdr', settings.xdr_enabled);
  setChecked('settingNetwork', settings.network_sensor_enabled);
  setChecked('settingBehavior', settings.behavior_enabled);
  setChecked('settingFeeds', settings.feeds_enabled);
  setChecked('settingAutoFeeds', settings.auto_feed_sync);
  setChecked('settingAutoDegrade', settings.auto_degrade);
  setValue('settingScan', settings.scan_interval_millis);
  setValue('settingNetworkInterval', settings.network_interval_seconds);
  setValue('settingAlert', settings.alert_score);
  setValue('settingContain', settings.contain_score);
  setValue('settingKill', settings.kill_score);
  const enabledModules = new Set(settings.enabled_rule_modules || Object.keys(ruleModuleInputs));
  for (const [module, input] of Object.entries(ruleModuleInputs)) setChecked(input, enabledModules.has(module));
  renderCustomRules(settings.custom_rules || []);
  renderAllowlist(settings.management_allowlist || []);
}

function settingsPayload(overrides = {}) {
  const modules = Object.entries(ruleModuleInputs)
    .filter(([, input]) => byID(input).checked)
    .map(([module]) => module);
  return {
    revision: runtimeSettings?.revision,
    xdr_enabled: byID('settingXdr').checked,
    network_sensor_enabled: byID('settingNetwork').checked,
    behavior_enabled: byID('settingBehavior').checked,
    feeds_enabled: byID('settingFeeds').checked,
    auto_feed_sync: byID('settingAutoFeeds').checked,
    auto_degrade: byID('settingAutoDegrade').checked,
    scan_interval_millis: Number.parseInt(byID('settingScan').value, 10),
    network_interval_seconds: Number.parseInt(byID('settingNetworkInterval').value, 10),
    alert_score: Number.parseInt(byID('settingAlert').value, 10),
    contain_score: Number.parseInt(byID('settingContain').value, 10),
    kill_score: Number.parseInt(byID('settingKill').value, 10),
    enabled_rule_modules: modules,
    custom_rules: (runtimeSettings?.custom_rules || []).map(rule => ({ ...rule })),
    ...overrides
  };
}

async function loadSettings() {
  const settings = await getSettings();
  applySettings(settings);
  return settings;
}

function selectTransaction(transaction) {
  selectedTransaction = transaction;
  const selection = byID('transactionSelection');
  selection.hidden = false;
  text('selectedTransactionID', transaction.id || '---');
  let plan = t('hardening.planUnavailable');
  if (transaction.plan) {
    try {
      plan = JSON.stringify(transaction.plan, null, 2);
    } catch (_) {
      plan = t('hardening.planUnavailable');
    }
  }
  text('selectedTransactionPlan', plan);
  const reverse = transaction.status === 'applied' || transaction.status === 'recovery_required';
  const prefix = reverse ? 'REVERSE' : 'APPLY';
  const confirmation = byID('transactionConfirmation');
  confirmation.value = '';
  confirmation.placeholder = `${prefix} ${transaction.id}`;
  text('transactionExecute', t(reverse ? 'hardening.reverse' : 'hardening.apply'));
}

function renderTransactions(payload) {
  const healthy = Boolean(payload?.healthy);
  badge(
    'transactionHealth',
    healthy ? t('dynamic.verified') : (payload?.recovery_required ? 'RECOVERY REQUIRED' : t('dynamic.quarantined')),
    healthy ? 'good' : 'danger'
  );
  const body = byID('transactionRows');
  const transactions = Array.isArray(payload?.transactions) ? payload.transactions : [];
  if (!transactions.length) {
    const row = document.createElement('tr');
    const message = document.createElement('td');
    message.colSpan = 6;
    message.className = 'empty-row';
    message.textContent = t('hardening.noTransactions');
    row.append(message);
    body.replaceChildren(row);
    return;
  }
  const rows = transactions.map(transaction => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [transaction.id, 'mono'],
      [transaction.type, 'mono'],
      [transaction.summary, ''],
      [transaction.status, transaction.status === 'applied' ? 'state-good' : transaction.status === 'recovery_required' ? 'state-warn' : ''],
      [formatTime(transaction.created_at), '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '');
      if (className) cell.className = className;
      row.append(cell);
    }
    const action = document.createElement('td');
    if (['previewed', 'applied', 'recovery_required'].includes(transaction.status)) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'button button-quiet table-action';
      button.textContent = t(transaction.status === 'previewed' ? 'hardening.selectApply' : 'hardening.selectReverse');
      button.addEventListener('click', () => selectTransaction(transaction));
      action.append(button);
    }
    row.append(action);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadTransactions() {
  const payload = await getTransactions();
  renderTransactions(payload);
  return payload;
}

async function selectTransactionByID(transactionID) {
  const payload = await getTransactions();
  const transaction = (payload?.transactions || []).find(item => item.id === transactionID);
  if (!transaction) throw new Error(t('quarantine.transactionUnavailable'));
  activateView('settings');
  renderTransactions(payload);
  selectTransaction(transaction);
}

function renderQuarantine(payload) {
  const healthy = Boolean(payload?.healthy);
  badge('quarantineHealth', healthy ? t('dynamic.verified') : t('dynamic.quarantined'), healthy ? 'good' : 'danger');
  const body = byID('quarantineRows');
  const items = Array.isArray(payload?.items) ? payload.items : [];
  if (!items.length) {
    const row = document.createElement('tr');
    const message = document.createElement('td');
    message.colSpan = 6;
    message.className = 'empty-row';
    message.textContent = t('quarantine.empty');
    row.append(message);
    body.replaceChildren(row);
    return;
  }
  const rows = items.map(item => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [item.transaction_id, 'mono'],
      [item.path, 'mono'],
      [item.sha256, 'mono'],
      [`${number(item.size)} B`, 'mono'],
      [item.status, item.status === 'applied' ? 'state-good' : item.status === 'recovery_required' ? 'state-warn' : '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '');
      if (className) cell.className = className;
      row.append(cell);
    }
    const action = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'button button-quiet table-action';
    button.textContent = t(item.status === 'previewed' ? 'hardening.selectApply' : 'hardening.selectReverse');
    button.addEventListener('click', () => {
      selectTransactionByID(item.transaction_id).catch(handleActionError);
    });
    action.append(button);
    row.append(action);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadQuarantine() {
  const payload = await getQuarantine();
  renderQuarantine(payload);
  return payload;
}

function selectCase(record) {
  byID('selectedCaseID').value = record.id || '';
  byID('caseStatus').value = record.status === 'open' ? 'investigating' : record.status;
  byID('caseResolution').value = '';
  byID('caseResolution').focus();
}

function renderCases(payload) {
  const healthy = Boolean(payload?.healthy);
  badge('caseHealth', healthy ? t('dynamic.verified') : t('dynamic.quarantined'), healthy ? 'good' : 'danger');
  const body = byID('caseRows');
  const records = Array.isArray(payload?.cases) ? payload.cases : [];
  if (!records.length) {
    const row = document.createElement('tr');
    const message = document.createElement('td');
    message.colSpan = 7;
    message.className = 'empty-row';
    message.textContent = t('cases.empty');
    row.append(message);
    body.replaceChildren(row);
    return;
  }
  const rows = records.map(record => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [record.id, 'mono'], [record.title, ''], [record.severity, `severity-${record.severity}`],
      [record.occurrence_count, 'mono'], [record.status, record.status === 'resolved' ? 'state-good' : 'state-warn'],
      [formatTime(record.updated_at), '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '');
      if (className) cell.className = className;
      row.append(cell);
    }
    const action = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'button button-quiet table-action';
    button.textContent = t('cases.select');
    button.addEventListener('click', () => selectCase(record));
    action.append(button);
    row.append(action);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadCases() {
  const payload = await getCases();
  renderCases(payload);
  return payload;
}

async function prepareCellAction(cell, action) {
  const reason = byID('cellActionReason').value.trim();
  if (reason.length < 3) throw new Error(t('cells.reasonRequired'));
  const transaction = await previewCellAction({
    uuid: cell.uuid,
    generation: cell.generation,
    cgroup_id: cell.cgroup_id,
    action,
    reason
  });
  await selectTransactionByID(transaction.id);
  toast(t('cells.previewReady'), 'good');
}

function renderCells(payload) {
  const healthy = Boolean(payload?.healthy);
  badge(
    'cellsHealth',
    String(payload?.availability || 'unavailable').toUpperCase(),
    healthy ? 'good' : payload?.enabled ? 'warning' : ''
  );
  const body = byID('cellsRows');
  const cells = Array.isArray(payload?.cells) ? payload.cells : [];
  if (!cells.length) {
    const row = document.createElement('tr');
    const message = document.createElement('td');
    message.colSpan = 7;
    message.className = 'empty-row';
    message.textContent = payload?.availability === 'runtime_not_installed'
      ? t('cells.runtimeMissing')
      : t('cells.empty');
    row.append(message);
    body.replaceChildren(row);
    return;
  }
  const rows = cells.map(cell => {
    const row = document.createElement('tr');
    const guardedNetwork = cell.network_state === 'guarded';
    const networkLabel = guardedNetwork ? t('cells.networkGuarded') : cell.network_state;
    for (const [value, className] of [
      [cell.uuid, 'mono'], [cell.label, ''], [cell.class, ''],
      [cell.state, cell.state === 'running' ? 'state-good' : 'state-warn'],
      [networkLabel, (cell.network_state === 'revoked' || guardedNetwork) ? 'state-warn' : 'state-good'],
      [cell.cgroup_id, 'mono']
    ]) {
      const column = document.createElement('td');
      column.textContent = String(value ?? '');
      if (className) column.className = className;
      row.append(column);
    }
    const actions = document.createElement('td');
    for (const [action, label, allowed] of [
      ['freeze', t('cells.freeze'), cell.state === 'running'],
      ['revoke-network', t('cells.revokeNetwork'), cell.network_state === 'normal']
    ]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'button button-quiet table-action';
      button.textContent = label;
      button.disabled = !allowed;
      button.addEventListener('click', () => {
        prepareCellAction(cell, action).catch(handleActionError);
      });
      actions.append(button);
    }
    row.append(actions);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadCells() {
  const payload = await getCells();
  renderCells(payload);
  return payload;
}

function emptyTable(body, columns, message) {
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = columns;
  cell.className = 'empty-cell';
  cell.textContent = message;
  row.append(cell);
  body.replaceChildren(row);
}

function updateHardeningSelectionCount() {
  const selected = document.querySelectorAll('#hardeningSwitches input[data-runtime-managed="true"]:checked').length;
  text('hardeningSelectionCount', `${selected} AUSGEWÄHLT`);
}

function renderHardeningSwitches(checks) {
  const container = byID('hardeningSwitches');
  if (!checks.length) {
    const message = document.createElement('p');
    message.className = 'empty-state';
    message.textContent = 'Keine Härtungskontrollen verfügbar.';
    container.replaceChildren(message);
    updateHardeningSelectionCount();
    return;
  }
  const controls = checks.map(check => {
    const configurable = configurableHardeningControls.has(String(check.id || ''));
    const protectedState = check.state === 'PROTECTED';
    const row = document.createElement('label');
    row.className = `toggle-row hardening-control ${configurable ? 'runtime-control' : 'platform-control'}`;

    const copy = document.createElement('span');
    const title = document.createElement('b');
    title.textContent = String(check.title || check.id || 'Kontrolle');
    const detail = document.createElement('small');
    detail.textContent = configurable
      ? String(check.recommendation || 'Aktiv, live gemessen und durch GeDefense verwaltet.')
      : `${String(check.evidence || 'Nicht messbar')} · ${String(check.recommendation || 'Plattformkontrolle ohne sichere Laufzeitänderung.')}`;
    const domain = document.createElement('em');
    domain.textContent = configurable ? 'RUNTIME + PERSISTENT' : 'INSTALLATION / BOOT / FIRMWARE';
    copy.append(title, detail, domain);

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = protectedState;
    input.disabled = !configurable || protectedState;
    input.dataset.controlId = String(check.id || '');
    input.dataset.runtimeManaged = String(configurable);
    input.setAttribute('aria-label', String(check.title || check.id || 'Kontrolle'));
    input.addEventListener('change', updateHardeningSelectionCount);
    const switchVisual = document.createElement('i');
    switchVisual.setAttribute('aria-hidden', 'true');
    row.append(copy, input, switchVisual);
    return row;
  });
  container.replaceChildren(...controls);
  updateHardeningSelectionCount();
}

function renderHardening(payload) {
  const score = Math.max(0, Math.min(100, Number(payload?.score || 0)));
  text('hardeningScore', score);
  text('hardeningScoreTitle', String(payload?.level || 'UNAVAILABLE'));
  text('hardeningCollected', payload?.collected_at ? formatTime(payload.collected_at) : 'Keine Messung');
  badge('hardeningLevel', String(payload?.level || 'UNAVAILABLE'), score >= 90 ? 'good' : score >= 50 ? 'warning' : 'danger');
  byID('hardeningScoreRing').style.setProperty('--score', String(score));

  const domains = Array.isArray(payload?.domains) ? payload.domains : [];
  const domainCards = domains.map(domain => {
    const card = document.createElement('article');
    card.className = 'panel posture-domain';
    const header = document.createElement('header');
    const title = document.createElement('h3');
    title.textContent = domain.title || domain.id || 'Domain';
    const value = document.createElement('strong');
    value.textContent = `${Number(domain.score || 0)}%`;
    header.append(title, value);
    const detail = document.createElement('small');
    detail.textContent = `${Number(domain.protected || 0)} von ${Number(domain.total || 0)} Kontrollen vollständig geschützt`;
    const progress = document.createElement('div');
    progress.className = 'progress';
    const bar = document.createElement('i');
    bar.style.width = `${Math.max(0, Math.min(100, Number(domain.score || 0)))}%`;
    progress.append(bar);
    card.append(header, detail, progress);
    return card;
  });
  byID('hardeningDomains').replaceChildren(...domainCards);

  const body = byID('hardeningChecks');
  const checks = Array.isArray(payload?.checks) ? payload.checks : [];
  renderHardeningSwitches(checks);
  if (!checks.length) {
    emptyTable(body, 5, 'Keine Härtungsdaten verfügbar.');
    return;
  }
  const rows = checks.map(check => {
    const row = document.createElement('tr');
    for (const value of [check.domain, check.title]) {
      const cell = document.createElement('td');
      cell.textContent = String(value || '---');
      row.append(cell);
    }
    const state = document.createElement('td');
    state.className = `posture-state ${String(check.state || 'unavailable').toLowerCase()}`;
    state.textContent = String(check.state || 'UNAVAILABLE');
    const evidence = document.createElement('td');
    evidence.textContent = String(check.evidence || '---');
    evidence.className = 'mono';
    const recommendation = document.createElement('td');
    recommendation.textContent = String(check.recommendation || (check.managed ? 'Durch GeDefense transaktional verwaltet.' : 'Keine Maßnahme erforderlich.'));
    row.append(state, evidence, recommendation);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadHardening() {
  const payload = await getHardeningPosture();
  renderHardening(payload);
  return payload;
}

function renderFIM(status) {
  const healthy = status?.health === 'HEALTHY';
  badge('fimHealth', String(status?.health || 'UNAVAILABLE'), healthy ? 'good' : 'danger');
  text('fimBaselineCount', number(status?.baseline_count));
  text('fimGeneration', number(status?.generation));
  const findings = Array.isArray(status?.last_scan?.findings) ? status.last_scan.findings : [];
  text('fimFindings', number(findings.length));
  text('fimRoots', Array.isArray(status?.roots) && status.roots.length ? status.roots.join(' · ') : 'Keine geschützten Pfade geladen');
  const body = byID('fimRows');
  if (!findings.length) {
    emptyTable(body, 5, 'Keine Dateiabweichungen im letzten Scan.');
    return;
  }
  const rows = findings.map(finding => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [finding.status, `posture-state ${String(finding.status || '').toLowerCase()}`],
      [finding.path, 'mono'],
      [finding.size, ''],
      [finding.mode, 'mono'],
      [finding.message, '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

function renderEvidence(payload) {
  const status = payload?.status || payload || {};
  const records = Array.isArray(payload?.records) ? payload.records : [];
  badge('evidenceHealth', status.healthy ? 'VERIFIED' : 'DEGRADED', status.healthy ? 'good' : 'danger');
  text('evidenceRecords', number(status.records));
  text('evidenceBytes', `${number(status.stored_bytes)} B`);
  text('evidenceHead', status.head_hash ? String(status.head_hash).slice(0, 16) : '---');
  text('evidenceKey', status.public_key ? `Ed25519 ${status.public_key}` : 'Signer nicht geladen');
  const body = byID('evidenceRows');
  if (!records.length) {
    emptyTable(body, 6, 'Noch keine authentifizierten Evidence-Records.');
    return;
  }
  const rows = records.map(record => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [record.sequence, 'mono'],
      [formatTime(record.time), ''],
      [record.severity, ''],
      [record.kind, 'mono'],
      [record.source, ''],
      [record.message, '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

function renderPackageIntegrity(status) {
  const clean = Boolean(status?.last_scan) && !status?.running &&
    Number(status?.modified || 0) === 0 && Number(status?.missing || 0) === 0 &&
    Number(status?.errors || 0) === 0;
  const state = status?.running ? 'SCANNT' : clean ? 'VERIFIZIERT' : status?.last_scan ? 'ABWEICHUNG' : 'NICHT GEPRÜFT';
  badge('packageIntegrityHealth', state, status?.running ? 'warning' : clean ? 'good' : 'danger');
  text('packageIntegrityPackages', number(status?.packages));
  text('packageIntegrityFiles', number(status?.files));
  text('packageIntegrityDeviations', number(Number(status?.modified || 0) + Number(status?.missing || 0) + Number(status?.errors || 0)));
  text('packageIntegrityDetail', status?.last_scan ? `Letzter Scan ${formatTime(status.last_scan)}` : 'Pacman-MTREE-Vertrauensbasis');
  const findings = Array.isArray(status?.findings) ? status.findings : [];
  const body = byID('packageIntegrityRows');
  if (!findings.length) {
    emptyTable(body, 3, status?.running ? 'Paketdateien werden kryptografisch geprüft.' : 'Keine Paketabweichungen im letzten Scan.');
    return;
  }
  const rows = findings.map(finding => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [finding.status, `posture-state ${String(finding.status || '').toLowerCase()}`],
      [finding.package, 'mono'],
      [finding.path, 'mono']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value || '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

function renderMalwareProtection() {
  const sensor = String(snapshot?.xdr?.sensor || '');
  const active = Boolean(snapshot?.core_connected) && sensor.includes('fanotify-exec');
  badge('malwareProtectionHealth', active ? 'AKTIV' : 'NICHT VERIFIZIERT', active ? 'good' : 'danger');
  text('malwareRuntime', active ? 'FANOTIFY EXEC GUARD' : 'SENSOR NICHT BEREIT');
  text('malwareSignatures', active ? 'ROOT + FS-VERITY' : 'NICHT VERIFIZIERT');
  text('malwareReleaseGate', active ? 'SCAN + HASH RECHECK' : 'FAIL CLOSED');
  text('malwareProtectionDetail', active
    ? 'Ausführbare Dateien unter /home werden vor dem ersten Befehl geprüft. Browserdownloads bleiben bis zu einem sauberen Verdict in der GaiaCell-Quarantäne.'
    : 'Der aktuelle Snapshot bestätigt den Fanotify-Ereigniskanal nicht. Geschützte Freigaben bleiben gesperrt.');
  return active;
}

function renderMalwareResult(result, path) {
  const clean = result?.state === 'clean';
  const suspicious = result?.state === 'suspicious';
  badge('malwareScanState', String(result?.state || 'unknown').toUpperCase(), clean ? 'good' : suspicious ? 'warning' : 'danger');
  text('malwareResultPath', path || '---');
  text('malwareResultType', result?.classification || '---');
  text('malwareResultSize', `${number(result?.size)} B`);
  text('malwareResultReason', result?.reason || '---');
  text('malwareResultHash', result?.sha256 || '---');
}

async function loadIntegrity() {
  const [fim, evidence, packages] = await Promise.all([getFIM(), getEvidence(), getPackageIntegrity()]);
  renderFIM(fim);
  renderEvidence(evidence);
  renderPackageIntegrity(packages);
  const packageHealthy = !packages?.last_scan ||
    (!packages?.running && Number(packages?.modified || 0) === 0 &&
      Number(packages?.missing || 0) === 0 && Number(packages?.errors || 0) === 0);
  const healthy = fim?.health === 'HEALTHY' && Boolean(evidence?.status?.healthy) && packageHealthy && renderMalwareProtection();
  badge('integrityHealth', healthy ? 'GESCHÜTZT' : 'HANDLUNGSBEDARF', healthy ? 'good' : 'danger');
  return { fim, evidence, packages };
}

function renderBootTrust(report) {
  badge('bootClaim', String(report?.claim_level || 'EVIDENCE ONLY'), report?.astraeaos ? 'good' : 'warning');
  text('bootPlatform', report?.platform || '---');
  text('bootDistro', report?.distro_name || report?.distro_id || '---');
  text('bootGaia', report?.astraeaos ? 'ERKANNT' : 'NICHT ERKANNT');
  text('bootVersion', report?.version_id || '---');
  text('bootSummary', report?.summary || '---');
  text('bootGenerated', report?.generated_at ? formatTime(report.generated_at) : '---');
  const body = byID('bootRows');
  const items = Array.isArray(report?.items) ? report.items : [];
  if (!items.length) {
    emptyTable(body, 5, 'Keine Boot-Evidenz verfügbar.');
    return;
  }
  const rows = items.map(item => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [item.id, 'mono'],
      [item.state, `posture-state ${String(item.state || '').toLowerCase()}`],
      [item.summary, ''],
      [item.source, 'mono'],
      [item.digest || item.evidence || '---', 'mono']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadBootTrust() {
  const report = await getBootTrust();
  renderBootTrust(report);
  return report;
}

function updateSnapshot(data) {
  snapshot = data;
  const xdr = data.xdr || {};
  const policy = data.policy || {};
  const behavior = xdr.behavior || {};
  const release = data.release || {};
  text('versionText', data.version || '2.0.0-beta.1');
  if (data.settings) applySettings(data.settings);
  text('nodeName', data.node_name || 'VGT Node');
  text('uptime', formatUptime(data.uptime_seconds));
  text('blockCount', number((data.blocks || []).length));
  text('feedCount', number(data.feed_vectors));
  text('iface', data.telemetry?.interface || '---');
  text('rxRate', formatRate(data.telemetry?.rx_rate || 0));
  text('txRate', formatRate(data.telemetry?.tx_rate || 0));
  const cpu = Number(data.telemetry?.cpu_percent || 0);
  const memory = Number(data.telemetry?.memory_percent || 0);
  text('cpuText', `${cpu.toFixed(1)}%`);
  text('memText', `${memory.toFixed(1)}%`);
  byID('cpuBar').style.width = `${Math.min(100, Math.max(0, cpu))}%`;
  byID('memBar').style.width = `${Math.min(100, Math.max(0, memory))}%`;
  appendTraffic(Number(data.telemetry?.rx_rate || 0), Number(data.telemetry?.tx_rate || 0));
  drawTraffic(byID('trafficChart'));

  if (data.core_connected) {
    text('coreMetric', t('dynamic.online'));
    text('coreDetail', `XDP ${data.core_mode} · ${t('dynamic.allowlist', { state: data.allowlist_ready ? 'SYNC' : t('dynamic.blocked') })}`);
    text('shieldState', data.enforcement === 'enforce' ? t('dynamic.kernelShield') : t('dynamic.observeFabric'));
    text('coreMode', t('dynamic.authVgt', { mode: data.core_mode }));
  } else {
    text('coreMetric', t('dynamic.offline'));
    text('coreDetail', t('dynamic.controlSafe'));
    text('shieldState', t('dynamic.controlOnly'));
    text('coreMode', t('dynamic.rustOffline'));
  }

  const degraded = Boolean(xdr.degraded) || (data.policy && !policy.verified);
  const nominal = data.core_connected && !degraded;
  badge('systemBadge', nominal ? t('dynamic.nominal') : degraded ? t('dynamic.degraded') : t('dynamic.controlOnly'), nominal ? 'good' : degraded ? 'danger' : 'warning');
  text('sidebarState', nominal ? t('dynamic.nominal') : degraded ? t('dynamic.degraded') : t('dynamic.controlOnly'));
  text('sidebarMode', `${String(data.enforcement || 'observe').toUpperCase()} · ${String(xdr.mode || 'observe').toUpperCase()}`);
  byID('sidebarPulse').className = `status-dot${nominal ? '' : degraded ? ' danger' : ' warning'}`;
  byID('heroPulse').className = byID('sidebarPulse').className;

  text('xdrMetric', xdr.enabled ? (xdr.degraded ? t('dynamic.degraded') : String(xdr.mode || 'observe').toUpperCase()) : t('dynamic.disabled'));
  text('xdrDetail', xdr.degraded ? xdr.degraded_reason || t('dynamic.disabled') : `${xdr.sensor || 'sensor'} · ${t('dynamic.incidents', { value: number(xdr.incidents_total) })}`);
  renderMalwareProtection();
  text('anomalyCount', number(xdr.anomalies_total));
  text('xdrProcesses', number(xdr.processes));
  text('xdrConnections', number(xdr.open_connections));
  text('evaluationCount', number(xdr.evaluations_total));
  text('queueDepth', `${number(xdr.queue_depth)} / ${number(xdr.queue_capacity)}`);
  text('queueDrops', t('dynamic.drops', { value: number(xdr.evaluation_drops) }));
  text('profileCount', number(behavior.profiles));
  text('warmProfiles', t('dynamic.warm', { value: number(behavior.warm_profiles) }));
  badge('xdrModeBadge', String(xdr.mode || 'disabled').toUpperCase(), xdr.degraded ? 'danger' : xdr.mode === 'enforce' ? 'good' : 'warning');
  badge('behaviorIntegrity', behavior.integrity_ok ? t('dynamic.macVerified') : t('dynamic.integrityFailure'), behavior.integrity_ok ? 'good' : 'danger');

  badge('enforcementBadge', String(data.enforcement || 'observe').toUpperCase(), data.enforcement === 'enforce' ? 'good' : 'warning');
  badge('policyBadge', policy.verified ? t('dynamic.signatureVerified') : t('dynamic.signatureFailure'), policy.verified ? 'good' : 'danger');
  text('policySigner', policy.signer || '---');
  text('policyGeneration', number(policy.generation));
  text('policyUpdated', formatTime(policy.updated_at));

  text('incidentIntegrity', xdr.degraded && String(xdr.degraded_reason || '').includes('incident') ? t('dynamic.quarantined') : t('dynamic.verified'));
  text('incidentDetail', xdr.degraded ? xdr.degraded_reason || t('dynamic.degraded') : t('dynamic.hmacChain'));
  text('incidentCount', number(xdr.incidents_total));
  text('actionCount', number(xdr.actions_total));

  badge('nodeModeBadge', String(data.node_mode || 'standalone').toUpperCase());
  text('systemNode', data.node_name || '---');
  text('systemUptime', `${formatUptime(data.uptime_seconds)} · ${data.version || ''}`);
  text('systemCore', data.core_connected ? t('dynamic.online') : t('dynamic.offline'));
  text('systemCoreDetail', data.core_connected ? `XDP ${data.core_mode} · VGT3 HMAC · ${t('dynamic.allowlist', { state: data.allowlist_ready ? 'SYNC' : t('dynamic.blocked') })}` : t('dynamic.safeMode'));
  text('systemXdr', xdr.enabled ? (xdr.degraded ? t('dynamic.degraded') : t('dynamic.online')) : t('dynamic.disabled'));
  text('systemXdrDetail', `${xdr.sensor || '---'} · ${t('dynamic.protectedObjects', { value: number(xdr.protected_objects) })}`);
  text('systemPolicy', policy.verified ? t('dynamic.verified') : t('dynamic.failed'));
  text('systemPolicyDetail', `${policy.signer || t('dynamic.noSigner')} · ${t('dynamic.generation', { value: number(policy.generation) })}`);
  text('systemBehavior', behavior.integrity_ok ? t('dynamic.verified') : t('dynamic.failed'));
  text('systemBehaviorDetail', t('dynamic.profilesWarm', { profiles: number(behavior.profiles), warm: number(behavior.warm_profiles) }));
  text('systemFeeds', number(data.feed_vectors));
  text('systemFeedTime', data.last_feed_sync ? formatTime(data.last_feed_sync) : t('system.notSynced'));

  const releaseReady = Boolean(release.ready);
  badge('releasePhaseBadge', String(release.phase || 'observe').toUpperCase(), release.phase === 'enforce' ? 'good' : release.phase === 'degraded' ? 'danger' : 'warning');
  text('releasePhase', String(release.phase || 'observe').toUpperCase());
  text('releaseSince', release.since ? t('dynamic.since', { time: formatTime(release.since) }) : t('release.startPhase'));
  text('releaseReady', releaseReady ? t('dynamic.ready') : t('dynamic.blocked'));
  text('releaseDetail', release.detail || t('release.gateCheck'));
  text('releaseCoreMisses', number(release.core_misses));
  text('releaseKernelState', String(release.kernel_policy_state || 'unverified').toUpperCase());
  text('releaseFailSafe', release.fail_safe_verified ? t('dynamic.failSafeVerified') : t('dynamic.failSafeUnverified'));
  renderReleaseBlockers(release.blockers || []);

  renderEvents(data.events || []);
  renderRules(data.blocks || [], removeRule);
  renderIncidents(data.incidents || [], acknowledge);
}

async function refresh() {
  try {
    updateSnapshot(await getStatus());
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      badge('systemBadge', t('dynamic.locked'), 'warning');
      text('sidebarState', t('dynamic.operatorLocked'));
      if (!byID('authDialog').open) byID('authDialog').showModal();
      return;
    }
    badge('systemBadge', t('dynamic.apiOffline'), 'danger');
    text('sidebarState', t('dynamic.apiOffline'));
    if (!(error instanceof DOMException && error.name === 'AbortError')) console.error(error);
  }
}

async function connectStream() {
  if (streamController) streamController.abort();
  streamController = new AbortController();
  globalThis.clearInterval(pollTimer);
  try {
    await streamSnapshots({
      signal: streamController.signal,
      onSnapshot: updateSnapshot,
      onEvent: () => refresh()
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    if (error instanceof APIError && error.status === 401) {
      byID('authDialog').showModal();
      return;
    }
    pollTimer = globalThis.setInterval(refresh, 3000);
  }
}

async function removeRule(id) {
  try {
    await deleteBlock(id);
    toast(t('toast.ruleRemoved'), 'good');
    await refresh();
  } catch (error) {
    handleActionError(error);
  }
}

async function acknowledge(id) {
  try {
    await acknowledgeIncident(id);
    toast(t('toast.incidentAck'), 'good');
    await refresh();
  } catch (error) {
    handleActionError(error);
  }
}

function handleActionError(error) {
  if (error instanceof APIError && error.status === 401) {
    byID('authDialog').showModal();
    toast(t('toast.operatorRequired'), 'warning');
    return;
  }
  const suffix = error instanceof APIError && error.errorID ? ` · ${error.errorID}` : '';
  toast(`${error.message || t('toast.operationFailed')}${suffix}`, 'danger');
}

function downloadJSON(name, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function bindActions() {
  document.querySelectorAll('[data-view]').forEach(button => {
    button.addEventListener('click', () => activateView(button.getAttribute('data-view')));
  });
  byID('authButton').addEventListener('click', () => {
    byID('tokenInput').value = getToken();
    byID('authDialog').showModal();
  });
  byID('supportButton').addEventListener('click', () => byID('supportDialog').showModal());
  byID('languageSelect').addEventListener('change', event => setLanguage(event.currentTarget.value));
  document.querySelectorAll('.copy-address').forEach(button => {
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy || '');
        toast(t('support.copied'), 'good');
      } catch (_) {
        toast(t('toast.operationFailed'), 'danger');
      }
    });
  });
  byID('saveToken').addEventListener('click', () => {
    setToken(byID('tokenInput').value);
    toast(t('toast.sessionUpdated'), 'good');
    refresh();
    connectStream();
  });
  byID('blockForm').addEventListener('submit', async event => {
    event.preventDefault();
    const target = byID('target').value.trim();
    const reason = byID('reason').value.trim();
    const ttlSeconds = Number.parseInt(byID('ttl').value, 10);
    try {
      await addBlock({ target, reason, ttl_seconds: ttlSeconds });
      text('actionMessage', t('message.policySet'));
      event.currentTarget.reset();
      toast(t('toast.policyActivated'), 'good');
      await refresh();
    } catch (error) {
      text('actionMessage', error.message || t('message.policyFailed'));
      handleActionError(error);
    }
  });
  byID('syncFeeds').addEventListener('click', async () => {
    try {
      await syncFeeds();
      toast(t('toast.feedStarted'), 'good');
    } catch (error) {
      handleActionError(error);
      await refresh();
    }
  });
  byID('loadProfiles').addEventListener('click', async () => {
    try {
      const payload = await getProfiles();
      renderProfiles(Array.isArray(payload) ? payload : payload.profiles || []);
      toast(t('toast.profilesLoaded'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('exportForensics').addEventListener('click', async () => {
    try {
      const payload = await exportForensics();
      downloadJSON(`gedefense-forensics-${new Date().toISOString().replaceAll(':', '-')}.json`, payload);
      toast(t('toast.forensicsCreated'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('releaseForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await transitionRelease({
        target: byID('releaseTarget').value,
        reason: byID('releaseReason').value.trim(),
        confirmation: byID('releaseConfirmation').value.trim()
      });
      toast(t('toast.phaseChanged'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('emergencyForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await emergencyStop(byID('emergencyReason').value.trim());
      toast(t('toast.emergencyActive'), 'danger');
      await refresh();
    } catch (error) {
      handleActionError(error);
      // The stop marker is persisted before kernel verification. A failed
      // request therefore still changes safety state and must be rendered.
      await refresh();
    }
  });
  byID('emergencyClearForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await clearEmergencyStop(byID('emergencyClearConfirmation').value.trim(), byID('emergencyClearReason').value.trim());
      toast(t('toast.emergencyCleared'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('settingFeeds').addEventListener('change', event => {
    if (!event.currentTarget.checked) byID('settingAutoFeeds').checked = false;
  });
  byID('settingAutoFeeds').addEventListener('change', event => {
    if (event.currentTarget.checked) byID('settingFeeds').checked = true;
  });
  byID('settingsForm').addEventListener('submit', async event => {
    event.preventDefault();
    const payload = settingsPayload();
    try {
      const saved = await updateSettings(payload);
      applySettings(saved);
      text('settingsMessage', t('message.settingsSaved'));
      toast(t('toast.settingsActivated'), 'good');
      await refresh();
    } catch (error) {
      text('settingsMessage', error.message || t('message.settingsFailed'));
      handleActionError(error);
    }
  });
  byID('hardeningSwitchForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const controls = Array.from(
        document.querySelectorAll('#hardeningSwitches input[data-runtime-managed="true"]:checked'),
        input => input.dataset.controlId
      ).filter(Boolean);
      if (!controls.length) throw new Error('Mindestens eine aktivierbare Schutzmaßnahme auswählen.');
      const transaction = await previewTransaction({
        type: 'hardening.sysctl-profile',
        summary: `${controls.length} ausgewählte AstraeaOS-Härtungskontrollen`,
        reason: byID('hardeningReason').value.trim(),
        payload: { controls }
      });
      selectTransaction(transaction);
      toast(t('hardening.previewReady'), 'good');
      await loadTransactions();
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('refreshHardening').addEventListener('click', () => loadHardening().catch(handleActionError));
  byID('refreshBoot').addEventListener('click', () => loadBootTrust().catch(handleActionError));
  byID('fimScan').addEventListener('click', async () => {
    try {
      await scanFIM();
      toast('FIM-Prüfung abgeschlossen.', 'good');
      await Promise.all([loadIntegrity(), loadHardening(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('fimBaseline').addEventListener('click', async () => {
    try {
      await createFIMBaseline();
      toast('Verschlüsselte FIM-Baseline wurde neu erstellt.', 'good');
      await Promise.all([loadIntegrity(), loadHardening(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('evidenceVerify').addEventListener('click', async () => {
    try {
      await verifyEvidence();
      toast('Die Evidence-Kette ist kryptografisch verifiziert.', 'good');
      await Promise.all([loadIntegrity(), loadHardening()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('packageIntegrityScan').addEventListener('click', async () => {
    try {
      await scanPackageIntegrity();
      toast('Paketintegritätsprüfung wurde gestartet.', 'good');
      await loadIntegrity();
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('malwareScanForm').addEventListener('submit', async event => {
    event.preventDefault();
    const path = byID('malwareScanPath').value.trim();
    try {
      const result = await scanMalware(path);
      renderMalwareResult(result, path);
      toast(result.state === 'clean' ? 'Inhaltsprüfung abgeschlossen: kein Fund.' : 'Fund wurde als XDR-Evidenz und Sicherheitsfall erfasst.', result.state === 'clean' ? 'good' : 'danger');
      await refresh();
    } catch (error) {
      badge('malwareScanState', 'SCAN ABGEWIESEN', 'danger');
      handleActionError(error);
    }
  });
  byID('quarantinePreviewForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const transaction = await previewQuarantine({
        path: byID('quarantinePath').value.trim(),
        reason: byID('quarantineReason').value.trim()
      });
      byID('quarantinePreviewForm').reset();
      await loadQuarantine();
      await selectTransactionByID(transaction.id);
      toast(t('quarantine.previewReady'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('caseStatusForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const id = byID('selectedCaseID').value;
      if (!id) throw new Error(t('cases.selectionRequired'));
      await setCaseStatus(
        id,
        byID('caseStatus').value,
        byID('caseResolution').value.trim()
      );
      byID('caseStatusForm').reset();
      toast(t('cases.saved'), 'good');
      await Promise.all([loadCases(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('transactionExecuteForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!selectedTransaction) return;
    try {
      const confirmation = byID('transactionConfirmation').value.trim();
      const reverse = selectedTransaction.status === 'applied' || selectedTransaction.status === 'recovery_required';
      const result = reverse
        ? await reverseTransaction(selectedTransaction.id, confirmation)
        : await applyTransaction(selectedTransaction.id, confirmation);
      selectedTransaction = result;
      byID('transactionSelection').hidden = true;
      byID('transactionConfirmation').value = '';
      toast(t(reverse ? 'hardening.reversed' : 'hardening.applied'), 'good');
      await Promise.all([loadTransactions(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('customRuleForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      if (!runtimeSettings) await loadSettings();
      const customRules = [...(runtimeSettings?.custom_rules || []), {
        id: byID('customRuleId').value.trim(),
        enabled: true,
        category: byID('customRuleCategory').value.trim(),
        summary: byID('customRuleSummary').value.trim(),
        pattern: byID('customRulePattern').value,
        score: Number.parseInt(byID('customRuleScore').value, 10)
      }];
      const saved = await updateSettings(settingsPayload({ custom_rules: customRules }));
      applySettings(saved);
      byID('customRuleForm').reset();
      setValue('customRuleScore', 25);
      toast(t('toast.customRuleSaved'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  byID('allowlistForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const result = await addAllowlist(byID('allowlistTarget').value.trim());
      applySettings(result.settings || result);
      byID('allowlistTarget').value = '';
      toast(t('toast.allowlistSynced'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
  document.addEventListener('gedefense:language', () => {
    const currentView = location.hash.replace('#', '') || 'overview';
    activateView(currentView);
    if (snapshot) updateSnapshot(snapshot);
  });
  globalThis.addEventListener('resize', () => drawTraffic(byID('trafficChart')));
}

function initialize() {
  initializeI18n();
  bindActions();
  const requested = location.hash.replace('#', '');
  activateView(requested || 'overview');
  globalThis.setInterval(() => text('clock', new Date().toLocaleTimeString(locale())), 1000);
  refresh();
  connectStream();
}

document.addEventListener('DOMContentLoaded', initialize, { once: true });
