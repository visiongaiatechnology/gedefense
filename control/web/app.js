'use strict';

import {
  acknowledgeIncident,
  addAllowlist,
  addBlock,
  applyTransaction,
  APIError,
  clearEmergencyStop,
  deleteBlock,
  exportForensics,
  emergencyStop,
  getProfiles,
  getQuarantine,
  getCases,
  getCells,
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
  setToken,
  setCaseStatus,
  streamSnapshots,
  syncFeeds,
  transitionRelease,
  updateSettings
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

const viewMeta = {
  overview: ['view.overview.eyebrow', 'view.overview.title'],
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
    for (const [value, className] of [
      [cell.uuid, 'mono'], [cell.label, ''], [cell.class, ''],
      [cell.state, cell.state === 'running' ? 'state-good' : 'state-warn'],
      [cell.network_state, cell.network_state === 'revoked' ? 'state-warn' : 'state-good'],
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

function updateSnapshot(data) {
  snapshot = data;
  const xdr = data.xdr || {};
  const policy = data.policy || {};
  const behavior = xdr.behavior || {};
  const release = data.release || {};
  text('versionText', data.version || '1.0.0-beta.5');
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
  byID('hardeningPreviewForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const profile = byID('hardeningProfile').value;
      const transaction = await previewTransaction({
        type: 'hardening.sysctl-profile',
        summary: t('hardening.summary', { profile }),
        reason: byID('hardeningReason').value.trim(),
        payload: { profile }
      });
      selectTransaction(transaction);
      toast(t('hardening.previewReady'), 'good');
      await loadTransactions();
    } catch (error) {
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
