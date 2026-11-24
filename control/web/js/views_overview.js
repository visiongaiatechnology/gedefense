// STATUS: DIAMANT VGT SUPREME
'use strict';

// Overview/settings surfaces: settings forms, custom rules, allowlist,
// transaction selection, hardening posture and the kernel advisory panel.
// Split out of the former single app.js module (refactoring wave 2a,
// structure-only).

import {
  addAllowlist,
  applyKernelMitigation,
  applyTransaction,
  getHardeningPosture,
  getKernelExposure,
  getKernelMitigation,
  getSettings,
  getTransactions,
  planKernelMitigation,
  previewTransaction,
  reverseTransaction,
  rollbackKernelMitigation,
  updateSettings
} from '../api.js';
import { t } from '../i18n.js';
import {
  badge,
  byID,
  formatTime,
  text,
  toast
} from '../render.js';
import {
  refresh,
  snapshot
} from './state.js';
import {
  activateView,
  emptyTable,
  handleActionError,
  number,
  on,
  openProtectionRemoval,
  setChecked,
  setValue
} from './navigation.js';


// Settings and transaction state moved from the shared module scope.
let runtimeSettings = null;
let selectedTransaction = null;
const configurableHardeningControls = new Set([
  'kernel.aslr',
  'kernel.kptr',
  'kernel.dmesg',
  'kernel.ptrace',
  'kernel.bpf',
  // Managed because a host that cannot take the kernel update can still close this entry point; the
  // advisory layer then scores the difference. Rootless containers stop working, so it stays a switch.
  'kernel.userns',
  'filesystem.protected-links',
  'filesystem.suid-dumps',
  'network.syn-cookies',
  'network.ipv4-redirects',
  'network.ipv6-redirects'
]);

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
    button.addEventListener('click', () => openProtectionRemoval('allowlist', { target }));
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
    healthy ? t('dynamic.verified') : (payload?.recovery_required ? t('dynamic.recoveryRequired') : t('dynamic.quarantined')),
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

function updateHardeningSelectionCount() {
  // Counts every selectable control, not only the checked ones: the badge reports the
  // size of the selection the operator can act on, and a zero after this change means
  // the list is genuinely empty rather than merely unchecked.
  const selected = document.querySelectorAll('#hardeningSwitches input[data-runtime-managed="true"]:checked').length;
  const selectable = document.querySelectorAll('#hardeningSwitches input[data-runtime-managed="true"]').length;
  if (selectable > 0 && selected === 0) { text('hardeningSelectionCount', t('hardening.noneSelected', { count: selectable })); return; }
  text('hardeningSelectionCount', t('hardening.selectedCount', { count: selected }));
}

function renderHardeningSwitches(checks) {
  const container = byID('hardeningSwitches');
  if (!checks.length) {
    const message = document.createElement('p');
    message.className = 'empty-state';
    message.textContent = t('hardening.noControls');
    container.replaceChildren(message);
    updateHardeningSelectionCount();
    return;
  }
  const controls = checks.map(check => {
    const configurable = configurableHardeningControls.has(String(check.id || ''));
    const protectedState = check.state === 'PROTECTED';
    const row = document.createElement('div');
    row.className = `hardening-control ${configurable ? 'runtime-control' : 'platform-control'}`;

    const copy = document.createElement('span');
    copy.className = 'hardening-control-copy';
    const title = document.createElement('b');
    title.textContent = String(check.title || check.id || 'Kontrolle');
    const detail = document.createElement('small');
    detail.textContent = configurable
      ? String(check.recommendation || t('hardening.managedActive'))
      : `${String(check.evidence || t('dynamic.notMeasurable'))} Â· ${String(check.recommendation || t('hardening.platformOnly'))}`;
    const meta = document.createElement('span');
    meta.className = 'hardening-control-meta';
    const domain = document.createElement('em');
    domain.textContent = configurable ? t('hardening.scope.runtimePersistent') : t('hardening.scope.installBootFirmware');
    const state = document.createElement('span');
    state.className = `hardening-control-state ${protectedState ? 'is-protected' : configurable ? 'is-available' : 'is-platform'}`;
    // The pill states the measured verdict rather than the availability, because that is
    // what the operator is deciding on.
    state.textContent = protectedState
      ? t('hardening.state.protected')
      : check.state === 'UNPROTECTED'
        ? t('hardening.state.unprotected')
        : configurable
          ? t('dynamic.available')
          : t('hardening.state.platform');
    meta.append(domain, state);
    copy.append(title, detail, meta);
    row.append(copy);

    if (!configurable) {
      // These controls are not administrable at runtime at all: they live in firmware,
      // the bootloader or the kernel command line. They are shown so the posture is
      // complete, and they carry no control because there is nothing to toggle. The
      // reason is stated in the row rather than only implied by a disabled widget.
      const locked = document.createElement('span');
      locked.className = 'hardening-control-locked';
      locked.textContent = t('hardening.notRuntimeAdministrable');
      row.append(locked);
      return row;
    }

    // The switch reuses the primitive the Fabric Settings workbench already uses: a
    // <label> wrapping a visually hidden checkbox, a visual track and a state word.
    //
    // The previous markup exposed a bare native checkbox stretched to 42 px, which read
    // as broken next to the rest of the product, and it disabled every control that was
    // already PROTECTED. That second part was the real defect: the button in this form
    // verifies a selection, it does not apply one, so refusing to let an operator include
    // an already-hardened control made ten switches look dead on a hardened host for no
    // security reason.
    const wrap = document.createElement('label');
    wrap.className = 'settings-switch hardening-switch';

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = protectedState;
    input.dataset.controlId = String(check.id || '');
    input.dataset.runtimeManaged = 'true';
    input.setAttribute('aria-label', String(check.title || check.id || 'Kontrolle'));

    const track = document.createElement('span');
    track.className = 'settings-switch-track';
    track.setAttribute('aria-hidden', 'true');
    const stateWord = document.createElement('span');
    stateWord.className = 'settings-switch-state';
    stateWord.textContent = input.checked ? t('hardening.switchOn') : t('hardening.switchOff');

    input.addEventListener('change', () => {
      stateWord.textContent = input.checked ? t('hardening.switchOn') : t('hardening.switchOff');
      updateHardeningSelectionCount();
    });

    wrap.append(input, track, stateWord);
    row.append(wrap);
    return row;
  });  container.replaceChildren(...controls);
  updateHardeningSelectionCount();
}

function renderHardening(payload) {
  const score = Math.max(0, Math.min(100, Number(payload?.score || 0)));
  text('hardeningScore', score);
  text('hardeningScoreTitle', String(payload?.level || 'UNAVAILABLE'));

  // The coverage line states what the score rests on, and names the cap explicitly when
  // one applied. Without it a capped level and a genuine one look identical.
  const coverageNode = byID('hardeningCoverage');
  if (coverageNode) {
    const measured = Number(payload?.measured_checks ?? 0);
    const total = Number(payload?.total_checks ?? 0);
    const unavailable = Number(payload?.unavailable_checks ?? 0);
    const sufficient = payload?.coverage_sufficient !== false;
    const parts = [t('hardening.coverageLine', { measured, total })];
    if (unavailable > 0) parts.push(t('hardening.coverageUnavailable', { count: unavailable }));
    if (!sufficient && payload?.coverage_note) parts.push(String(payload.coverage_note));
    coverageNode.textContent = parts.join(' Â· ');
    coverageNode.setAttribute('data-sufficient', sufficient ? 'yes' : 'no');
  }
  text('hardeningCollected', payload?.collected_at ? formatTime(payload.collected_at) : t('hardening.noMeasurement'));
  badge('hardeningLevel', String(payload?.level || 'UNAVAILABLE'), score >= 90 ? 'good' : score >= 50 ? 'warning' : 'danger');
  const ring = byID('hardeningScoreRing');
  if (ring) ring.style.setProperty('--score', String(score));

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
    detail.textContent = t('hardening.domainProtected', { protected: Number(domain.protected || 0), total: Number(domain.total || 0) });
    const progress = document.createElement('div');
    progress.className = 'progress';
    const bar = document.createElement('i');
    bar.style.width = `${Math.max(0, Math.min(100, Number(domain.score || 0)))}%`;
    progress.append(bar);
    card.append(header, detail, progress);
    return card;
  });
  const domainsContainer = byID('hardeningDomains');
  if (domainsContainer) domainsContainer.replaceChildren(...domainCards);

  const body = byID('hardeningChecks');
  const checks = Array.isArray(payload?.checks) ? payload.checks : [];
  renderHardeningSwitches(checks);
  if (!checks.length) {
    emptyTable(body, 5, t('hardening.noData'));
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
    recommendation.textContent = String(check.recommendation || (check.managed ? t('hardening.managedTransactional') : t('hardening.noActionRequired')));
    row.append(state, evidence, recommendation);
    return row;
  });
  body.replaceChildren(...rows);
}

// Kernel advisory panel: exposure, the advisories behind it, and the guarded mitigation with its
// dry run, apply and rollback. The buttons are bound once; the panel re-renders on every load.
let kernelAdvisoryBound = false;

function renderKernelAdvisory(exposure, mitigation) {
  if (!exposure) return;
  text('kernExposureScore', `${exposure.score ?? 0} / 100`);
  text('kernExposureVerdict', String(exposure.verdict || 'unknown'));
  text('kernExposureKernel', `${exposure.kernel?.release || '?'} (${exposure.kernel?.channel || '?'})`);
  text('kernExposureSummary', String(exposure.recommendation || exposure.unknown_reason || ''));
  const grade = byID('kernExposureGrade');
  if (grade) {
    grade.textContent = String(exposure.grade || 'UNKNOWN');
    grade.className = `status-pill ${exposure.grade === 'EXPOSED' ? 'danger' : exposure.grade === 'HARDENED' ? 'good' : 'warn'}`;
  }
  const list = byID('kernAdvisoryList');
  if (list) {
    list.replaceChildren(...(exposure.advisories || []).map(advisory => {
      const item = document.createElement('li');
      item.textContent = `${advisory.id} - ${advisory.verdict} (reachability ${advisory.reachability ?? 0}%)`;
      return item;
    }));
  }
  if (mitigation) {
    text('kernMitigationState', `${mitigation.state || 'idle'}${mitigation.enabled ? '' : ' (auto aus)'}`);
    text('kernMitigationDetail', mitigation.key ? `${mitigation.key}=${mitigation.current || ''} ${mitigation.reason || ''}` : (mitigation.reason || ''));
  }
  if (kernelAdvisoryBound) return;
  kernelAdvisoryBound = true;
  byID('kernMitigationPlan')?.addEventListener('click', async () => {
    try {
      const plan = await planKernelMitigation();
      toast(`${t('advisory.plan')}: ${plan.applicable ? `${plan.key} ${plan.current} -> ${plan.desired}` : plan.reason}`, plan.applicable ? 'warn' : 'good');
    } catch (error) { handleActionError(error); }
  });
  byID('kernMitigationApply')?.addEventListener('click', async () => {
    const reason = (window.prompt(t('advisory.reason'), '') || '').trim();
    if (reason.length < 3) { toast(t('cells.reasonRequired'), 'bad'); return; }
    try { const plan = await planKernelMitigation(); await applyKernelMitigation(reason, `APPLY ${plan.key}`); toast(t('advisory.applied'), 'good'); await loadKernelAdvisory(); }
    catch (error) { handleActionError(error); }
  });
  byID('kernMitigationRollback')?.addEventListener('click', async () => {
    const reason = (window.prompt(t('advisory.reason'), '') || '').trim();
    if (reason.length < 3) { toast(t('cells.reasonRequired'), 'bad'); return; }
    try { const status = await getKernelMitigation(); await rollbackKernelMitigation(reason, `ROLLBACK ${status.key}`); toast(t('advisory.reverted'), 'good'); await loadKernelAdvisory(); }
    catch (error) { handleActionError(error); }
  });
}

async function loadKernelAdvisory() {
  try {
    const [exposure, mitigation] = await Promise.all([getKernelExposure(), getKernelMitigation()]);
    renderKernelAdvisory(exposure, mitigation);
  } catch (_) {
    // The panel stays empty rather than inventing a state; the API is the source of truth.
  }
}

async function loadHardening() {
  const payload = await getHardeningPosture();
  renderHardening(payload);
  await loadKernelAdvisory();
  return payload;
}


function bindHardeningActions() {
  on('hardeningSwitchForm', 'submit', async event => {
    event.preventDefault();
    try {
      const controls = Array.from(
        document.querySelectorAll('#hardeningSwitches input[data-runtime-managed="true"]:checked'),
        input => input.dataset.controlId
      ).filter(Boolean);
      if (!controls.length) throw new Error(t('hardening.selectAtLeastOne'));
      const reason = byID('hardeningReason')?.value.trim() || t('view.hardening.title');
      const transaction = await previewTransaction({
        type: 'hardening.sysctl-profile',
        summary: t('hardening.selectionSummary', { count: controls.length }),
        reason,
        payload: { controls }
      });
      selectTransaction(transaction);
      toast(t('hardening.previewReady'), 'good');
      await loadTransactions();
    } catch (error) {
      handleActionError(error);
    }
  });
  on('refreshHardening', 'click', () => loadHardening().catch(handleActionError));
}

function bindTransactionActions() {
  on('transactionExecuteForm', 'submit', async event => {
    event.preventDefault();
    if (!selectedTransaction) return;
    try {
      const confirmation = byID('transactionConfirmation')?.value.trim();
      const reverse = selectedTransaction.status === 'applied' || selectedTransaction.status === 'recovery_required';
      const result = reverse
        ? await reverseTransaction(selectedTransaction.id, confirmation)
        : await applyTransaction(selectedTransaction.id, confirmation);
      selectedTransaction = result;
      const selBox = byID('transactionSelection');
      if (selBox) selBox.hidden = true;
      const confInput = byID('transactionConfirmation');
      if (confInput) confInput.value = '';
      toast(t(reverse ? 'hardening.reversed' : 'hardening.applied'), 'good');
      await Promise.all([loadTransactions(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
}

function bindSettingsActions() {
  on('customRuleForm', 'submit', async event => {
    event.preventDefault();
    try {
      if (!runtimeSettings) await loadSettings();
      const id = byID('customRuleId')?.value.trim();
      const category = byID('customRuleCategory')?.value.trim() || 'custom';
      const summary = byID('customRuleSummary')?.value.trim() || t('settings.defaultCustomRule');
      const pattern = byID('customRulePattern')?.value || '';
      const score = Number.parseInt(byID('customRuleScore')?.value || '25', 10);
      if (!id || !pattern) return;
      const customRules = [...(runtimeSettings?.custom_rules || []), {
        id,
        enabled: true,
        category,
        summary,
        pattern,
        score
      }];
      const saved = await updateSettings(settingsPayload({ custom_rules: customRules }));
      applySettings(saved);
      byID('customRuleForm')?.reset();
      setValue('customRuleScore', 25);
      toast(t('toast.customRuleSaved'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  on('allowlistForm', 'submit', async event => {
    event.preventDefault();
    try {
      const target = byID('allowlistTarget')?.value.trim();
      if (!target) return;
      const result = await addAllowlist(target);
      applySettings(result.settings || result);
      const input = byID('allowlistTarget');
      if (input) input.value = '';
      toast(t('toast.allowlistSynced'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
}

export {
  applySettings,
  bindHardeningActions,
  bindSettingsActions,
  bindTransactionActions,
  loadHardening,
  loadSettings,
  loadTransactions,
  selectTransactionByID,
  settingsPayload
};
