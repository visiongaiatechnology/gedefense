// STATUS: DIAMANT VGT SUPREME
'use strict';

// XDR/spyware surfaces: quarantine, cases, Gaia Cells and on-access malware
// protection. Split out of the former single app.js module
// (refactoring wave 2a, structure-only).

import {
  getCases,
  getCells,
  getQuarantine,
  previewCellAction,
  previewQuarantine,
  pruneQuarantine,
  scanMalware,
  setCaseStatus
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
  handleActionError,
  number,
  on,
  withCriticalStepUp
} from './navigation.js';
import { selectTransactionByID } from './views_overview.js';

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
    if (item.status === 'applied' && item.identity && item.object_id) {
      const pruneBtn = document.createElement('button');
      pruneBtn.type = 'button';
      pruneBtn.className = 'button button-danger table-action ml-xs';
      pruneBtn.textContent = t('quarantine.prune');
      pruneBtn.addEventListener('click', async () => {
        try {
          const outcome = await withCriticalStepUp(t('quarantine.prune') + ': ' + item.object_id, proof =>
            pruneQuarantine({ object_id: item.object_id, identity: item.identity, confirm: item.object_id }, proof)
          );
          if (outcome === null) return;
          toast(t('quarantine.pruneDone'), 'good');
          await Promise.all([loadQuarantine(), refresh()]);
        } catch (error) {
          handleActionError(error);
        }
      });
      action.append(pruneBtn);
    }
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
      [record.id, 'mono'], [record.title, ''], [record.severity, `severity-${String(record.severity || 'info').toLowerCase()}`],
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

function renderMalwareProtection() {
  const sensor = String(snapshot?.xdr?.sensor || '');
  const active = Boolean(snapshot?.core_connected) && sensor.includes('fanotify-exec');
  badge('malwareProtectionHealth', active ? t('dynamic.active') : t('dynamic.notVerified'), active ? 'good' : 'danger');
  text('malwareRuntime', active ? t('malware.runtimeActive') : t('dynamic.sensorNotReady'));
  text('malwareSignatures', active ? t('malware.signatureActive') : t('dynamic.notVerified'));
  text('malwareReleaseGate', active ? t('malware.releaseGateActive') : t('dynamic.failClosed'));
  text('malwareProtectionDetail', active
    ? t('malware.activeDetail')
    : t('malware.inactiveDetail'));
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


function bindMalwareScanActions() {
  on('malwareScanForm', 'submit', async event => {
    event.preventDefault();
    const path = byID('malwareScanPath')?.value.trim();
    if (!path) return;
    try {
      const result = await scanMalware(path);
      renderMalwareResult(result, path);
      toast(result.state === 'clean' ? t('toast.malwareClean') : t('toast.malwareFinding'), result.state === 'clean' ? 'good' : 'danger');
      await refresh();
    } catch (error) {
      badge('malwareScanState', t('dynamic.scanRejected'), 'danger');
      handleActionError(error);
    }
  });
}

function bindForensicActions() {
  on('quarantinePreviewForm', 'submit', async event => {
    event.preventDefault();
    try {
      const path = byID('quarantinePath')?.value.trim();
      const reason = byID('quarantineReason')?.value.trim();
      if (!path || !reason) return;
      const transaction = await previewQuarantine({ path, reason });
      byID('quarantinePreviewForm')?.reset();
      await loadQuarantine();
      await selectTransactionByID(transaction.id);
      toast(t('quarantine.previewReady'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  on('caseStatusForm', 'submit', async event => {
    event.preventDefault();
    try {
      const id = byID('selectedCaseID')?.value;
      if (!id) throw new Error(t('cases.selectionRequired'));
      await setCaseStatus(
        id,
        byID('caseStatus')?.value || 'closed',
        byID('caseResolution')?.value.trim() || ''
      );
      byID('caseStatusForm')?.reset();
      toast(t('cases.saved'), 'good');
      await Promise.all([loadCases(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
}

export {
  bindForensicActions,
  bindMalwareScanActions,
  loadCases,
  loadCells,
  loadQuarantine,
  renderMalwareProtection
};
