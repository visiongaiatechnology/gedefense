// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6 panel — ephemeral parser cells.
//
// The panel shows the runtime projection (enabled, helper, sandbox, host layers,
// presets) and the bounded cell list. Burn is confirm-gated with the exact phrase
// the API requires ("BURN <uuid>"); freeze/unfreeze are reversible state changes
// and use the same dialog without a typed phrase. Every refusal is printed
// verbatim in the action result line.

import { t } from '../i18n.js';
import { toast } from '../render.js';
import {
  asArray,
  asBool,
  asObject,
  bindAction,
  byId,
  confirmAction,
  el,
  formatCount,
  formatStamp,
  getJSON,
  initV61Shared,
  refusalText,
  renderRows,
  sendJSON,
  setNotice,
  setText,
  setTone
} from './v6.js';

const STATUS_PATH = '/api/v1/parser-cells/status';
const LIST_PATH = '/api/v1/parser-cells?limit=64';

let busyCell = '';

export function initCellsModule() {
  initV61Shared();
  bindAction('cellsRefreshBtn', () => loadCellsView());
}

export async function loadCellsView() {
  const [statusResult, listResult] = await Promise.allSettled([getJSON(STATUS_PATH), getJSON(LIST_PATH)]);
  const status = statusResult.status === 'fulfilled' ? asObject(statusResult.value) : null;
  if (status) {
    renderStatus(status);
  } else {
    setNotice('cellsReason', refusalText(statusResult.reason, 'v61.v6.cells.unavailable'), 'bad');
    setTone('cellsPill', t('v61.v6.common.unavailable'), 'danger');
  }
  if (listResult.status === 'fulfilled') {
    renderCells(asArray(asObject(listResult.value).cells).map(asObject));
  } else {
    renderCells([]);
    setNotice('cellsActionResult', refusalText(listResult.reason, 'v61.v6.cells.listUnavailable'), 'warn');
  }
}

function renderStatus(status) {
  const enabled = asBool(status.enabled);
  const available = asBool(status.available);
  setTone('cellsPill', t(enabled ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), enabled ? (available ? 'good' : 'warn') : 'muted');
  setTone('cellsEnabledKpi', t(enabled ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), enabled ? 'good' : 'muted');
  setTone('cellsAvailableKpi', t(available ? 'v61.v6.common.available' : 'v61.v6.common.unavailable'), available ? 'good' : 'danger');
  setText('cellsHelperKpi', status.helper || '—');
  setText('cellsActiveKpi', formatCount(status.active));
  setText('cellsBurnedKpi', formatCount(status.burned));
  setText('cellsFailedKpi', formatCount(status.failed));
  setText('cellsRefusedKpi', formatCount(status.refused));
  setText('cellsMaxKpi', formatCount(status.max_concurrent));
  setText('cellsProfilesKpi', asArray(status.profiles).join(', ') || t('v61.v6.common.none'));
  setTone('cellsSandboxKpi', t(asBool(status.sandbox) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), asBool(status.sandbox) ? 'good' : 'warn');
  setTone('cellsBpfKpi', t(asBool(status.bpf_lsm) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), asBool(status.bpf_lsm) ? 'good' : 'warn');
  setText('cellsHelperCells', formatCount(status.helper_active_cells));
  setText('cellsTtl', formatCount(status.ttl_seconds));
  setText('cellsMaxInput', formatCount(status.max_input_bytes));
  setText('cellsLayerLsm', status.layer_cell_lsm || '—');
  setText('cellsLayerStyx', status.layer_styx_egress || '—');
  setText('cellsLayerTitan', status.layer_titan_exec || '—');

  const reason = [String(status.degraded_reason || '').trim(), String(status.last_error || '').trim()].filter(Boolean).join(' · ');
  setNotice('cellsReason', reason, enabled ? 'warn' : 'warn');
  renderRecent(asArray(status.recent).map(asObject));
}

function renderRecent(items) {
  renderRows('cellsRecentRows', 5, items.map(item => [
    { text: formatStamp(item.at) },
    { text: item.action || '—', cls: 'v61-mono' },
    { text: item.state || '—', cls: 'v61-mono' },
    { text: item.uuid || '—', cls: 'v61-mono' },
    { text: item.reason || item.detail || '—', cls: 'v61-tight' }
  ]), 'v61.v6.cells.empty.recent');
}

function renderCells(cells) {
  const body = byId('parserCellRows');
  if (!body) return;
  body.replaceChildren();
  if (!cells.length) {
    const row = document.createElement('tr');
    const cell = el('td', 'v61-empty', t('v61.v6.cells.empty.cells'));
    cell.colSpan = 8;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const cell of cells) {
    const row = document.createElement('tr');
    const terminal = asBool(cell.terminal);
    const uuid = String(cell.uuid || '');
    row.append(
      cellNode(uuid || '—', 'v61-mono v61-tight', uuid),
      cellNode(cell.profile || '—', 'v61-mono'),
      cellNode(cell.state || '—', 'v61-mono'),
      cellNode(cell.pid === undefined ? '—' : formatCount(cell.pid), 'v61-mono'),
      cellNode(cell.cgroup_id === undefined ? '—' : formatCount(cell.cgroup_id), 'v61-mono'),
      cellNode(formatCount(cell.ttl_seconds), 'v61-mono'),
      cellNode(formatStamp(cell.created_at)),
      actionCell(cell, terminal ? '' : uuid)
    );
    body.append(row);
  }
}

function cellNode(value, cls = '', title = '') {
  const node = el('td', cls, value);
  if (title) node.title = title;
  return node;
}

function actionCell(cell, uuid) {
  const td = el('td');
  const wrap = el('div', 'rule-actions');
  if (!uuid) {
    wrap.append(el('span', 'text-muted fs-xs', t('v61.v6.cells.terminal')));
    td.append(wrap);
    return td;
  }
  wrap.append(actionButton(t('v61.v6.cells.burn'), 'icon-button danger', () => burnCell(uuid)));
  wrap.append(actionButton(t('v61.v6.cells.freeze'), 'icon-button', () => setCellState(uuid, 'freeze')));
  wrap.append(actionButton(t('v61.v6.cells.unfreeze'), 'icon-button', () => setCellState(uuid, 'unfreeze')));
  td.append(wrap);
  return td;
}

function actionButton(label, className, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', handler);
  return button;
}

async function burnCell(uuid) {
  if (busyCell) return;
  const phrase = `BURN ${uuid}`;
  const confirmed = await confirmAction({
    titleKey: 'v61.v6.cells.burnTitle',
    bodyKey: 'v61.v6.cells.burnBody',
    submitKey: 'v61.v6.cells.burnSubmit',
    phrase,
    detail: t('v61.v6.cells.burnDetail', { uuid })
  });
  if (!confirmed) return;
  busyCell = uuid;
  setNotice('cellsActionResult', '');
  try {
    await sendJSON(`/api/v1/parser-cells/${encodeURIComponent(uuid)}/burn`, 'POST', { confirm: phrase });
    const message = t('v61.v6.cells.burnDone', { uuid });
    setNotice('cellsActionResult', message, 'good');
    toast(message, 'good');
  } catch (error) {
    setNotice('cellsActionResult', refusalText(error, 'v61.v6.cells.actionFailed'), 'bad');
    toast(refusalText(error), 'danger', error?.errorID || '');
  } finally {
    busyCell = '';
  }
  await loadCellsView();
}

async function setCellState(uuid, action) {
  if (busyCell) return;
  const confirmed = await confirmAction({
    titleKey: action === 'freeze' ? 'v61.v6.cells.freezeTitle' : 'v61.v6.cells.unfreezeTitle',
    bodyKey: action === 'freeze' ? 'v61.v6.cells.freezeBody' : 'v61.v6.cells.unfreezeBody',
    submitKey: action === 'freeze' ? 'v61.v6.cells.freezeSubmit' : 'v61.v6.cells.unfreezeSubmit',
    danger: action !== 'unfreeze',
    detail: t('v61.v6.cells.stateDetail', { uuid })
  });
  if (!confirmed) return;
  busyCell = uuid;
  setNotice('cellsActionResult', '');
  try {
    await sendJSON(`/api/v1/parser-cells/${encodeURIComponent(uuid)}/${action}`, 'POST', {});
    const message = t(action === 'freeze' ? 'v61.v6.cells.freezeDone' : 'v61.v6.cells.unfreezeDone', { uuid });
    setNotice('cellsActionResult', message, 'good');
    toast(message, 'good');
  } catch (error) {
    setNotice('cellsActionResult', refusalText(error, 'v61.v6.cells.actionFailed'), 'bad');
    toast(refusalText(error), 'danger', error?.errorID || '');
  } finally {
    busyCell = '';
  }
  await loadCellsView();
}
