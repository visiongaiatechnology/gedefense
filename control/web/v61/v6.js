// STATUS: DIAMANT VGT SUPREME
'use strict';

// GeDefense 6.1.0 — shared status helpers for the V6.1 dashboard surfaces.
//
// The five web-posture views (A–E) and the five V6 fabric panels render the same
// three primitives: a counter rail, a bounded detail table and an honest
// capability/reason line. They also share one mutating-action primitive: a typed
// confirmation dialog. Duplicating either in ten modules would drift, so both
// live here. Every operator value is written with textContent; this module never
// builds markup from data.

import { api } from '../api.js';
import { locale, t } from '../i18n.js';
import { formatBytes, formatTime, toast } from '../render.js';

export const byId = id => document.getElementById(id);

export const dash = value => (value === null || value === undefined || value === '' ? '—' : String(value));

export function setText(id, value) {
  const node = byId(id);
  if (node) node.textContent = dash(value);
}

export function setTone(id, label, tone = 'muted') {
  const node = byId(id);
  if (!node) return;
  node.textContent = dash(label);
  node.className = `status-pill ${tone}`;
}

export function setHidden(id, hidden) {
  const node = byId(id);
  if (node) node.hidden = Boolean(hidden);
}

export function el(tag, className = '', textContent = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (textContent !== '' && textContent !== null && textContent !== undefined) node.textContent = String(textContent);
  return node;
}

// pick returns the first present key. Several status documents carry Go structs
// without JSON tags (kernel health counters), so the same field can arrive as
// `RingDrops` or `ring_drops`. The renderer reports whichever the server sent
// instead of assuming one spelling.
export function pick(source, ...names) {
  if (!source || typeof source !== 'object') return undefined;
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(source, name) && source[name] !== undefined && source[name] !== null) {
      return source[name];
    }
  }
  return undefined;
}

export const asArray = value => (Array.isArray(value) ? value : []);
export const asObject = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});
export const asNumber = value => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};
export const asBool = value => value === true || value === 'true';
export const formatCount = value => asNumber(value).toLocaleString(locale());
export const formatStamp = value => (value ? formatTime(value) : '—');
export const formatSize = value => formatBytes(asNumber(value));

export function setNotice(id, message, tone = 'warn') {
  const node = byId(id);
  if (!node) return;
  const text = String(message || '').trim();
  node.hidden = !text;
  node.textContent = text;
  node.className = `v61-reason${tone && tone !== 'warn' ? ` tone-${tone}` : ''}`;
}

// refusalText keeps the control plane's own wording. A refusal that the backend
// phrased for the operator must not be replaced by a friendlier invention. When
// a failure carries no message (a body without an `error` field), the HTTP
// status is appended so the operator still sees a concrete fact.
export function refusalText(error, fallbackKey = 'v61.v6.error.fallback') {
  const message = String(error?.message || '').trim();
  if (message) return message;
  const status = Number(error?.status) || 0;
  return status ? `${t(fallbackKey)} (HTTP ${status})` : t(fallbackKey);
}

export function showRefusal(id, error, fallbackKey = 'v61.v6.error.fallback') {
  const message = refusalText(error, fallbackKey);
  setNotice(id, message, 'bad');
  toast(message, 'danger', error?.errorID || '');
  return message;
}

function cellNode(value) {
  const cell = document.createElement('td');
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    if (value.cls) cell.className = value.cls;
    if (value.pill) {
      cell.append(el('span', `status-pill ${value.pill.tone || 'muted'}`, dash(value.pill.label)));
    } else if (Array.isArray(value.badges)) {
      const wrap = el('span', 'v61-badge-list');
      for (const badge of value.badges) wrap.append(el('span', `badge ${badge.tone ? `badge-${badge.tone}` : ''}`, badge.label));
      cell.append(wrap);
    } else if (Array.isArray(value.list)) {
      cell.textContent = value.list.length ? value.list.join(', ') : '—';
    } else {
      cell.textContent = dash(value.text);
    }
    if (value.title) cell.title = String(value.title);
    return cell;
  }
  cell.textContent = dash(value);
  return cell;
}

// renderRows replaces a table body from plain values. `rows` is an array of
// arrays; a value may be a string/number or an object {text|pill|badges|list}.
export function renderRows(tbodyId, columns, rows, emptyKey) {
  const body = byId(tbodyId);
  if (!body) return;
  body.replaceChildren();
  const list = asArray(rows);
  if (!list.length) {
    const row = document.createElement('tr');
    const cell = el('td', 'v61-empty', t(emptyKey));
    cell.colSpan = columns;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const values of list) {
    const row = document.createElement('tr');
    for (const value of asArray(values)) row.append(cellNode(value));
    body.append(row);
  }
}

export async function getJSON(path) {
  return api(path, { feedback: true });
}

export async function sendJSON(path, method, body = {}) {
  return api(path, { method, json: body });
}

// bindAction wraps a mutating button: one in-flight call at a time, a visible
// busy state, and a reported failure instead of a silent no-op.
export function bindAction(id, handler) {
  const button = byId(id);
  if (!button) return;
  button.addEventListener('click', () => {
    if (button.dataset.busy === '1') return;
    button.dataset.busy = '1';
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    Promise.resolve()
      .then(() => handler())
      .catch(error => {
        toast(refusalText(error), 'danger', error?.errorID || '');
      })
      .finally(() => {
        delete button.dataset.busy;
        button.disabled = false;
        button.removeAttribute('aria-busy');
      });
  });
}

// ------------------------------------------------------- typed confirmation

let confirmState = null;
let confirmBound = false;

function failConfirm(message) {
  const error = byId('v61ConfirmError');
  if (!error) return;
  error.textContent = message;
  error.hidden = false;
}

function settleConfirm(result) {
  const state = confirmState;
  confirmState = null;
  const dialog = byId('v61ConfirmDialog');
  if (dialog && dialog.open) dialog.close();
  if (state) state.resolve(result);
}

function bindConfirm() {
  if (confirmBound) return;
  const dialog = byId('v61ConfirmDialog');
  const form = byId('v61ConfirmForm');
  if (!dialog || !form) return;
  confirmBound = true;
  byId('v61ConfirmCancel')?.addEventListener('click', () => settleConfirm(null));
  dialog.addEventListener('cancel', event => {
    event.preventDefault();
    settleConfirm(null);
  });
  dialog.addEventListener('close', () => settleConfirm(null));
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!confirmState) return;
    if (confirmState.phrase) {
      const entered = String(byId('v61ConfirmPhraseInput')?.value || '');
      if (entered !== confirmState.phrase) {
        failConfirm(t('v61.v6.confirm.phraseMismatch', { phrase: confirmState.phrase }));
        byId('v61ConfirmPhraseInput')?.focus();
        return;
      }
    }
    const reason = String(byId('v61ConfirmReasonInput')?.value || '').trim();
    if (confirmState.requireReason && reason.length < 8) {
      failConfirm(t('v61.v6.confirm.reasonTooShort'));
      byId('v61ConfirmReasonInput')?.focus();
      return;
    }
    settleConfirm({ reason });
  });
}

// confirmAction opens the shared dialog and resolves with null on cancel or with
// {reason} once the operator confirmed. `phrase` enables the typed confirmation
// used for destructive actions (lockdown trigger/clear, witness push, cell burn).
export function confirmAction(options = {}) {
  bindConfirm();
  const dialog = byId('v61ConfirmDialog');
  const submit = byId('v61ConfirmSubmit');
  if (!dialog || !submit) return Promise.resolve(null);
  // A second request while a confirmation is already open must not call
  // showModal() again (the browser throws) and must not stack intents.
  if (dialog.open) return Promise.resolve(null);
  const phrase = String(options.phrase || '');
  const requireReason = options.requireReason !== false;
  setText('v61ConfirmTitle', t(options.titleKey || 'v61.v6.confirm.title'));
  const body = byId('v61ConfirmBody');
  if (body) body.textContent = t(options.bodyKey || 'v61.v6.confirm.body');
  const detail = byId('v61ConfirmDetail');
  const detailText = options.detail ? String(options.detail) : (phrase ? t('v61.v6.confirm.phrasePattern', { phrase }) : '');
  if (detail) {
    detail.textContent = detailText;
    detail.hidden = !detailText;
  }
  const phraseWrap = byId('v61ConfirmPhraseWrap');
  const phraseInput = byId('v61ConfirmPhraseInput');
  if (phraseWrap) phraseWrap.hidden = !phrase;
  if (phraseInput) {
    phraseInput.value = '';
    phraseInput.placeholder = phrase;
  }
  const reasonWrap = byId('v61ConfirmReasonWrap');
  if (reasonWrap) reasonWrap.hidden = !requireReason;
  const reasonInput = byId('v61ConfirmReasonInput');
  if (reasonInput) reasonInput.value = '';
  const error = byId('v61ConfirmError');
  if (error) error.hidden = true;
  submit.textContent = t(options.submitKey || 'v61.v6.confirm.submit');
  submit.className = `button ${options.danger === false ? 'button-primary' : 'button-danger'}`;
  return new Promise(resolve => {
    confirmState = { resolve, phrase, requireReason };
    dialog.showModal();
    globalThis.setTimeout(() => {
      const target = phrase ? phraseInput : reasonInput;
      if (target) target.focus();
    }, 30);
  });
}

// initV61Shared is called from the module init chain so the dialog wiring exists
// before the first view is opened. It is idempotent.
export function initV61Shared() {
  bindConfirm();
  for (const id of ['v61ConfirmDialog']) {
    const dialog = byId(id);
    if (dialog && !dialog.dataset.v61Bound) dialog.dataset.v61Bound = '1';
  }
}

// severityTone maps a closed severity vocabulary onto the product's state tones.
// Unknown values stay muted: an unrecognised word must not look like "safe".
export function severityTone(severity) {
  switch (String(severity || '').toLowerCase()) {
    case 'critical':
    case 'high':
    case 'danger':
      return 'danger';
    case 'medium':
    case 'warn':
    case 'warning':
      return 'warn';
    case 'low':
    case 'info':
      return 'good';
    default:
      return 'muted';
  }
}
