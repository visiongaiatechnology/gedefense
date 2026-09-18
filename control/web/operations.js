// STATUS: DIAMANT VGT SUPREME
'use strict';

import { t } from './i18n.js';
import { byID } from './render.js';

const activeOperations = new Map();
let hideTimer = 0;
let revealTimer = 0;

const operationMatchers = [
  [/\/api\/v1\/hardening\//, 'operation.hardening'],
  [/\/api\/v1\/boot-trust(?:\/|$)/, 'operation.boot'],
  [/\/api\/v1\/evidence\/verify(?:\/|$)/, 'operation.evidence'],
  [/\/api\/v1\/forensics\/export(?:\/|$)/, 'operation.forensics'],
  [/\/api\/v1\/release\//, 'operation.release'],
  [/\/api\/v1\/transactions\//, 'operation.hardening'],
  [/\/api\/v1\/feeds\//, 'operation.feeds'],
  [/\/api\/v1\/fim\//, 'operation.fim'],
  [/\/api\/v1\/package-integrity\//, 'operation.packageIntegrity'],
  [/\/api\/v1\/malware\//, 'operation.malware'],
  [/\/api\/v1\/blocks(?:\/|$)/, 'operation.network'],
  [/\/api\/v1\/settings(?:\/|$)/, 'operation.settings'],
  [/\/api\/v1\/allowlist(?:\/|$)/, 'operation.allowlist'],
  [/\/api\/v1\/quarantine\//, 'operation.quarantine'],
  [/\/api\/v1\/cells\//, 'operation.cells'],
  [/\/api\/v1\/xdr\//, 'operation.xdr'],
  [/\/api\/v1\/deception\//, 'operation.deception'],
  [/\/api\/v1\/styx\//, 'operation.egress'],
  [/\/api\/v1\/airlock\//, 'operation.airlock']
];

function titleForPath(path) {
  const normalized = String(path || '');
  for (const [pattern, key] of operationMatchers) {
    if (pattern.test(normalized)) return t(key);
  }
  return t('operation.default');
}

function setOverlayState(state, title, detail) {
  const overlay = byID('operationOverlay');
  const panel = byID('operationPanel');
  const icon = byID('operationStateIcon');
  const titleNode = byID('operationTitle');
  const detailNode = byID('operationDetail');
  const close = byID('operationClose');
  if (!overlay || !panel || !icon || !titleNode || !detailNode || !close) return;

  panel.dataset.state = state;
  titleNode.textContent = String(title || t('operation.default'));
  detailNode.textContent = String(detail || '');
  close.hidden = state === 'running';
  icon.setAttribute('aria-label', state === 'success' ? t('operation.success') : state === 'error' ? t('operation.failed') : t('operation.working'));

  overlay.hidden = false;
  requestAnimationFrame(() => overlay.classList.add('is-visible'));
}

function hideOverlay() {
  const overlay = byID('operationOverlay');
  if (!overlay) return;
  overlay.classList.remove('is-visible');
  globalThis.clearTimeout(hideTimer);
  hideTimer = globalThis.setTimeout(() => {
    if (!overlay.classList.contains('is-visible')) overlay.hidden = true;
  }, 220);
}

function currentOperation() {
  const values = Array.from(activeOperations.values());
  return values.length ? values[values.length - 1] : null;
}

function showRunning(op) {
  globalThis.clearTimeout(hideTimer);
  setOverlayState('running', titleForPath(op.path), t('operation.working'));
}

function handleStart(event) {
  const detail = event.detail || {};
  const id = String(detail.id || '');
  if (!id) return;
  activeOperations.set(id, {
    id,
    method: String(detail.method || ''),
    path: String(detail.path || ''),
    startedAt: performance.now()
  });

  globalThis.clearTimeout(revealTimer);
  revealTimer = globalThis.setTimeout(() => {
    const op = currentOperation();
    if (op) showRunning(op);
  }, 120);
}

function handleEnd(event) {
  const detail = event.detail || {};
  const id = String(detail.id || '');
  if (!id || !activeOperations.has(id)) return;
  const completed = activeOperations.get(id);
  activeOperations.delete(id);
  globalThis.clearTimeout(revealTimer);

  const next = currentOperation();
  if (next) {
    showRunning(next);
    return;
  }

  setOverlayState('success', titleForPath(completed.path), t('operation.success'));
  globalThis.clearTimeout(hideTimer);
  hideTimer = globalThis.setTimeout(hideOverlay, 750);
}

function handleError(event) {
  const detail = event.detail || {};
  const id = String(detail.id || '');
  const failed = activeOperations.get(id) || { path: detail.path || '' };
  if (id) activeOperations.delete(id);
  globalThis.clearTimeout(revealTimer);

  const next = currentOperation();
  if (next) {
    showRunning(next);
    return;
  }

  const publicMessage = String(detail.message || t('operation.failed'));
  setOverlayState('error', titleForPath(failed.path), publicMessage);
  globalThis.clearTimeout(hideTimer);
  hideTimer = globalThis.setTimeout(hideOverlay, 2200);
}

export function initOperationFeedback() {
  document.addEventListener('gedefense:operation-start', handleStart);
  document.addEventListener('gedefense:operation-end', handleEnd);
  document.addEventListener('gedefense:operation-error', handleError);
  byID('operationClose')?.addEventListener('click', hideOverlay);
}
