// STATUS: DIAMANT VGT SUPREME
'use strict';

// Shell navigation and operator helpers: view switching, the authentication
// and undo surfaces, protection removal, incident actions and the shared DOM
// utilities. Split out of the former single app.js module
// (refactoring wave 2a, structure-only).

import {
  APIError,
  acknowledgeIncident,
  confineIncident,
  deleteBlock,
  getToken,
  mintDirectStepUp,
  mintGatewayStepUp,
  removeAllowlist,
  undoAllowlist,
  undoBlock
} from '../api.js';
import { drawTraffic } from '../charts.js';
import {
  locale,
  t
} from '../i18n.js';
import {
  byID,
  text,
  toast
} from '../render.js';
import {
  refresh,
  snapshot
} from './state.js';
import {
  applySettings,
  loadHardening,
  loadSettings,
  loadTransactions
} from './views_overview.js';
import {
  loadCases,
  loadCells,
  loadQuarantine
} from './views_xdr_spyware.js';
import {
  loadBootTrust,
  loadIntegrity
} from './views_logs_audit.js';
import { loadTitanView } from './views_titan_styx.js';
import { loadProtectionState } from '../protection.js';
import { loadL7View } from '../l7.js';
import { loadCMSView } from '../cms.js';
import { loadKineticView } from '../kinetic.js';
import { loadThreatIntelView } from '../threat-intel.js';
import { loadXDRView } from '../xdr.js';
import { loadAntispywareView } from './views_antispyware.js';
import { loadExposureView } from '../v61/exposure.js';
import { loadWorkersView } from '../v61/workers.js';
import { loadTLSView } from '../v61/tls.js';
import { loadLPEView } from '../v61/lpe.js';
import { loadEdgeView } from '../v61/edge.js';
import { loadStyxView } from '../v61/v6-styx.js';
import { loadTitanExecView } from '../v61/v6-titan.js';
import { loadCellsView } from '../v61/v6-cells.js';
import { loadLockdownView } from '../v61/v6-lockdown.js';
import { loadWitnessView } from '../v61/v6-witness.js';
import { loadSetupWizard } from '../setup-wizard.js';

// F-22: one protection-reducing removal is surfaced with its server-side undo
// window at a time. The token is opaque and only the control plane can redeem it.
let removalState = { kind: '', target: '', blockID: '', expected: '', busy: false };
let undoState = { token: '', kind: '', target: '', expiresAt: 0, timer: 0 };

const viewMeta = {
  overview: ['view.overview.eyebrow', 'view.overview.title'],
  protection: ['view.protection.eyebrow', 'view.protection.title'],
  l7: ['view.l7.eyebrow', 'view.l7.title'],
  cms: ['view.cms.eyebrow', 'view.cms.title'],
  kinetic: ['view.kinetic.eyebrow', 'view.kinetic.title'],
  'threat-intel': ['view.threatIntel.eyebrow', 'view.threatIntel.title'],
  hardening: ['view.hardening.eyebrow', 'view.hardening.title'],
  detection: ['view.detection.eyebrow', 'view.detection.title'],
  integrity: ['view.integrity.eyebrow', 'view.integrity.title'],
  boot: ['view.boot.eyebrow', 'view.boot.title'],
  xdr: ['view.xdr.eyebrow', 'view.xdr.title'],
  antispyware: ['antispyware.eyebrow', 'antispyware.title'],
  network: ['view.network.eyebrow', 'view.network.title'],
  policy: ['view.policy.eyebrow', 'view.policy.title'],
  forensics: ['view.forensics.eyebrow', 'view.forensics.title'],
  release: ['view.release.eyebrow', 'view.release.title'],
  settings: ['view.settings.eyebrow', 'view.settings.title'],
  system: ['view.system.eyebrow', 'view.system.title'],
  titan: ['view.titan.eyebrow', 'view.titan.title'],
  'web-exposure': ['v61.exposure.eyebrow', 'v61.exposure.title'],
  'worker-guard': ['v61.workers.eyebrow', 'v61.workers.title'],
  'tls-sensor': ['v61.tls.eyebrow', 'v61.tls.title'],
  'lpe-guard': ['v61.lpe.eyebrow', 'v61.lpe.title'],
  'edge-proxy': ['v61.edge.eyebrow', 'v61.edge.title'],
  styx: ['v61.v6.styx.eyebrow', 'v61.v6.styx.title'],
  'titan-exec': ['v61.v6.titan.eyebrow', 'v61.v6.titan.title'],
  'parser-cells': ['v61.v6.cells.eyebrow', 'v61.v6.cells.title'],
  lockdown: ['v61.v6.lockdown.eyebrow', 'v61.v6.lockdown.title'],
  witness: ['v61.v6.witness.eyebrow', 'v61.v6.witness.title'],
  'setup-wizard': ['wizard.eyebrow', 'wizard.title']
};

function number(value) {
  return Number(value || 0).toLocaleString(locale());
}

function activateView(name) {
  const selected = Object.prototype.hasOwnProperty.call(viewMeta, name) ? name : 'overview';
  const sidebar = byID('sidebar');
  const backdrop = byID('sidebarMobileBackdrop');
  if (sidebar?.classList.contains('mobile-open')) {
    sidebar.classList.remove('mobile-open');
    if (backdrop) backdrop.classList.remove('active');
  }
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
  if (selected === 'protection') loadProtectionState(snapshot).catch(handleActionError);
  if (selected === 'l7') loadL7View(snapshot).catch(handleActionError);
  if (selected === 'cms') loadCMSView(snapshot).catch(handleActionError);
  if (selected === 'kinetic') loadKineticView().catch(handleActionError);
  if (selected === 'threat-intel') loadThreatIntelView().catch(handleActionError);
  if (selected === 'xdr') loadXDRView(snapshot).catch(handleActionError);
  if (selected === 'antispyware') loadAntispywareView(snapshot).catch(handleActionError);
  if (selected === 'hardening') Promise.all([loadHardening(), loadTransactions()]).catch(handleActionError);
  if (selected === 'integrity') loadIntegrity().catch(handleActionError);
  if (selected === 'boot') loadBootTrust().catch(handleActionError);
  if (selected === 'settings') Promise.all([loadSettings(), loadTransactions()]).catch(handleActionError);
  if (selected === 'forensics') Promise.all([loadQuarantine(), loadCases()]).catch(handleActionError);
  if (selected === 'system') loadCells().catch(handleActionError);
  if (selected === 'titan') loadTitanView().catch(handleActionError);
  if (selected === 'web-exposure') loadExposureView().catch(handleActionError);
  if (selected === 'worker-guard') loadWorkersView().catch(handleActionError);
  if (selected === 'tls-sensor') loadTLSView().catch(handleActionError);
  if (selected === 'lpe-guard') loadLPEView().catch(handleActionError);
  if (selected === 'edge-proxy') loadEdgeView().catch(handleActionError);
  if (selected === 'styx') loadStyxView().catch(handleActionError);
  if (selected === 'titan-exec') loadTitanExecView().catch(handleActionError);
  if (selected === 'parser-cells') loadCellsView().catch(handleActionError);
  if (selected === 'lockdown') loadLockdownView().catch(handleActionError);
  if (selected === 'witness') loadWitnessView().catch(handleActionError);
  if (selected === 'setup-wizard') loadSetupWizard().catch(handleActionError);
}

function setChecked(id, value) {
  const element = byID(id);
  if (element) element.checked = Boolean(value);
}

function setValue(id, value) {
  const element = byID(id);
  if (element) element.value = value ?? '';
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

// ------------------------------------------------------------------ F-22 protection removal
// Removing a block or allowlist entry reduces protection. The server demands a
// target-derived typed phrase plus an operator reason, and returns a short-lived
// server-side undo token. This surface never assumes success or invents an undo
// window: it renders the server answer, and shows the token lifetime it received.

function protectionRemovalPhrase(kind, target) {
  return kind === 'allowlist' ? `REMOVE ALLOWLIST ${target}` : `REMOVE BLOCK ${target}`;
}

function runeLength(value) {
  return Array.from(String(value ?? '')).length;
}

function showRemovalError(message) {
  const node = byID('removalError');
  if (!node) return;
  node.hidden = !message;
  node.textContent = message ? String(message) : '';
}

function setRemovalBusy(busy) {
  const button = byID('removalSubmit');
  if (!button) return;
  button.disabled = Boolean(busy);
  button.setAttribute('aria-busy', busy ? 'true' : 'false');
}

function openProtectionRemoval(kind, item) {
  const target = String(item?.target ?? '').trim();
  if (!target) {
    toast(t('toast.operationFailed'), 'danger');
    return;
  }
  removalState = {
    kind,
    target,
    blockID: kind === 'block' ? String(item?.id ?? '') : '',
    expected: protectionRemovalPhrase(kind, target),
    busy: false
  };
  text('removalTitle', t(kind === 'allowlist' ? 'removal.titleAllowlist' : 'removal.titleBlock'));
  text('removalSubtitle', t(kind === 'allowlist' ? 'removal.subtitleAllowlist' : 'removal.subtitleBlock'));
  text('removalTarget', target);
  text('removalExpectedPhrase', removalState.expected);
  const confirmation = byID('removalConfirmation');
  if (confirmation) {
    confirmation.value = '';
    confirmation.placeholder = removalState.expected;
  }
  const reason = byID('removalReason');
  if (reason) reason.value = '';
  showRemovalError('');
  setRemovalBusy(false);
  byID('protectionRemovalDialog')?.showModal();
  confirmation?.focus();
}

function formatUndoRemaining(seconds) {
  const remaining = Math.max(0, Math.ceil(Number(seconds) || 0));
  const minutes = Math.floor(remaining / 60);
  return `${minutes}:${String(remaining % 60).padStart(2, '0')}`;
}

function stopUndoTimer() {
  if (undoState.timer) globalThis.clearInterval(undoState.timer);
  undoState.timer = 0;
}

function hideUndoBanner() {
  stopUndoTimer();
  const banner = byID('undoBanner');
  if (banner) banner.hidden = true;
  text('undoMessage', '');
  const button = byID('undoAction');
  if (button) {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
  undoState = { token: '', kind: '', target: '', expiresAt: 0, timer: 0 };
}

function updateUndoCountdown() {
  const remaining = Math.max(0, Math.ceil((undoState.expiresAt - Date.now()) / 1000));
  if (remaining <= 0) {
    stopUndoTimer();
    text('undoMessage', t('removal.undoExpired', { target: undoState.target }));
    const button = byID('undoAction');
    if (button) button.disabled = true;
    return;
  }
  text('undoMessage', t('removal.undoMessage', { target: undoState.target, time: formatUndoRemaining(remaining) }));
}

function showUndo(kind, target, result) {
  const token = String(result?.undo_token || '').trim();
  const expires = Number(result?.undo_expires_seconds || 0);
  if (!token || !(expires > 0)) {
    // The server removed the protection but could not retain an undo token; say so
    // instead of offering a button that can never work.
    toast(t('removal.undoUnavailable'), 'warning');
    return;
  }
  stopUndoTimer();
  undoState = { token, kind, target, expiresAt: Date.now() + expires * 1000, timer: 0 };
  const banner = byID('undoBanner');
  if (banner) banner.hidden = false;
  const button = byID('undoAction');
  if (button) {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
  updateUndoCountdown();
  undoState.timer = globalThis.setInterval(updateUndoCountdown, 1000);
}

async function undoProtectionRemoval() {
  if (!undoState.token) return;  const token = undoState.token;
  const kind = undoState.kind;
  const target = undoState.target;
  const button = byID('undoAction');
  if (button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  }
  try {
    if (kind === 'allowlist') {
      const settings = await undoAllowlist(token);
      if (settings) applySettings(settings);
    } else {
      await undoBlock(token);
    }
    hideUndoBanner();
    toast(t('removal.undoSuccess', { target }), 'good');
    await refresh();
  } catch (error) {
    if (error instanceof APIError && error.status === 404) {
      hideUndoBanner();
      toast(t('removal.undoExpired', { target }), 'danger');
      return;
    }
    if (error instanceof APIError && error.status === 401) {
      hideUndoBanner();
      handleActionError(error);
      return;
    }
    toast(`${t('removal.undoFailed')} ${error?.message || ''}`.trim(), 'danger');
    if (button) {
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }
}

function dismissUndo() {
  hideUndoBanner();
}

async function submitProtectionRemoval(event) {
  event.preventDefault();
  if (removalState.busy) return;
  const confirmation = String(byID('removalConfirmation')?.value || '').trim();
  const reason = String(byID('removalReason')?.value || '').trim();
  if (confirmation !== removalState.expected) {
    showRemovalError(t('removal.confirmationMismatch', { phrase: removalState.expected }));
    byID('removalConfirmation')?.focus();
    return;
  }
  const runes = runeLength(reason);
  if (runes < 8 || runes > 240) {
    showRemovalError(t('removal.reasonInvalid'));
    byID('removalReason')?.focus();
    return;
  }
  const { kind, target, blockID } = removalState;
  showRemovalError('');
  removalState.busy = true;
  setRemovalBusy(true);
  try {
    const result = kind === 'allowlist'
      ? await removeAllowlist(target, confirmation, reason)
      : await deleteBlock(blockID, confirmation, reason);
    if (kind === 'allowlist' && result?.settings) applySettings(result.settings);
    byID('protectionRemovalDialog')?.close();
    toast(t(kind === 'allowlist' ? 'removal.removedAllowlist' : 'removal.removedBlock', { target }), 'good');
    showUndo(kind, target, result);
    await refresh();
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      byID('protectionRemovalDialog')?.close();
      handleActionError(error);
      return;
    }
    showRemovalError(`${t('removal.failed')} ${error?.message || ''}`.trim());
  } finally {
    removalState.busy = false;
    setRemovalBusy(false);
  }
}

// Kept as the table callback name: renderRules hands over the whole block entry so
// the typed confirmation phrase can be derived from its target.
function removeRule(block) {
  const entry = typeof block === 'object' && block
    ? block
    : (snapshot?.blocks || []).find(candidate => candidate.id === block);
  if (!entry?.id || !entry?.target) {
    toast(t('toast.operationFailed'), 'danger');
    return;
  }
  openProtectionRemoval('block', entry);
}

// Manual isolation from the incident row: the operator names the reason, the platform resolves the
// Gaia Cell that owns the workload and applies the change through the transaction engine.
async function confineWorkload(incident) {
  if (!incident || !incident.id) return;
  const entered = window.prompt(t('cells.confine'), '');
  const reason = (entered || '').trim();
  if (reason.length < 3) {
    toast(t('cells.reasonRequired'), 'bad');
    return;
  }
  try {
    await confineIncident(incident.id, 'revoke-network', reason);
    toast(t('cells.confineDone'), 'good');
    await refresh();
  } catch (error) {
    handleActionError(error);
    toast(t('cells.confineFailed'), 'bad');
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

function on(id, event, handler) {
  const node = byID(id);
  if (node) node.addEventListener(event, handler);
}

// ------------------------------------------------------------------ authentication

// setAuthState drives the one live region on the authentication surface. It is a state
// machine rather than a toast because the operator has to be able to tell a rejected
// key from an unreachable control plane before deciding what to do next.
function setAuthState(state, message) {
  const node = byID('authState');
  if (!node) return;
  if (!state) {
    node.textContent = '';
    node.removeAttribute('data-state');
    return;
  }
  node.setAttribute('data-state', state);
  node.textContent = message || '';
}

// populateAuthFacts fills the identity plane from what this host can attest before any
// credential exists. Nothing here is inferred: the node is the origin the dashboard was
// served from, and the channel is the transport it was served over.
function populateAuthFacts() {
  const origin = globalThis.location ? String(globalThis.location.host || '') : '';
  text('authNode', origin || t('auth.nodeUnknown'));

  const channel = byID('authChannel');
  if (!channel) return;
  const secure = Boolean(globalThis.location && globalThis.location.protocol === 'https:');
  channel.textContent = secure ? t('auth.channelTLS') : t('auth.channelPlain');
  // The distinction matters operationally, so it is carried in the text and not only in
  // the colour of the row.
  channel.setAttribute('data-secure', secure ? 'yes' : 'no');
}

// setRestartState drives the single live region on the lifecycle surface.
function setRestartState(state, message) {
  const node = byID('restartState');
  if (!node) return;
  if (!state) {
    node.textContent = '';
    node.removeAttribute('data-state');
    return;
  }
  node.setAttribute('data-state', state);
  node.textContent = message || '';
}

function openAuthDialog() {
  populateAuthFacts();
  setAuthState(null, '');
  const dialog = byID('authDialog');
  if (dialog && !dialog.open) dialog.showModal();
}

async function withCriticalStepUp(actionLabel, callback) {
  if (getToken()) {
    const minted = await mintDirectStepUp();
    if (!minted?.step_up) throw new Error(t('stepUp.unavailable'));
    return callback(minted.step_up);
  }
  const dialog = byID('stepUpDialog');
  const form = byID('stepUpForm');
  const input = byID('stepUpPassword');
  const labelNode = byID('stepUpActionLabel');
  const stateNode = byID('stepUpState');
  if (!dialog || !form || !input) {
    throw new Error(t('stepUp.unavailable'));
  }
  if (labelNode) labelNode.textContent = String(actionLabel || '');
  if (stateNode) stateNode.textContent = '';
  input.value = '';
  return new Promise(resolve => {
    const cleanup = () => {
      form.removeEventListener('submit', onSubmit);
      dialog.removeEventListener('close', onClose);
      input.value = '';
    };
    const onClose = () => {
      cleanup();
      resolve(null);
    };
    const onSubmit = async event => {
      event.preventDefault();
      const password = String(input.value || '');
      input.value = '';
      if (password.length < 12) {
        if (stateNode) stateNode.textContent = t('stepUp.passwordShort');
        input.focus();
        return;
      }
      const confirmBtn = byID('stepUpConfirm');
      if (confirmBtn) confirmBtn.disabled = true;
      if (stateNode) stateNode.textContent = t('stepUp.verifying');
      try {
        const res = await mintGatewayStepUp(password);
        if (!res?.step_up_proof) throw new Error(t('stepUp.unavailable'));
        cleanup();
        dialog.close();
        const outcome = await callback(res.step_up_proof);
        resolve(outcome === undefined ? true : outcome);
      } catch (err) {
        if (stateNode) stateNode.textContent = err?.message || t('stepUp.rejected');
      } finally {
        if (confirmBtn) confirmBtn.disabled = false;
      }
    };
    form.addEventListener('submit', onSubmit);
    dialog.addEventListener('close', onClose);
    dialog.showModal();
    input.focus();
  });
}

export {
  activateView,
  acknowledge,
  confineWorkload,
  dismissUndo,
  downloadJSON,
  emptyTable,
  handleActionError,
  number,
  on,
  openAuthDialog,
  openProtectionRemoval,
  populateAuthFacts,
  removeRule,
  setAuthState,
  setChecked,
  setRestartState,
  setValue,
  submitProtectionRemoval,
  undoProtectionRemoval,
  withCriticalStepUp
};
