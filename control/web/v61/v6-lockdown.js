// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6 panel — emergency lockdown.
//
// Destructive actions are confirm-gated with the exact phrases the API requires
// ("TRIGGER LOCKDOWN", "CLEAR:LOCKDOWN") plus an operator reason of at least
// eight characters. Clear sends the epoch the status endpoint reported, so a
// stale dialog cannot release an epoch the engine no longer holds. Every refusal
// is printed verbatim; the view never reports "released" on a refusal.

import { t } from '../i18n.js';
import { toast } from '../render.js';
import {
  asArray,
  asObject,
  bindAction,
  confirmAction,
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

const STATUS_PATH = '/api/v1/lockdown/status';

let currentEpoch = '';

export function initLockdownModule() {
  initV61Shared();
  bindAction('lockdownRefreshBtn', () => loadLockdownView());
  bindAction('lockdownArmBtn', () => armLockdown('locked'));
  bindAction('lockdownDisarmBtn', () => armLockdown('unlocked'));
  bindAction('lockdownTriggerBtn', triggerLockdown);
  bindAction('lockdownClearBtn', clearLockdown);
}

export async function loadLockdownView() {
  try {
    renderStatus(asObject(await getJSON(STATUS_PATH)));
  } catch (error) {
    setNotice('lockdownReason', refusalText(error, 'v61.v6.lockdown.unavailable'), 'bad');
    setTone('lockdownPill', t('v61.v6.common.unavailable'), 'danger');
  }
}

async function armLockdown(mode) {
  const locked = mode === 'locked';
  const confirmed = await confirmAction({
    titleKey: locked ? 'v61.v6.lockdown.armTitle' : 'v61.v6.lockdown.disarmTitle',
    bodyKey: locked ? 'v61.v6.lockdown.armBody' : 'v61.v6.lockdown.disarmBody',
    submitKey: locked ? 'v61.v6.lockdown.armSubmit' : 'v61.v6.lockdown.disarmSubmit',
    danger: locked,
    detail: t('v61.v6.lockdown.armDetail')
  });
  if (!confirmed) return;
  await mutate('/api/v1/lockdown/arm', { mode, reason: confirmed.reason }, 'v61.v6.lockdown.armDone');
}

async function triggerLockdown() {
  const confirmed = await confirmAction({
    titleKey: 'v61.v6.lockdown.triggerTitle',
    bodyKey: 'v61.v6.lockdown.triggerBody',
    submitKey: 'v61.v6.lockdown.triggerSubmit',
    phrase: 'TRIGGER LOCKDOWN',
    detail: t('v61.v6.lockdown.triggerDetail')
  });
  if (!confirmed) return;
  await mutate('/api/v1/lockdown/trigger', { confirmation: 'TRIGGER LOCKDOWN', reason: confirmed.reason, source: 'manual' }, 'v61.v6.lockdown.triggerDone');
}

async function clearLockdown() {
  if (!currentEpoch) {
    setNotice('lockdownActionResult', t('v61.v6.lockdown.epochMissing'), 'bad');
    return;
  }
  const epoch = currentEpoch;
  const confirmed = await confirmAction({
    titleKey: 'v61.v6.lockdown.clearTitle',
    bodyKey: 'v61.v6.lockdown.clearBody',
    submitKey: 'v61.v6.lockdown.clearSubmit',
    phrase: 'CLEAR:LOCKDOWN',
    detail: t('v61.v6.lockdown.clearDetail', { epoch })
  });
  if (!confirmed) return;
  await mutate('/api/v1/lockdown/clear', { confirmation: 'CLEAR:LOCKDOWN', reason: confirmed.reason, expected_epoch: epoch }, 'v61.v6.lockdown.clearDone');
}

async function mutate(path, body, doneKey) {
  setNotice('lockdownActionResult', '');
  try {
    const result = asObject(await sendJSON(path, 'POST', body));
    const view = asObject(result.lockdown);
    const message = t(doneKey);
    setNotice('lockdownActionResult', message, 'good');
    toast(message, 'good');
    if (Object.keys(view).length) renderStatus(view);
    else await loadLockdownView();
  } catch (error) {
    setNotice('lockdownActionResult', refusalText(error, 'v61.v6.lockdown.actionFailed'), 'bad');
    toast(refusalText(error), 'danger', error?.errorID || '');
  }
}

function renderStatus(status) {
  const core = asObject(status.core);
  const cooldown = asObject(status.cooldown);
  const settings = asObject(status.settings);
  const state = String(status.state || '');
  const latched = status.latched === true;
  const armed = status.armed === true;
  const enabled = status.enabled === true;
  currentEpoch = String(status.epoch || core.epoch || '').trim();

  setTone('lockdownPill', stateLabel(state), stateTone(state));
  setText('lockdownStateKpi', stateLabel(state));
  setTone('lockdownArmedKpi', t(armed ? 'v61.v6.lockdown.armed' : 'v61.v6.lockdown.notArmed'), armed ? 'good' : 'muted');
  setTone('lockdownLatchedKpi', t(latched ? 'v61.v6.lockdown.latched' : 'v61.v6.lockdown.notLatched'), latched ? 'danger' : 'good');
  setText('lockdownModeKpi', status.mode || '—');
  setText('lockdownEpochKpi', currentEpoch || '—');
  setText('lockdownCoreKpi', core.capability || t('v61.v6.common.unknown'));
  setText('lockdownPendingKpi', formatCount(status.pending_sources));
  setText('lockdownFalsePosKpi', formatCount(status.false_positive_guards));
  setText('lockdownDroppedKpi', formatCount(status.dropped_core_events));
  setText('lockdownCooldownKpi', t(cooldown.active ? 'v61.v6.lockdown.cooldownActive' : 'v61.v6.lockdown.cooldownClear', {
    seconds: formatCount(cooldown.remaining_seconds || cooldown.seconds)
  }));

  setTone('lockdownEnabledKpi', t(enabled ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), enabled ? 'good' : 'muted');
  setText('lockdownEvidenceKpi', status.evidence || '—');
  setText('lockdownUpdatedKpi', formatStamp(status.updated_at));
  setTone('lockdownDuressKpi', t(settings.duress_configured || status.duress_configured ? 'v61.v6.common.yes' : 'v61.v6.common.no'), settings.duress_configured || status.duress_configured ? 'good' : 'muted');
  setText('lockdownRequireSources', formatCount(settings.require_sources));
  setText('lockdownCoreApplied', asArray(core.applied).join(', ') || t('v61.v6.common.none'));
  setText('lockdownCoreUnsupported', asArray(core.unsupported).join(', ') || t('v61.v6.common.none'));

  const trigger = asObject(status.trigger);
  setText('lockdownTriggerInfo', Object.keys(trigger).length
    ? t('v61.v6.lockdown.triggerInfo', {
      source: trigger.source || '—',
      reason: trigger.reason || '—',
      at: formatStamp(trigger.at)
    })
    : t('v61.v6.lockdown.noTrigger'));
  const lastClear = asObject(status.last_clear);
  setText('lockdownClearInfo', Object.keys(lastClear).length
    ? t('v61.v6.lockdown.clearInfo', { at: formatStamp(lastClear.at), reason: lastClear.reason || '—' })
    : t('v61.v6.lockdown.noClear'));

  const degraded = [String(status.degraded || '').trim(), String(core.last_error || '').trim()].filter(Boolean);
  setNotice('lockdownReason', degraded.join(' · '), latched ? 'bad' : 'warn');

  renderRows('lockdownPhaseRows', 4, asArray(status.phases).map(asObject).map(phase => [
    { text: phase.phase || '—', cls: 'v61-mono' },
    { pill: { label: phase.status || '—', tone: phaseTone(phase.status) } },
    { text: phase.targets === undefined ? '—' : formatCount(phase.targets), cls: 'v61-mono' },
    { text: phase.detail || '—', cls: 'v61-tight', title: String(phase.detail || '') }
  ]), 'v61.v6.lockdown.empty.phases');
}

function stateLabel(state) {
  switch (String(state || '').toLowerCase()) {
    case 'latched':
      return t('v61.v6.lockdown.state.latched');
    case 'armed':
      return t('v61.v6.lockdown.state.armed');
    case 'clearing':
      return t('v61.v6.lockdown.state.clearing');
    case 'triggering':
      return t('v61.v6.lockdown.state.triggering');
    case 'idle':
      return t('v61.v6.lockdown.state.idle');
    case 'unavailable':
      return t('v61.v6.common.unavailable');
    default:
      return t('v61.v6.common.unknown');
  }
}

function stateTone(state) {
  switch (String(state || '').toLowerCase()) {
    case 'idle':
    case 'armed':
      return 'good';
    case 'triggering':
    case 'clearing':
      return 'warn';
    case 'latched':
    case 'unavailable':
      return 'danger';
    default:
      return 'muted';
  }
}

function phaseTone(status) {
  switch (String(status || '').toLowerCase()) {
    case 'applied':
    case 'ok':
      return 'good';
    case 'failed':
    case 'error':
      return 'danger';
    case 'unsupported':
    case 'skipped':
      return 'warn';
    default:
      return 'muted';
  }
}
