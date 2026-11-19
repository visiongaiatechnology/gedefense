// STATUS: DIAMANT VGT SUPREME
'use strict';

// Module D — LPE kill-chain (socket policy, StyX web-ingress profile, kernel
// hardening baseline).
//
// The socket policy matrix reports `applied` per cgroup, because a plan that was
// rendered but never written to the kernel is not enforcement. Applying is a
// single confirm-gated mutation; the backend's refusal is printed verbatim and
// the view re-reads the status instead of assuming the plan took effect.

import { t } from '../i18n.js';
import { toast } from '../render.js';
import {
  asArray,
  asBool,
  asObject,
  bindAction,
  confirmAction,
  formatCount,
  getJSON,
  initV61Shared,
  refusalText,
  renderRows,
  sendJSON,
  setNotice,
  setText,
  setTone,
  showRefusal
} from './v6.js';

const STATUS_PATH = '/api/v1/lpe-guard/status';
const APPLY_PATH = '/api/v1/lpe-guard/apply';

export function initLPEModule() {
  initV61Shared();
  bindAction('lpeGuardRefreshBtn', () => loadLPEView());
  bindAction('lpeGuardApplyBtn', applyPlan);
}

export async function loadLPEView() {
  try {
    renderStatus(asObject(await getJSON(STATUS_PATH)));
  } catch (error) {
    setNotice('lpeGuardReason', refusalText(error, 'v61.lpe.unavailable'));
    setTone('lpeGuardPill', t('v61.v6.common.unavailable'), 'danger');
  }
}

async function applyPlan() {
  const confirmed = await confirmAction({
    titleKey: 'v61.lpe.confirm.title',
    bodyKey: 'v61.lpe.confirm.body',
    submitKey: 'v61.lpe.confirm.submit',
    danger: false,
    detail: t('v61.lpe.confirm.detail')
  });
  if (!confirmed) return;
  setNotice('lpeGuardResult', '');
  let result;
  try {
    result = asObject(await sendJSON(APPLY_PATH, 'POST', {}));
  } catch (error) {
    // A partial apply answers 409 and an apply that changed nothing answers 503;
    // the control plane's concrete per-path error is shown verbatim. Never a
    // green toast for a result the kernel did not confirm.
    showRefusal('lpeGuardResult', error, 'v61.lpe.applyFailed');
    await loadLPEView();
    return;
  }
  // The apply result is the honesty record: `enforcement` names what really ran,
  // the *_error fields name every path that did not, and `styx_apply_state` is
  // the projected profile state. Module blacklisting stays manual_required.
  const enforcement = asObject(result.enforcement);
  const styxState = String(result.styx_apply_state || '').trim();
  const errors = ['socket_error', 'styx_error', 'hardening_error']
    .map(key => String(result[key] || '').trim())
    .filter(Boolean);
  const enforcementText = Object.keys(enforcement)
    .map(key => `${key}=${String(enforcement[key] || '')}`)
    .join(', ');
  const detail = [enforcementText, styxState ? `styx_apply_state=${styxState}` : '', errors.join(' · ')]
    .filter(Boolean)
    .join(' · ');
  const message = detail ? t('v61.lpe.appliedDetail', { detail }) : t('v61.lpe.applied');
  const manualOnly = String(enforcement.block_lpe_modules || '') === 'manual_required';
  const aslrState = String(enforcement.aslr || '');
  const aslrPending = aslrState !== '' && !['applied', 'already_applied', 'manual_required'].includes(aslrState);
  if (errors.length) {
    setNotice('lpeGuardResult', `${t('v61.lpe.applyFailed')} ${detail}`.trim(), 'bad');
    toast(t('v61.lpe.applyFailed'), 'danger');
  } else if (manualOnly || aslrPending) {
    // Requested enforcement that is only a plan is a warning, not a success.
    setNotice('lpeGuardResult', message, 'warn');
    toast(message, 'warning');
  } else {
    setNotice('lpeGuardResult', message, 'good');
    toast(message, 'good');
  }
  await loadLPEView();
}

function renderStatus(status) {
  const socketPolicy = asArray(status.socket_policy).map(asObject);
  const hardening = asArray(status.hardening).map(asObject);
  const profile = asObject(status.styx_profile);
  const mode = String(status.mode || '');
  const capability = String(status.capability || '');
  const pass = hardening.filter(entry => String(entry.state || '').toLowerCase() === 'pass').length;
  const fail = hardening.filter(entry => String(entry.state || '').toLowerCase() === 'fail').length;
  const enforceable = hardening.filter(entry => asBool(entry.enforceable)).length;
  const applied = socketPolicy.filter(entry => asBool(entry.applied)).length;

  setTone('lpeGuardPill', capability || t('v61.v6.common.unknown'), capability === 'active' ? 'good' : capability ? 'warn' : 'danger');
  setText('lpeModeKpi', mode || t('v61.v6.common.unknown'));
  setText('lpeCapabilityKpi', capability || t('v61.v6.common.unknown'));
  setText('lpePoliciesKpi', formatCount(socketPolicy.length));
  setText('lpeAppliedKpi', formatCount(applied));
  setText('lpePassKpi', formatCount(pass));
  setText('lpeFailKpi', formatCount(fail));
  setText('lpeEnforceableKpi', formatCount(enforceable));
  setTone('lpeStyxState', t(asBool(profile.enabled) ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), asBool(profile.enabled) ? 'good' : 'muted');

  setNotice('lpeGuardReason', String(status.reason || '').trim(), capability === 'active' ? 'warn' : 'bad');

  setText('lpeStyxName', profile.name || '—');
  setText('lpeStyxAllow', asArray(profile.allow).join(', ') || t('v61.v6.common.none'));
  setText('lpeStyxDns', asArray(profile.dns).join(', ') || t('v61.v6.common.none'));
  setText('lpeStyxBackend', asArray(profile.backend).join(', ') || t('v61.v6.common.none'));

  renderRows('lpeSocketRows', 4, socketPolicy.map(entry => [
    { text: entry.cgroup_id === undefined ? '—' : formatCount(entry.cgroup_id), cls: 'v61-mono' },
    { text: entry.comm || '—', cls: 'v61-mono' },
    { badges: asArray(entry.deny).map(deny => ({ label: deny, tone: 'danger' })) },
    { pill: { label: t(asBool(entry.applied) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(entry.applied) ? 'good' : 'warn' } }
  ]), 'v61.lpe.empty.policies');

  renderRows('lpeHardeningRows', 5, hardening.map(entry => [
    { text: entry.key || '—', cls: 'v61-mono v61-tight', title: String(entry.key || '') },
    { text: entry.expected || '—', cls: 'v61-mono' },
    { text: entry.actual || '—', cls: 'v61-mono' },
    { pill: { label: stateLabel(entry.state), tone: stateTone(entry.state) } },
    { pill: { label: t(asBool(entry.enforceable) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(entry.enforceable) ? 'warn' : 'muted' } }
  ]), 'v61.lpe.empty.hardening');
}

function stateLabel(state) {
  switch (String(state || '').toLowerCase()) {
    case 'pass':
      return t('v61.lpe.state.pass');
    case 'fail':
      return t('v61.lpe.state.fail');
    case 'warn':
      return t('v61.lpe.state.warn');
    default:
      return t('v61.v6.common.unknown');
  }
}

function stateTone(state) {
  switch (String(state || '').toLowerCase()) {
    case 'pass':
      return 'good';
    case 'fail':
      return 'danger';
    case 'warn':
      return 'warn';
    default:
      return 'muted';
  }
}
