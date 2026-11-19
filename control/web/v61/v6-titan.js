// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6 panel — Titan exec gate (kernel exec/mmap decisions).
//
// The projection separates what the syncer applied from what the kernel reports
// (applied vs kernel entries/scopes) and from the bounded ingestion counters. A
// control plane without a wired syncer answers with an honest unavailable state;
// this view shows that state instead of a synthetic green sensor.

import { t } from '../i18n.js';
import {
  asObject,
  bindAction,
  formatCount,
  formatStamp,
  getJSON,
  initV61Shared,
  pick,
  refusalText,
  setNotice,
  setText,
  setTone
} from './v6.js';

const STATUS_PATH = '/api/v1/titan/exec/status';

export function initTitanExecModule() {
  initV61Shared();
  bindAction('titanExecRefreshBtn', () => loadTitanExecView());
}

export async function loadTitanExecView() {
  try {
    renderStatus(asObject(await getJSON(STATUS_PATH)));
  } catch (error) {
    setNotice('titanExecReason', refusalText(error, 'v61.v6.titan.unavailable'), 'bad');
    setTone('titanExecPill', t('v61.v6.common.unavailable'), 'danger');
  }
}

function renderStatus(status) {
  const sync = asObject(status.sync);
  const kernel = asObject(status.kernel);
  const counters = asObject(status.counters);
  const health = asObject(kernel.health);
  const state = String(status.state || sync.state || '');

  setTone('titanExecPill', stateLabel(state), stateTone(state));
  setText('titanExecStateKpi', stateLabel(state));
  setText('titanExecCapabilityKpi', status.capability || sync.capability || t('v61.v6.common.unknown'));
  setText('titanExecSensorKpi', status.sensor_state || t('v61.v6.common.unknown'));
  setText('titanExecModeKpi', sync.mode || '—');
  setText('titanExecPathKpi', kernel.path || sync.path || '—');
  setText('titanExecLsmKpi', kernel.lsm || sync.lsm || '—');
  setText('titanExecOffsetsKpi', kernel.offsets || sync.offsets || '—');
  setText('titanExecEntriesKpi', formatCount(sync.entries));
  setText('titanExecScopesKpi', formatCount(sync.scopes));
  setText('titanExecEventsKpi', formatCount(counters.events_total));
  setText('titanExecDeniesKpi', formatCount(counters.denies));
  setText('titanExecAuditsKpi', formatCount(counters.audits));
  setText('titanExecDroppedKpi', formatCount(counters.dropped));
  setText('titanExecParseKpi', formatCount(counters.parse_errors));
  setText('titanExecIncidentsKpi', formatCount(counters.incidents));
  setText('titanExecHistoryKpi', formatCount(status.history_limit));

  setText('titanExecEpoch', sync.epoch || '—');
  setText('titanExecAppliedEntries', formatCount(sync.applied_entries));
  setText('titanExecAppliedScopes', formatCount(sync.applied_scopes));
  setText('titanExecKernelEntries', formatCount(sync.kernel_entries ?? kernel.entries));
  setText('titanExecKernelScopes', formatCount(sync.kernel_scopes ?? kernel.scopes));
  setText('titanExecRejected', formatCount(sync.rejected));
  setText('titanExecUnverified', formatCount(sync.unverified));
  setText('titanExecHealthAt', kernel.health_at || sync.last_applied_at ? formatStamp(kernel.health_at || sync.last_applied_at) : t('v61.v6.common.unknown'));
  setText('titanExecKernelEmitted', sample(health, ['Emitted', 'emitted']));
  setText('titanExecKernelRingDrops', sample(health, ['RingDrops', 'ring_drops']));
  setText('titanExecKernelReadFailures', sample(health, ['ReadFailures', 'read_failures']));
  setText('titanExecKernelCtime', sample(health, ['CtimeRejects', 'ctime_rejects']));

  const errors = [
    String(kernel.health_error || '').trim(),
    String(kernel.drain_error || '').trim(),
    String(sync.last_error || '').trim()
  ].filter(Boolean);
  if (errors.length) setNotice('titanExecReason', errors.join(' · '), 'warn');
  else if (sync.retry_in_seconds) setNotice('titanExecReason', t('v61.v6.titan.retry', { seconds: formatCount(sync.retry_in_seconds) }), 'warn');
  else setNotice('titanExecReason', '', 'good');
}

function sample(health, names) {
  const value = pick(health, ...names);
  return value === undefined ? t('v61.v6.common.unknown') : formatCount(value);
}

function stateLabel(state) {
  switch (String(state || '').toLowerCase()) {
    case 'applied':
    case 'synced':
      return t('v61.v6.state.applied');
    case 'pending':
    case 'syncing':
      return t('v61.v6.state.pending');
    case 'unavailable':
      return t('v61.v6.common.unavailable');
    case 'capability-missing':
      return t('v61.v6.state.capabilityMissing');
    case 'error':
    case 'degraded':
      return t('v61.v6.state.error');
    default:
      return t('v61.v6.common.unknown');
  }
}

function stateTone(state) {
  switch (String(state || '').toLowerCase()) {
    case 'applied':
    case 'synced':
      return 'good';
    case 'pending':
    case 'syncing':
      return 'warn';
    case 'unavailable':
    case 'capability-missing':
    case 'error':
    case 'degraded':
      return 'danger';
    default:
      return 'muted';
  }
}
