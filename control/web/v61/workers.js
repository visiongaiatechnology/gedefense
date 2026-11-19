// STATUS: DIAMANT VGT SUPREME
'use strict';

// Module B — worker integrity watch.
//
// The view separates the facts the control plane can attest (crash source,
// capability, registry, counters) from the classification it derived (strict
// cgroups, storm incidents). A missing crash source is named as missing: an
// empty event list without a source is not evidence that no worker crashed.

import { t } from '../i18n.js';
import {
  asArray,
  asBool,
  asObject,
  bindAction,
  formatCount,
  formatStamp,
  getJSON,
  initV61Shared,
  refusalText,
  renderRows,
  setNotice,
  setText,
  setTone,
  severityTone
} from './v6.js';

const STATUS_PATH = '/api/v1/worker-guard/status';
const EVENTS_PATH = '/api/v1/worker-guard/events?limit=100';

export function initWorkersModule() {
  initV61Shared();
  bindAction('workerGuardRefreshBtn', () => loadWorkersView());
}

export async function loadWorkersView() {
  const [status, events] = await Promise.allSettled([getJSON(STATUS_PATH), getJSON(EVENTS_PATH)]);
  if (status.status === 'fulfilled') {
    renderStatus(asObject(status.value));
  } else {
    setNotice('workerGuardReason', refusalText(status.reason, 'v61.workers.unavailable'));
    setTone('workerGuardPill', t('v61.v6.common.unavailable'), 'danger');
  }
  if (events.status === 'fulfilled') {
    renderEvents(asArray(asObject(events.value).events).map(asObject));
  } else {
    renderRows('workerEventRows', 9, [], 'v61.workers.empty.events');
    setNotice('workerEventNotice', refusalText(events.reason, 'v61.workers.eventsUnavailable'));
  }
}

function renderStatus(status) {
  const registry = asObject(status.registry);
  const counters = asObject(status.counters);
  const source = String(status.source || 'none');
  const capability = String(status.capability || '');
  const active = capability === 'active';

  setTone('workerGuardPill', sourceLabel(source), active ? 'good' : source === 'none' ? 'danger' : 'warn');
  setText('workerSourceKpi', sourceLabel(source));
  setText('workerCapabilityKpi', capability || t('v61.v6.common.unknown'));
  setText('workerModeKpi', status.mode || '—');
  setText('workerEventsKpi', formatCount(counters.events));
  setText('workerStormsKpi', formatCount(counters.storms));
  setText('workerDeniedExecKpi', formatCount(counters.denied_exec));
  setText('workerDeniedMmapKpi', formatCount(counters.denied_mmap));
  setText('workerCommsKpi', formatCount(asArray(registry.comms).length));
  setText('workerUidsKpi', formatCount(asArray(registry.uids).length));
  setText('workerCgroupsKpi', formatCount(asArray(registry.strict_cgroups).length));

  // Two independent reasons matter: no crash source at all, and a source that is
  // configured but not active. Both are shown verbatim; neither becomes silence.
  // Shared systemd master/worker cgroups withheld from strict scope are shown too.
  const reason = [String(status.reason || '').trim(), String(status.strict_reason || '').trim()].filter(Boolean).join(' · ');
  if (reason) setNotice('workerGuardReason', reason, active ? 'warn' : 'bad');
  else if (source === 'none') setNotice('workerGuardReason', t('v61.workers.noSource'), 'bad');
  else setNotice('workerGuardReason', '');

  renderRows('workerRows', 5, asArray(status.workers).map(asObject).map(workerRow), 'v61.workers.empty.workers');
  renderRows('workerStormRows', 7, asArray(status.recent_storms).map(asObject).map(stormRow), 'v61.workers.empty.storms');
}

function sourceLabel(source) {
  switch (source) {
    case 'ebpf':
      return t('v61.workers.source.ebpf');
    case 'netlink':
      return t('v61.workers.source.netlink');
    case 'none':
      return t('v61.workers.source.none');
    default:
      return t('v61.v6.common.unknown');
  }
}

function workerRow(worker) {
  return [
    { text: worker.comm || '—', cls: 'v61-mono' },
    { text: formatCount(worker.pid), cls: 'v61-mono' },
    { text: formatCount(worker.uid), cls: 'v61-mono' },
    { text: dash(worker.cgroup_id), cls: 'v61-mono' },
    { pill: { label: t(asBool(worker.strict) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(worker.strict) ? 'warn' : 'muted' } }
  ];
}

function stormRow(storm) {
  const peers = asArray(storm.peers);
  return [
    { text: storm.id || '—', cls: 'v61-mono v61-tight', title: String(storm.id || '') },
    { text: storm.comm || '—', cls: 'v61-mono' },
    { text: `${formatCount(storm.crashes)} / ${formatCount(storm.window_seconds)}s`, cls: 'v61-mono' },
    { pill: { label: dash(storm.severity), tone: severityTone(storm.severity) } },
    { text: formatStamp(storm.first_at) },
    { text: formatStamp(storm.last_at) },
    { list: peers }
  ];
}

function renderEvents(events) {
  if (!events.length) {
    renderRows('workerEventRows', 9, [], 'v61.workers.empty.events');
    return;
  }
  setNotice('workerEventNotice', '');
  renderRows('workerEventRows', 9, events.map(event => [
    { text: formatStamp(event.at) },
    { text: event.comm || '—', cls: 'v61-mono' },
    { text: formatCount(event.pid), cls: 'v61-mono' },
    { text: formatCount(event.uid), cls: 'v61-mono' },
    { text: event.signal || '—', cls: 'v61-mono' },
    { text: event.exit_code === undefined ? '—' : formatCount(event.exit_code), cls: 'v61-mono' },
    { text: dash(event.cgroup_id), cls: 'v61-mono' },
    { text: event.peer || '—', cls: 'v61-mono' },
    { text: event.source || '—' }
  ]), 'v61.workers.empty.events');
}

function dash(value) {
  return value === null || value === undefined || value === '' ? '—' : String(value);
}
