// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6 panel — StyX kernel egress enforcement.
//
// Two reads are combined: /styx/status carries the sync state, the kernel flow
// health and the Go evaluator counters; /styx/beacons carries the detector's
// bounded top-10 flow projection. The kernel health counters are Go structs
// without JSON tags, so both spellings are accepted and a missing sample is
// reported as "no sample" instead of as zero.

import { t } from '../i18n.js';
import {
  asArray,
  asObject,
  bindAction,
  formatCount,
  formatSize,
  formatStamp,
  getJSON,
  initV61Shared,
  pick,
  refusalText,
  renderRows,
  setNotice,
  setText,
  setTone
} from './v6.js';

const STATUS_PATH = '/api/v1/styx/status';
const BEACON_PATH = '/api/v1/styx/beacons';

export function initStyxModule() {
  initV61Shared();
  bindAction('styxRefreshBtn', () => loadStyxView());
}

export async function loadStyxView() {
  const [statusResult, beaconResult] = await Promise.allSettled([getJSON(STATUS_PATH), getJSON(BEACON_PATH)]);
  if (statusResult.status !== 'fulfilled' && beaconResult.status !== 'fulfilled') {
    setNotice('styxReason', refusalText(statusResult.reason, 'v61.v6.styx.unavailable'), 'bad');
    setTone('styxPill', t('v61.v6.common.unavailable'), 'danger');
    return;
  }
  const status = statusResult.status === 'fulfilled' ? asObject(statusResult.value) : {};
  const beaconPayload = beaconResult.status === 'fulfilled' ? asObject(beaconResult.value) : {};
  renderStatus(status, beaconPayload);
}

function renderStatus(status, beaconPayload) {
  const sync = asObject(status.sync);
  const beacon = asObject(beaconPayload.beacon || status.beacon);
  const kernel = asObject(beaconPayload.kernel_health || status.kernel_health);
  const flow = asObject(beaconPayload.flow || status.flow);
  const state = String(status.state || sync.state || '');
  const sensor = String(status.sensor_state || beacon.sensor_state || '');
  const capability = String(status.capability || sync.capability || '');
  const telemetry = String(status.telemetry_state || flow.telemetry_state || '');
  const enforcementActive = status.enforcement_active === true;

  setTone('styxPill', stateLabel(state), stateTone(state));
  setText('styxStateKpi', stateLabel(state));
  setText('styxCapabilityKpi', capability || t('v61.v6.common.unknown'));
  setText('styxModeKpi', sync.mode || sensor || '—');
  setText('styxEpochKpi', sync.epoch || '—');
  // Enforcement and telemetry are two separate facts. A drop-driven telemetry
  // degradation must never turn the enforcement claim off (and vice versa).
  setText('styxEnforcementKpi', enforcementActive
    ? t('v61.v6.styx.kpi.enforcementActive')
    : t('v61.v6.styx.kpi.enforcementInactive'));
  setTone('styxTelemetryKpi', telemetryLabel(telemetry), telemetryTone(telemetry));
  setText('styxTrackedKpi', formatCount(beacon.tracked_flows));
  setText('styxEventsKpi', formatCount(beacon.events_total));
  setText('styxIncidentsKpi', formatCount(beacon.incident_total));
  setText('styxSuppressedKpi', formatCount(beacon.suppressed_total));
  setText('styxDroppedKpi', formatCount(beacon.rejected_total));
  setText('styxGoRulesKpi', formatCount(status.go_rule_count));
  setText('styxGoDropsKpi', formatCount(status.go_rule_drops));
  setText('styxGoMetadataKpi', formatCount(status.go_rule_metadata_hits));

  setText('styxKernelEmitted', kernelSample(kernel, ['Emitted', 'emitted']));
  setText('styxKernelRingDrops', kernelSample(kernel, ['RingDrops', 'ring_drops']));
  setText('styxKernelAgg', kernelSample(kernel, ['AggInsertFailures', 'agg_insert_failures']));
  setText('styxKernelParse', kernelSample(kernel, ['ParseErrors', 'parse_errors']));
  setText('styxKernelDrops', kernelSample(kernel, ['DropsTotal', 'drops_total']));
  setText('styxKernelPolicyDrops', kernelSample(kernel, ['PolicyDrops', 'policy_drops']));
  setText('styxKernelDropRatio', ratioSample(flow.drop_ratio));
  setText('styxKernelRingDelta', deltaSample(flow.ring_drops_delta));
  setText('styxKernelEmittedDelta', deltaSample(flow.emitted_delta));
  setText('styxKernelDrainLag', secondsSample(flow.drain_lag_seconds));
  setText('styxKernelUpdated', beaconPayload.kernel_health_at || status.kernel_health_at
    ? formatStamp(beaconPayload.kernel_health_at || status.kernel_health_at)
    : t('v61.v6.common.unknown'));

  const errors = [
    String(status.kernel_health_error || beaconPayload.kernel_health_error || '').trim(),
    String(sync.last_error || '').trim()
  ].filter(Boolean);
  const telemetryDegraded = telemetry === 'degraded' || telemetry === 'stale' || status.telemetry_degraded === true;
  if (errors.length) setNotice('styxReason', errors.join(' · '), 'warn');
  else if (telemetryDegraded) {
    const reason = String(flow.reason || status.reason || '').trim();
    setNotice('styxReason', t('v61.v6.styx.telemetry.warning') + (reason ? ': ' + reason : ''), 'warn');
  } else setNotice('styxReason', String(status.reason || '').trim(), state === 'applied' ? 'good' : 'warn');

  renderTop(asArray(beacon.top).map(asObject));
}

function telemetryLabel(value) {
  switch (String(value || '').toLowerCase()) {
    case 'healthy':
      return t('v61.v6.styx.telemetry.healthy');
    case 'degraded':
      return t('v61.v6.styx.telemetry.degraded');
    case 'stale':
      return t('v61.v6.styx.telemetry.stale');
    case 'disabled':
    case 'off':
      return t('v61.v6.styx.telemetry.disabled');
    case 'unavailable':
      return t('v61.v6.styx.telemetry.unavailable');
    default:
      return t('v61.v6.common.unknown');
  }
}

function telemetryTone(value) {
  switch (String(value || '').toLowerCase()) {
    case 'healthy':
      return 'good';
    case 'degraded':
    case 'stale':
      return 'warn';
    case 'unavailable':
      return 'danger';
    default:
      return 'muted';
  }
}

function ratioSample(value) {
  const number = Number(value);
  if (value === null || value === undefined || !Number.isFinite(number)) {
    return t('v61.v6.common.unknown');
  }
  return `${(number * 100).toFixed(2)} %`;
}

function deltaSample(value) {
  return value === null || value === undefined
    ? t('v61.v6.common.unknown')
    : formatCount(value);
}

function secondsSample(value) {
  const number = Number(value);
  if (value === null || value === undefined || !Number.isFinite(number)) {
    return t('v61.v6.common.unknown');
  }
  return `${number.toFixed(1)} s`;
}

function kernelSample(kernel, names) {
  const value = pick(kernel, ...names);
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
    case 'degraded':
      return t('v61.v6.state.degraded');
    case 'error':
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
    case 'degraded':
      return 'warn';
    case 'pending':
    case 'syncing':
      return 'warn';
    case 'unavailable':
    case 'capability-missing':
    case 'error':
      return 'danger';
    default:
      return 'muted';
  }
}

function renderTop(items) {
  renderRows('styxBeaconRows', 7, items.map(item => [
    { text: item.remote || '—', cls: 'v61-mono' },
    { text: item.comm || '—', cls: 'v61-mono' },
    { text: item.pid === undefined ? '—' : formatCount(item.pid), cls: 'v61-mono' },
    { text: formatSize(item.tx_bytes), cls: 'v61-mono' },
    { text: formatSize(item.rx_bytes), cls: 'v61-mono' },
    { text: formatCount(item.score), cls: 'v61-mono' },
    { badges: asArray(item.signals).map(signal => ({ label: signal, tone: 'warning' })) }
  ]), 'v61.v6.styx.empty.beacons');
}

