// STATUS: DIAMANT VGT SUPREME
'use strict';

// Module C — TLS/ALPN sensor and control-storm budget.
//
// The storm banner shows the four predicate values the control plane evaluated,
// not only its verdict: an operator who sees `active` must be able to check the
// numbers against the documented rule. Bytes arrive as absolute counters and are
// rendered as such; nothing is inferred when the capture is inactive.

import { t } from '../i18n.js';
import {
  asArray,
  asBool,
  asNumber,
  asObject,
  byId,
  bindAction,
  el,
  formatCount,
  formatSize,
  formatStamp,
  getJSON,
  initV61Shared,
  refusalText,
  renderRows,
  setNotice,
  setText,
  setTone
} from './v6.js';

const STATUS_PATH = '/api/v1/tls-sensor/status';
const HANDSHAKE_PATH = '/api/v1/tls-sensor/handshakes?limit=100';
const FLOW_PATH = '/api/v1/tls-sensor/flows';

export function initTLSModule() {
  initV61Shared();
  bindAction('tlsSensorRefreshBtn', () => loadTLSView());
}

export async function loadTLSView() {
  const results = await Promise.allSettled([getJSON(STATUS_PATH), getJSON(HANDSHAKE_PATH), getJSON(FLOW_PATH)]);
  const status = results[0];
  if (status.status === 'fulfilled') {
    renderStatus(asObject(status.value));
  } else {
    setNotice('tlsSensorReason', refusalText(status.reason, 'v61.tls.unavailable'));
    setTone('tlsSensorPill', t('v61.v6.common.unavailable'), 'danger');
  }
  if (results[1].status === 'fulfilled') {
    renderHandshakes(asArray(asObject(results[1].value).handshakes).map(asObject));
  } else {
    renderRows('tlsHandshakeRows', 7, [], 'v61.tls.empty.handshakes');
    setNotice('tlsHandshakeNotice', refusalText(results[1].reason, 'v61.tls.handshakesUnavailable'));
  }
  if (results[2].status === 'fulfilled') {
    const payload = asObject(results[2].value);
    renderFlows(asArray(payload.flows).map(asObject), asObject(payload.budget));
  } else {
    renderRows('tlsFlowRows', 9, [], 'v61.tls.empty.flows');
    setText('tlsBudgetNote', t('v61.tls.budgetUnavailable'));
    setNotice('tlsFlowNotice', refusalText(results[2].reason, 'v61.tls.flowsUnavailable'));
  }
}

function renderStatus(status) {
  const capture = String(status.capture || '');
  const storm = asObject(status.storm);
  const predicate = asObject(storm.predicate);
  const engine = asObject(status.tls_engine);
  const alpn = asObject(status.alpn);

  setTone('tlsSensorPill', captureLabel(capture), captureTone(capture));
  setTone('tlsCaptureKpi', captureLabel(capture), captureTone(capture));
  setText('tlsHandshakesKpi', formatCount(status.handshakes));
  setText('tlsQuicKpi', formatCount(status.quic_initial));
  setText('tlsFlowsKpi', formatCount(status.flows));
  setText('tlsFindingsKpi', formatCount(engine.findings));
  setText('tlsTrackedKpi', formatCount(engine.tracked));

  const reason = String(status.reason || '').trim();
  setNotice('tlsSensorReason', reason, capture === 'active' ? 'warn' : 'bad');

  renderAlpn(alpn);
  renderStorm(storm, predicate);
}

function captureLabel(capture) {
  switch (capture) {
    case 'active':
      return t('v61.tls.capture.active');
    case 'inactive':
      return t('v61.tls.capture.inactive');
    case 'unsupported':
      return t('v61.tls.capture.unsupported');
    default:
      return t('v61.v6.common.unknown');
  }
}

function captureTone(capture) {
  if (capture === 'active') return 'good';
  if (capture === 'unsupported') return 'danger';
  return 'warn';
}

// The ALPN distribution has an open key set (the protocols the peers offered),
// so it is rendered as a key/value list rather than a fixed column set.
function renderAlpn(alpn) {
  const host = byId('tlsAlpnList');
  if (!host) return;
  host.replaceChildren();
  const entries = Object.entries(alpn).filter(([, value]) => Number.isFinite(Number(value)));
  if (!entries.length) {
    const row = el('div', 'v61-kv');
    row.append(el('dt', '', t('v61.tls.alpn.label')), el('dd', '', t('v61.tls.empty.alpn')));
    host.append(row);
    return;
  }
  for (const [protocol, count] of entries) {
    const row = el('div', 'v61-kv');
    row.append(el('dt', '', protocol), el('dd', 'v61-mono', formatCount(count)));
    host.append(row);
  }
}

function renderStorm(storm, predicate) {
  const banner = byId('tlsStormBanner');
  const active = asBool(storm.active);
  if (banner) {
    banner.hidden = false;
    banner.classList.toggle('is-alert', active);
    banner.classList.toggle('is-attention', !active);
  }
  setTone('tlsStormState', t(active ? 'v61.tls.storm.active' : 'v61.tls.storm.clear'), active ? 'danger' : 'good');
  setText('tlsStormPeers', asArray(storm.peers).length ? asArray(storm.peers).join(', ') : t('v61.v6.common.none'));
  setText('tlsStormRx', formatSize(predicate.rx_bytes));
  setText('tlsStormTx', formatSize(predicate.tx_bytes));
  setText('tlsStormRatio', formatCount(predicate.ratio));
  setText('tlsStormAvg', formatSize(predicate.avg_pkt_len));
  setText('tlsStormPps', formatCount(predicate.pps_ratio));
  setNotice('tlsStormNote', t(active ? 'v61.tls.storm.noteActive' : 'v61.tls.storm.noteClear'), active ? 'warn' : 'good');
}

function renderHandshakes(handshakes) {
  setNotice('tlsHandshakeNotice', '');
  renderRows('tlsHandshakeRows', 7, handshakes.map(handshake => [
    { text: formatStamp(handshake.at) },
    { text: handshake.peer || '—', cls: 'v61-mono' },
    { text: handshake.sni || '—', cls: 'v61-mono v61-tight', title: String(handshake.sni || '') },
    { list: asArray(handshake.alpn) },
    { text: handshake.ja3 || '—', cls: 'v61-mono v61-tight', title: String(handshake.ja3 || '') },
    { text: handshake.tls_version === undefined ? '—' : formatCount(handshake.tls_version), cls: 'v61-mono' },
    { text: handshake.cipher === undefined ? '—' : formatCount(handshake.cipher), cls: 'v61-mono' }
  ]), 'v61.tls.empty.handshakes');
}

function renderFlows(flows, budget) {
  setNotice('tlsFlowNotice', '');
  const used = asNumber(budget.used);
  const max = asNumber(budget.max_flows);
  setText('tlsBudgetNote', max ? t('v61.tls.budget', { used: formatCount(used), max: formatCount(max) }) : t('v61.v6.common.unknown'));
  renderRows('tlsFlowRows', 9, flows.map(flow => [
    { text: flow.peer || '—', cls: 'v61-mono' },
    { text: flow.port === undefined ? '—' : formatCount(flow.port), cls: 'v61-mono' },
    { text: formatSize(flow.rx_bytes), cls: 'v61-mono' },
    { text: formatSize(flow.tx_bytes), cls: 'v61-mono' },
    { text: formatCount(flow.segs_in), cls: 'v61-mono' },
    { text: formatCount(flow.segs_out), cls: 'v61-mono' },
    { text: formatSize(flow.avg_pkt_len), cls: 'v61-mono' },
    { text: formatCount(flow.age_seconds), cls: 'v61-mono' },
    { pill: { label: verdictLabel(flow.verdict), tone: verdictTone(flow.verdict) } }
  ]), 'v61.tls.empty.flows');
}

function verdictLabel(verdict) {
  switch (String(verdict || '').toLowerCase()) {
    case 'ok':
      return t('v61.tls.verdict.ok');
    case 'watch':
      return t('v61.tls.verdict.watch');
    case 'storm':
      return t('v61.tls.verdict.storm');
    default:
      return t('v61.v6.common.unknown');
  }
}

function verdictTone(verdict) {
  switch (String(verdict || '').toLowerCase()) {
    case 'storm':
      return 'danger';
    case 'watch':
      return 'warn';
    case 'ok':
      return 'good';
    default:
      return 'muted';
  }
}
