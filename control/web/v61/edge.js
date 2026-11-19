// STATUS: DIAMANT VGT SUPREME
'use strict';

// Module E — memory-safe edge terminator.
//
// The view reports the listener, the upstream, the negotiated HTTP/2 bounds and
// the request counters from the running proxy. `enabled` and `state` are shown
// as two separate facts: a configured-but-stopped listener is not a protected
// surface, and the restart action re-reads the status instead of claiming a
// running proxy.

import { t } from '../i18n.js';
import { toast } from '../render.js';
import {
  asBool,
  asObject,
  bindAction,
  confirmAction,
  formatCount,
  getJSON,
  initV61Shared,
  pick,
  refusalText,
  sendJSON,
  setNotice,
  setText,
  setTone,
  showRefusal
} from './v6.js';

const STATUS_PATH = '/api/v1/edge-proxy/status';
const RESTART_PATH = '/api/v1/edge-proxy/restart';

export function initEdgeModule() {
  initV61Shared();
  bindAction('edgeProxyRefreshBtn', () => loadEdgeView());
  bindAction('edgeProxyRestartBtn', restartProxy);
}

export async function loadEdgeView() {
  try {
    renderStatus(asObject(await getJSON(STATUS_PATH)));
  } catch (error) {
    setNotice('edgeProxyReason', refusalText(error, 'v61.edge.unavailable'));
    setTone('edgeProxyPill', t('v61.v6.common.unavailable'), 'danger');
  }
}

async function restartProxy() {
  const confirmed = await confirmAction({
    titleKey: 'v61.edge.confirm.title',
    bodyKey: 'v61.edge.confirm.body',
    submitKey: 'v61.edge.confirm.submit',
    detail: t('v61.edge.confirm.detail')
  });
  if (!confirmed) return;
  setNotice('edgeProxyResult', '');
  try {
    // The restart route is reason-bound: the operator's dialog reason is the
    // audit reason, and the control plane refuses a restart without one.
    const result = asObject(await sendJSON(RESTART_PATH, 'POST', { reason: confirmed.reason }));
    const detail = String(result.reason || result.state || result.status || '').trim();
    const message = detail ? t('v61.edge.restartedDetail', { detail }) : t('v61.edge.restarted');
    setNotice('edgeProxyResult', message, 'good');
    toast(message, 'good');
  } catch (error) {
    showRefusal('edgeProxyResult', error, 'v61.edge.restartFailed');
    return;
  }
  await loadEdgeView();
}

function renderStatus(status) {
  const h2 = asObject(status.h2);
  const counters = asObject(status.counters);
  const state = String(status.state || '');
  const enabled = asBool(status.enabled);

  setTone('edgeProxyPill', stateLabel(state), stateTone(state));
  setText('edgeStateKpi', stateLabel(state));
  setTone('edgeEnabledKpi', t(enabled ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), enabled ? 'good' : 'muted');
  setText('edgeListenKpi', status.listen || '—');
  setText('edgeUpstreamKpi', status.upstream || '—');
  setText('edgeRequestsKpi', formatCount(counters.requests));
  setText('edgeBlockedKpi', formatCount(counters.blocked));
  setText('edgeActiveKpi', formatCount(counters.active));

  setText('edgeH2Streams', formatCount(h2.max_concurrent_streams));
  setText('edgeH2Frame', formatCount(h2.max_read_frame_size));
  setText('edgeH2Header', formatCount(h2.max_header_bytes));
  // The running proxy reports the certificate fingerprint at the top level; the
  // nested `tls` object from the blueprint is accepted as a fallback so an older
  // additive payload does not render as "no identity".
  const fingerprint = pick(status, 'fingerprint') || asObject(status.tls).fingerprint;
  setText('edgeTlsFingerprint', fingerprint || '—');
  setText('edgeTlsMin', status.min_tls || asObject(status.tls).min_tls || '—');

  const reason = String(status.reason || '').trim();
  if (reason) setNotice('edgeProxyReason', reason, state === 'running' ? 'warn' : 'bad');
  else if (!enabled) setNotice('edgeProxyReason', t('v61.edge.disabledNote'), 'warn');
  else setNotice('edgeProxyReason', '');
}

function stateLabel(state) {
  switch (String(state || '').toLowerCase()) {
    case 'running':
      return t('v61.edge.state.running');
    case 'stopped':
      return t('v61.edge.state.stopped');
    case 'error':
      return t('v61.edge.state.error');
    default:
      return t('v61.v6.common.unknown');
  }
}

function stateTone(state) {
  switch (String(state || '').toLowerCase()) {
    case 'running':
      return 'good';
    case 'stopped':
      return 'muted';
    case 'error':
      return 'danger';
    default:
      return 'warn';
  }
}
