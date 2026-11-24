// STATUS: DIAMANT VGT SUPREME
'use strict';

// Dashboard live state: connection state, the SSE snapshot stream with its
// polling fallback, the snapshot render dispatcher, and the generic table-pane
// and stable-list guards. Split out of the former single app.js module
// (refactoring wave 2a, structure-only).

import {
  APIError,
  getStatus,
  streamSnapshots
} from '../api.js';
import {
  appendTraffic,
  drawTraffic
} from '../charts.js';
import { t } from '../i18n.js';
import {
  badge,
  byID,
  formatRate,
  formatTime,
  formatUptime,
  renderEvents,
  renderIncidents,
  renderReleaseBlockers,
  renderRules,
  text
} from '../render.js';
import {
  handleThreatIntelStreamEvent,
  loadThreatIntelView
} from '../threat-intel.js';
import {
  acknowledge,
  confineWorkload,
  number,
  openAuthDialog,
  removeRule
} from './navigation.js';
import { renderMalwareProtection } from './views_xdr_spyware.js';
import { applySettings } from './views_overview.js';
import { loadProtectionState } from '../protection.js';
import { loadL7View } from '../l7.js';
import { loadXDRView } from '../xdr.js';

let snapshot = null;

// The settings and transaction module state (runtimeSettings,
// selectedTransaction) lives with those surfaces in js/views_overview.js.
let streamController = null;
let pollTimer = 0;
let reconnectTimer = 0;
let reconnectAttempt = 0;
let streamRefreshTimer = 0;
let refreshInFlight = null;
let connectionState = 'LIVE'; // 'LIVE' | 'POLLING_FALLBACK' | 'CONTROL_UNREACHABLE'
let consecutiveRestFailures = 0;

function setConnectionState(online, detail = '') {
  const banner = byID('connectionBanner');
  const detailNode = byID('connectionDetail');
  if (!banner) return;
  if (online) {
    banner.classList.remove('is-visible');
    globalThis.setTimeout(() => {
      if (!banner.classList.contains('is-visible')) banner.hidden = true;
    }, 180);
    return;
  }
  if (detailNode) detailNode.textContent = detail || t('connection.offlineDetail');
  banner.hidden = false;
  requestAnimationFrame(() => banner.classList.add('is-visible'));
}

function updateSnapshot(data) {
  setConnectionState(true);
  snapshot = data;
  const xdr = data.xdr || {};
  const policy = data.policy || {};
  const behavior = xdr.behavior || {};
  const release = data.release || {};
  // G-WEB-05: the unauthenticated shell carries no version/build. Only an
  // authenticated status answer may fill these placeholders.
  const version = String(data.version || '---');
  text('versionText', version);
  const build = data.ui_build || data.build || '';
  text('uiBuild', build ? `UI ${String(build)}` : '---');
  if (version !== '---') document.title = t('app.titleWithVersion', { version });
  if (data.settings) applySettings(data.settings);
  text('nodeName', data.node_name || 'VGT Node');
  text('uptime', formatUptime(data.uptime_seconds));
  text('blockCount', number((data.blocks || []).length));
  text('feedCount', number(data.feed_vectors));
  const feedBlocks = Number(data.feed_block_vectors || 0);
  const feedTotal = Number(data.feed_vectors || 0);
  const feedGen = Number(data.feed_generation || 0);
  const overviewFeedEl = byID('overviewFeedCount');
  if (overviewFeedEl) {
    overviewFeedEl.textContent = number(feedBlocks > 0 ? feedBlocks : feedTotal);
    overviewFeedEl.title = `${number(feedBlocks)} Block / ${number(feedTotal)} Total`;
  }
  if (data.last_feed_sync || feedGen > 0 || feedTotal > 0) {
    const detailParts = [];
    if (feedBlocks > 0 && feedTotal > feedBlocks) {
      detailParts.push(`${number(feedTotal)} total`);
    }
    if (feedGen > 0) {
      detailParts.push(`Gen ${feedGen}`);
    }
    if (data.feed_fingerprint) {
      detailParts.push(String(data.feed_fingerprint).slice(0, 8));
    }
    text('overviewFeedDetail', detailParts.join(' Â· ') || t('metric.threatFeedsDetail'));
  } else {
    text('overviewFeedDetail', t('metric.threatFeedsDetail'));
  }
  // Kinetic telemetry on the landing page.
  //
  // The row is grouped by the question each column answers, and these are the three that
  // were missing: what the engine enforced, what it recognised, and whether the kernel
  // channel delivering to it is keeping up. Every value is read from the snapshot the
  // control plane already publishes - nothing is recomputed or estimated here.
  const kinetic = data.kinetic || {};
  text('overviewBansEnforced', number(kinetic.bans_enforced_total));
  text('overviewHits', number(kinetic.hits_total));
  text('overviewPortscans', number(kinetic.portscans_total));
  text('overviewKernelEvents', number(kinetic.kernel_events_emitted));

  // Ring losses are tonally marked because a non-zero value is the one number here that
  // says the sensor is dropping observation, which is a different condition from simply
  // having seen nothing.
  const ringDrops = Number(kinetic.kernel_ring_drops || 0);
  const ringEl = byID('overviewRingDrops');
  if (ringEl) {
    ringEl.textContent = number(ringDrops);
    ringEl.className = ringDrops > 0 ? 'text-warning' : '';
  }

  // The detection note carries the two signals the row has no space for, so a busy host
  // is legible without adding a fourth column.
  const detectionNote = byID('overviewDetectionDetail');
  if (detectionNote) {
    const subnet = Number(kinetic.subnet_strikes_total || 0);
    const velocity = Number(kinetic.velocity_bursts_total || 0);
    detectionNote.textContent = (subnet > 0 || velocity > 0)
      ? t('metric.detectionDetail', { subnet: number(subnet), velocity: number(velocity) })
      : t('metric.adaptive');
  }

  // Which hook the kernel attached, read from the core's own health response. An
  // unreported mode is stated as unreported rather than described as native.
  const pathEl = byID('overviewEnforcementPath');
  if (pathEl) {
    const mode = String(kinetic.ingress_mode || '');
    const modeKey = {
      NATIVE_XDP: 'kinetic.enforcement.modeNative',
      GENERIC_XDP: 'kinetic.enforcement.modeGeneric',
      TC_INGRESS: 'kinetic.enforcement.modeTc'
    }[mode];
    pathEl.textContent = modeKey
      ? t('metric.enforcementPath', { path: t(modeKey) })
      : t('metric.enforcementPathUnknown');
  }

  text('iface', data.telemetry?.interface || '---');
  text('rxRate', formatRate(data.telemetry?.rx_rate || 0));
  text('txRate', formatRate(data.telemetry?.tx_rate || 0));  const cpu = Number(data.telemetry?.cpu_percent || 0);
  const memory = Number(data.telemetry?.memory_percent || 0);
  text('cpuText', `${cpu.toFixed(1)}%`);
  text('memText', `${memory.toFixed(1)}%`);
  const cpuBar = byID('cpuBar');
  if (cpuBar) cpuBar.style.width = `${Math.min(100, Math.max(0, cpu))}%`;
  const memBar = byID('memBar');
  if (memBar) memBar.style.width = `${Math.min(100, Math.max(0, memory))}%`;
  appendTraffic(Number(data.telemetry?.rx_rate || 0), Number(data.telemetry?.tx_rate || 0));
  const chart = byID('trafficChart');
  if (chart) drawTraffic(chart);

  if (data.core_connected) {
    text('coreMetric', t('dynamic.online'));
    text('coreDetail', `XDP ${data.core_mode} Â· ${t('dynamic.allowlist', { state: data.allowlist_ready ? 'SYNC' : t('dynamic.blocked') })}`);
    text('shieldState', data.enforcement === 'enforce' ? t('dynamic.kernelShield') : t('dynamic.observeFabric'));
    text('coreMode', t('dynamic.authVgt', { mode: data.core_mode }));
  } else {
    text('coreMetric', t('dynamic.offline'));
    text('coreDetail', t('dynamic.controlSafe'));
    text('shieldState', t('dynamic.controlOnly'));
    text('coreMode', t('dynamic.rustOffline'));
  }

  // The global status must not contradict a view. Kinetic reports DEGRADED from
  // State.Coverage, so the sidebar has to read the same source; otherwise the
  // platform announces SYSTEM NOMINAL while a sensor rail says DEGRADED.
  const coverage = data.coverage || {};
  const coverageNominal = coverage.nominal !== false && String(coverage.overall_status || '') !== 'degraded' && String(coverage.overall_status || '') !== 'offline';
  // The sidebar has to read every source that can contradict it. It knew the XDR state, the
  // policy and the sensor coverage, but not the release phase - so a platform sitting in a
  // fail-safe with its automatic response paused announced SYSTEM NOMINAL in green while the
  // Protection Center one click away showed DEGRADED. A retained kernel enforcement is not a
  // nominal platform either: the posture is restricted, and the badge has to say which.
  const releaseDegraded = String(release.phase || '') === 'degraded';
  const enforcementRetained = String(release.kernel_policy_state || '') === 'verified-enforce';
  const degraded = Boolean(xdr.degraded) || (data.policy && !policy.verified) || !coverageNominal || Boolean(release.emergency_stop);
  const restricted = !degraded && releaseDegraded;
  const nominal = data.core_connected && !degraded && !restricted;
  const stateKey = nominal ? 'dynamic.nominal' : restricted ? 'dynamic.restricted' : degraded ? 'dynamic.degraded' : 'dynamic.controlOnly';
  badge('systemBadge', t(stateKey), nominal ? 'good' : restricted ? 'warning' : degraded ? 'danger' : 'warning');
  text('sidebarState', t(stateKey));
  const modes = `${String(data.enforcement || 'observe').toUpperCase()} Â· ${String(xdr.mode || 'observe').toUpperCase()}`;
  text('sidebarMode', restricted && enforcementRetained ? `${modes} Â· ${t('dynamic.enforcementRetained')}` : modes);
  byID('sidebarPulse').className = `status-dot${nominal ? '' : restricted ? ' warning' : degraded ? ' danger' : ' warning'}`;
  byID('heroPulse').className = byID('sidebarPulse').className;

  text('xdrMetric', xdr.enabled ? (xdr.degraded ? t('dynamic.degraded') : String(xdr.mode || 'observe').toUpperCase()) : t('dynamic.disabled'));
  text('xdrDetail', xdr.degraded ? xdr.degraded_reason || t('dynamic.disabled') : `${xdr.sensor || 'sensor'} Â· ${t('dynamic.incidents', { value: number(xdr.incidents_total) })}`);
  renderMalwareProtection();
  text('anomalyCount', number(xdr.anomalies_total));
  text('xdrProcesses', number(xdr.processes));
  text('xdrConnections', number(xdr.open_connections));
  const qDepth = Number(xdr.queue_depth || 0);
  const qCap = Number(xdr.queue_capacity || 0);
  const qDrops = Number(xdr.evaluation_drops || 0);
  text('queueDepth', `${number(qDepth)} / ${number(qCap)}`);
  const qDropEl = byID('queueDrops');
  if (qDropEl) {
    qDropEl.textContent = qDrops > 0
      ? t('dynamic.drops', { value: number(qDrops) })
      : `${number(qDrops)} Drops Â· optimal`;
    qDropEl.className = qDrops > 0 ? 'text-danger font-semibold' : 'text-muted';
  }
  text('profileCount', number(behavior.profiles ?? xdr.profiles_total ?? 0));
  text('warmProfiles', number(behavior.warm_profiles ?? xdr.profiles_warm ?? 0));
  badge('xdrModeBadge', String(xdr.mode || 'disabled').toUpperCase(), xdr.degraded ? 'danger' : xdr.mode === 'enforce' ? 'good' : 'warning');
  badge('behaviorIntegrity', behavior.integrity_ok ? t('dynamic.macVerified') : t('dynamic.integrityFailure'), behavior.integrity_ok ? 'good' : 'danger');

  badge('enforcementBadge', String(data.enforcement || 'observe').toUpperCase(), data.enforcement === 'enforce' ? 'good' : 'warning');
  badge('policyBadge', policy.verified ? t('dynamic.signatureVerified') : t('dynamic.signatureFailure'), policy.verified ? 'good' : 'danger');
  text('policySigner', policy.signer || '---');
  text('policyGeneration', number(policy.generation));
  text('policyUpdated', formatTime(policy.updated_at));

  text('incidentIntegrity', xdr.degraded && String(xdr.degraded_reason || '').includes('incident') ? t('dynamic.quarantined') : t('dynamic.verified'));
  text('incidentDetail', xdr.degraded ? xdr.degraded_reason || t('dynamic.degraded') : t('dynamic.hmacChain'));
  text('incidentCount', number(xdr.incidents_total));
  text('actionCount', number(xdr.actions_total));

  badge('nodeModeBadge', String(data.node_mode || 'standalone').toUpperCase());
  text('systemNode', data.node_name || '---');
  text('systemUptime', `${formatUptime(data.uptime_seconds)} Â· ${data.version || ''}`);
  text('systemCore', data.core_connected ? t('dynamic.online') : t('dynamic.offline'));
  text('systemCoreDetail', data.core_connected ? `XDP ${data.core_mode} Â· VGT3 HMAC Â· ${t('dynamic.allowlist', { state: data.allowlist_ready ? 'SYNC' : t('dynamic.blocked') })}` : t('dynamic.safeMode'));
  text('systemXdr', xdr.enabled ? (xdr.degraded ? t('dynamic.degraded') : t('dynamic.online')) : t('dynamic.disabled'));
  text('systemXdrDetail', `${xdr.sensor || '---'} Â· ${t('dynamic.protectedObjects', { value: number(xdr.protected_objects) })}`);
  text('systemPolicy', policy.verified ? t('dynamic.verified') : t('dynamic.failed'));
  text('systemPolicyDetail', `${policy.signer || t('dynamic.noSigner')} Â· ${t('dynamic.generation', { value: number(policy.generation) })}`);
  text('systemBehavior', behavior.integrity_ok ? t('dynamic.verified') : t('dynamic.failed'));
  text('systemBehaviorDetail', t('dynamic.profilesWarm', { profiles: number(behavior.profiles), warm: number(behavior.warm_profiles) }));
  text('systemFeeds', number(data.feed_vectors));
  text('systemFeedTime', data.last_feed_sync ? formatTime(data.last_feed_sync) : t('system.notSynced'));

  const releaseReady = Boolean(release.ready);
  const releaseRetained = String(release.kernel_policy_state || '') === 'verified-enforce';
  // The same rule as the Protection Center badge: a degraded platform whose kernel still enforces
  // is restricted, not broken. Two pages must not describe the same state differently.
  badge('releasePhaseBadge',
    release.phase === 'degraded' && releaseRetained ? t('dynamic.restricted') : String(release.phase || 'observe').toUpperCase(),
    release.phase === 'enforce' ? 'good' : release.phase === 'degraded' ? (releaseRetained ? 'warning' : 'danger') : 'warning');
  text('releasePhase', String(release.phase || 'observe').toUpperCase());
  text('releaseSince', release.since ? t('dynamic.since', { time: formatTime(release.since) }) : t('release.startPhase'));
  text('releaseReady', releaseReady ? t('dynamic.ready') : t('dynamic.blocked'));
  // The backend names three release states; each has its own sentence here. A host that still
  // reports "release gates satisfied" while its phase is degraded - an older backend, or a
  // rollout in progress - must not be able to make the panel contradict its own badge either, so
  // the phase decides and not the string. Without that, the readiness field announced that every
  // gate held, directly beside the gate list explaining the retained enforcement.
  const detail = String(release.detail || '');
  const detailKey = detail === 'automatic response paused; kernel enforcement retained and verified' ? 'dynamic.detailRetained'
    : detail === 'automatic response paused; kernel enforcement not confirmed' ? 'dynamic.detailNotConfirmed'
      : (detail === 'release gates satisfied' && !releaseDegraded) ? 'dynamic.allGates'
        : '';
  text('releaseDetail', detailKey ? t(detailKey)
    : releaseDegraded ? t(releaseRetained ? 'dynamic.detailRetained' : 'dynamic.detailNotConfirmed')
      : (detail || t('release.gateCheck')));
  text('releaseCoreMisses', number(release.core_misses));
  text('releaseKernelState', String(release.kernel_policy_state || 'unverified').toUpperCase());
  // The kernel state, not the boolean alone, decides what the fail-safe line says - and only a
  // fail-safe can say anything about a retained enforcement. The kernel also reports
  // verified-enforce while the platform is healthy and enforcing normally, where nothing was
  // retained and nothing is paused, so the phase decides whether there was a fail-safe at all.
  text('releaseFailSafe', releaseDegraded && releaseRetained
    ? t('dynamic.failSafeEnforceRetained')
    : (release.fail_safe_verified ? t('dynamic.failSafeVerified') : t('dynamic.failSafeUnverified')));
  renderReleaseBlockers(release.blockers || [], release);

  // The XDR view owns the incident timeline; the generic snapshot pass must not replace it
  // underneath its own renderer. Both wrote the same tbody, and each pass replaced the
  // other's rows.
  const activePage = document.querySelector('[data-page].active')?.getAttribute('data-page');

  renderStableList('events', data.events || [], renderEvents);
  renderStableList('blocks', data.blocks || [], list => renderRules(list, removeRule));
  renderStableList('incidents', data.incidents || [], list => renderIncidents(list, acknowledge, confineWorkload, { skipMain: activePage === 'xdr' }));

  const l7 = data.l7 || {};
  text('overviewL7Inspected', number(l7.requests_total || 0));
  text('overviewL7Findings', number(l7.findings_total || 0));
  text('overviewL7Blocked', number(l7.blocked_total || 0));
  const overviewL7Pill = byID('overviewL7Pill');
  if (overviewL7Pill) {
    const coverage = String(l7.coverage || '').toUpperCase();
    const coverageGood = coverage === 'TRAFFIC_ACTIVE';
    const coverageDisabled = !l7.enabled || coverage === 'DISABLED';
    overviewL7Pill.className = `status-pill ${coverageGood ? 'good' : (coverageDisabled ? 'muted' : (coverage === 'OFFLINE' ? 'danger' : 'warn'))}`;
    overviewL7Pill.textContent = coverageGood ? 'ACTIVE' : (coverageDisabled ? 'INACTIVE' : (coverage === 'TLS_NOT_IN_PATH' ? 'TLS NOT IN PATH' : 'DEGRADED'));
  }

  loadProtectionState(data).catch(() => {});

  if (activePage === 'l7') {
    loadL7View(data).catch(() => {});
  }
  // Kinetic Defense owns its own bounded live refresh loop. Triggering four
  // additional Kinetic API requests from every global status refresh caused
  // request amplification whenever SSE events arrived in quick succession.
  // The view is loaded once on activation and then refreshed by kinetic.js.
  if (activePage === 'threat-intel') {
    loadThreatIntelView().catch(() => {});
  }
  if (activePage === 'xdr') {
    loadXDRView(data).catch(() => {});
  }
}

// Long lists are bounded: every table shows its newest 50 rows inside a scroll pane and can be
// expanded to the full history. The pane is applied generically so a future table inherits it.
//
// Row order is not a detail here. The server publishes every list newest first - incidents and
// events are reversed before they leave the control plane, block rules are ordered by the next
// expiry - so the pane must keep the FIRST rows and collapse the tail. The first version of this
// function hid `index < length - limit` instead, which on a 250-row incident log collapsed the
// 200 newest entries and left exactly the two-hour-old tail on screen. A wrong pane alone would
// have been a display bug; what made it an endless jump was the second half: the pane was
// re-applied from a two-second timer while every stream snapshot rebuilt the table from scratch.
// Fresh rows appeared unbounded, the timer collapsed the newest ones, the next snapshot rebuilt,
// and the list oscillated between the top and the old tail.
const TABLE_PANE_LIMIT = 50;

// The pane follows the DOM, not a clock. Any renderer that inserts rows schedules one pass on the
// next animation frame; the pass runs before that frame is painted, so fresh rows are bounded
// before they can flash at full length, and an unchanged table is never touched at all.
let paneApplyScheduled = false;

function scheduleApplyTablePanes() {
  if (paneApplyScheduled) return;
  paneApplyScheduled = true;
  requestAnimationFrame(() => {
    paneApplyScheduled = false;
    try {
      applyTablePanes();
    } catch (_) {
      // A broken table must not stall the frame loop of the whole dashboard.
    }
  });
}

function applyTablePanes() {
  document.querySelectorAll('.view .table-wrap').forEach(wrap => {
    const body = wrap.querySelector('table tbody');
    if (!body) return;
    const rows = Array.from(body.rows);
    const expanded = wrap.dataset.paneExpanded === '1';
    const limited = !expanded && rows.length > TABLE_PANE_LIMIT;
    rows.forEach((row, index) => {
      const hide = limited && index >= TABLE_PANE_LIMIT;
      if (row.hidden !== hide) row.hidden = hide;
    });
    let more = wrap.querySelector('.table-pane-more');
    if (rows.length <= TABLE_PANE_LIMIT) {
      if (more) more.remove();
      return;
    }
    if (!more) {
      more = document.createElement('div');
      more.className = 'table-pane-more';
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'button button-quiet';
      toggle.addEventListener('click', () => {
        wrap.dataset.paneExpanded = wrap.dataset.paneExpanded === '1' ? '0' : '1';
        applyTablePanes();
      });
      more.append(toggle);
      wrap.append(more);
    }
    const toggle = more.querySelector('button');
    const label = expanded ? t('table.showFewer') : t('table.showAll');
    if (toggle.textContent !== label) toggle.textContent = label;
  });
}

if (typeof MutationObserver === 'function' && document.body) {
  new MutationObserver(scheduleApplyTablePanes).observe(document.body, { childList: true, subtree: true });
}

// Two independent sources feed these tables: the SSE snapshot push and the polling refresh. They can
// arrive with different completeness, and the smaller frame used to erase the fuller list for a
// second - the flicker an operator sees as "only warnings", then "the real list", then warnings again.
// A smaller list therefore has to persist for a settle window before it replaces a fuller one.
const stableListState = new Map();

// The server payload is stable (a HAR capture of 21 consecutive /status calls showed the same 250
// incidents in the same order), yet the list visibly jumped between two scroll positions every second.
// The reason was DOM churn: every poll replaced the whole table body, and a replaced body inside a
// bounded scroll pane does not keep its viewport reliably. The rule is therefore: render only when the
// data actually changed. Two guards work together -
//   * an identical signature is not re-rendered at all (scroll position and focus stay untouched),
//   * a frame whose newest entry is older than what is on screen never replaces it (a stale frame from a
//     second source cannot rewind the list).
function listSignature(items) {
  return items.map(item => `${item?.id || ''}|${item?.acknowledged ? 1 : 0}|${item?.decision || ''}|${item?.outcome || ''}`).join(';');
}

function listNewest(items) {
  let newest = 0;
  for (const item of items) {
    const value = Date.parse(item?.time || item?.created_at || item?.last_seen || '');
    if (Number.isFinite(value) && value > newest) newest = value;
  }
  return newest;
}

function renderStableList(key, items, render) {
  const previous = stableListState.get(key);
  const now = Date.now();
  const signature = listSignature(items);
  if (previous) {
    if (previous.signature === signature) {
      previous.at = now;
      return;
    }
    const incoming = listNewest(items);
    if (previous.newest && incoming && incoming < previous.newest && now - previous.at < 15000) {
      render(previous.items);
      return;
    }
  }
  stableListState.set(key, {
    items, at: now, newest: listNewest(items), signature,
    ids: new Set(items.map(item => item?.id)),
  });
  render(items);
}

async function refreshOnce() {
  try {
    const snap = await getStatus();
    consecutiveRestFailures = 0;
    if (connectionState === 'CONTROL_UNREACHABLE') {
      connectionState = 'POLLING_FALLBACK';
    }
    // As long as REST is responding, hide the fatal red Control Plane offline banner
    setConnectionState(true);
    updateSnapshot(snap);
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      badge('systemBadge', t('dynamic.locked'), 'warning');
      text('sidebarState', t('dynamic.operatorLocked'));
      openAuthDialog();
      return;
    }
    consecutiveRestFailures++;
    // Only show red Control Plane offline banner if consecutive REST failures threshold reached (Point 86)
    if (consecutiveRestFailures >= 3) {
      connectionState = 'CONTROL_UNREACHABLE';
      badge('systemBadge', t('dynamic.apiOffline'), 'danger');
      text('sidebarState', t('dynamic.apiOffline'));
      setConnectionState(false, error?.message || t('connection.offlineDetail'));
    }
  }
}

function refresh() {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = refreshOnce().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

function scheduleStreamRefresh() {
  // SSE is an event stream, not permission to issue one complete /status
  // request per event. Coalesce event bursts into roughly one refresh per second and let the
  // Kinetic view use its own bounded endpoint polling.
  if (streamRefreshTimer) return;
  streamRefreshTimer = globalThis.setTimeout(() => {
    streamRefreshTimer = 0;
    refresh().catch(() => {});
  }, 750);
}

function scheduleStreamReconnect() {
  globalThis.clearTimeout(reconnectTimer);
  const backoff = Math.min(30000, 1000 * Math.pow(1.8, reconnectAttempt) + Math.random() * 500);
  reconnectAttempt++;
  reconnectTimer = globalThis.setTimeout(() => connectStream(), backoff);
}

function startFallbackPolling() {
  globalThis.clearInterval(pollTimer);
  refresh().catch(() => {});
  pollTimer = globalThis.setInterval(() => refresh().catch(() => {}), 3000);
}

async function connectStream() {
  globalThis.clearTimeout(reconnectTimer);
  if (streamController) streamController.abort();
  streamController = new AbortController();
  const controller = streamController;
  try {
    await streamSnapshots({
      signal: controller.signal,
      onSnapshot: payload => {
        // A successful live snapshot proves the SSE path has recovered. Stop
        // fallback polling immediately; otherwise every reconnect permanently
        // leaves an extra /status poller behind.
        globalThis.clearInterval(pollTimer);
        pollTimer = 0;
        reconnectAttempt = 0;
        consecutiveRestFailures = 0;
        connectionState = 'LIVE';
        setConnectionState(true);
        updateSnapshot(payload);
      },
      onEvent: event => {
        handleThreatIntelStreamEvent(event);
        scheduleStreamRefresh();
      }
    });
    if (controller.signal.aborted) return;
    // Stream closed by server or finished; initiate fallback polling
    connectionState = 'POLLING_FALLBACK';
    startFallbackPolling();
    scheduleStreamReconnect();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    if (error instanceof APIError && error.status === 401) {
      byID('authDialog').showModal();
      return;
    }
    // Stream error; fallback to polling without immediately showing red offline banner
    connectionState = 'POLLING_FALLBACK';
    startFallbackPolling();
    scheduleStreamReconnect();
  }
}

export {
  connectStream,
  refresh,
  snapshot,
  updateSnapshot
};
