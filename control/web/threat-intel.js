// STATUS: VGT GEDEFENSE 4.1 OPENAI REWORK B11
'use strict';

import { applyFeeds, getThreatIntelStatus, syncFeeds } from './api.js';
import { t } from './i18n.js';
import { byID, formatTime, text, toast } from './render.js';

let threatIntelRefreshInFlight = null;
let threatIntelRefreshPending = false;

export function initThreatIntelModule() {
  const syncBtn = byID('threatIntelSyncBtn');
  if (syncBtn) {
    syncBtn.addEventListener('click', async () => {
      if (syncBtn.disabled) return;
      syncBtn.disabled = true;
      syncBtn.classList.add('loading');
      try {
        renderSyncOperation('FETCHING', t('threatIntel.syncPhaseFetching'));
        toast(t('threatIntel.syncing'), 'info');
        const result = await syncFeeds();
        const sourceErrors = Number(result?.source_errors || 0);
        const overall = String(result?.overall_status || (sourceErrors > 0 ? 'PARTIAL' : 'OK')).toUpperCase();
        renderSyncOperation(overall === 'PARTIAL' ? 'PARTIAL' : 'APPLIED',
          sourceErrors > 0
            ? t('threatIntel.syncPartialResult', { errors: sourceErrors, added: Number(result?.kernel_added || 0), deleted: Number(result?.kernel_deleted || 0) })
            : t('threatIntel.syncAppliedResult', { added: Number(result?.kernel_added || 0), deleted: Number(result?.kernel_deleted || 0) }));
        toast(sourceErrors > 0 ? t('threatIntel.syncPartialToast', { errors: sourceErrors }) : t('threatIntel.syncSuccess'), sourceErrors > 0 ? 'warning' : 'good');
        await loadThreatIntelView(true);
      } catch (err) {
        renderSyncOperation('ERROR', t('threatIntel.syncFailed', { error: err.message || err }));
        toast(t('threatIntel.syncFailed', { error: err.message || err }), 'danger');
        await loadThreatIntelView(true).catch(() => {});
      } finally {
        syncBtn.disabled = false;
        syncBtn.classList.remove('loading');
      }
    });
  }

  const refreshBtn = byID('threatIntelRefreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => loadThreatIntelView(true).catch(() => {}));

  // Explicit kernel publication. It is the counterpart to "apply to kernel
  // automatically" in Threat Intelligence / Settings: with automatic
  // publication switched off, a sync validates and stages, and this action is
  // the only way to enforce the staged generation.
  const applyBtn = byID('threatIntelApplyBtn');
  if (applyBtn) {
    applyBtn.addEventListener('click', async () => {
      if (applyBtn.disabled) return;
      applyBtn.disabled = true;
      applyBtn.classList.add('loading');
      try {
        renderSyncOperation('APPLYING', t('threatIntel.applyingKernel'));
        const result = await applyFeeds();
        renderSyncOperation('APPLIED', t('threatIntel.applyResult', {
          added: Number(result?.kernel_added || 0),
          deleted: Number(result?.kernel_deleted || 0),
          generation: Number(result?.generation || 0)
        }));
        toast(t('threatIntel.applySuccess'), 'good');
        await loadThreatIntelView(true);
      } catch (err) {
        renderSyncOperation('ERROR', t('threatIntel.applyFailed', { error: err.message || err }));
        toast(t('threatIntel.applyFailed', { error: err.message || err }), 'danger');
        await loadThreatIntelView(true).catch(() => {});
      } finally {
        applyBtn.disabled = false;
        applyBtn.classList.remove('loading');
      }
    });
  }
}

export async function loadThreatIntelView(force = false) {
  if (threatIntelRefreshInFlight) {
    if (force) threatIntelRefreshPending = true;
    return threatIntelRefreshInFlight;
  }

  threatIntelRefreshInFlight = (async () => {
    try {
      renderThreatIntelView(await getThreatIntelStatus());
    } catch (err) {
      renderThreatIntelOffline(err.message || String(err));
      throw err;
    } finally {
      threatIntelRefreshInFlight = null;
      if (threatIntelRefreshPending) {
        threatIntelRefreshPending = false;
        queueMicrotask(() => loadThreatIntelView().catch(() => {}));
      }
    }
  })();

  return threatIntelRefreshInFlight;
}

function renderThreatIntelView(data) {
  if (!data) return;

  const feeds = Array.isArray(data.feeds) ? data.feeds : [];
  const statuses = summarizeFeedStatuses(feeds);
  const total = Number(data.total_vectors ?? ((data.block_vectors || 0) + (data.correlate_vectors || 0) + (data.annotate_vectors || 0)));
  const generation = Number(data.generation || 0);
  const kernelGeneration = Number(data.kernel_generation || 0);
  const overallStatus = String(data.overall_status || 'NEVER_SYNCED').toUpperCase();
  const kernelStatus = String(data.kernel_apply_status || 'NOT_APPLIED').toUpperCase();

  const blockVectors = Number(data.block_vectors || 0);
  const correlateVectors = Number(data.correlate_vectors || 0);
  const annotateVectors = Number(data.annotate_vectors || 0);
  const problemSources = statuses.stale + statuses.error;

  text('threatIntelTotalVectors', total.toLocaleString());
  text('threatIntelBlockVectors', blockVectors.toLocaleString());
  text('threatIntelCorrelateVectors', correlateVectors.toLocaleString());
  text('threatIntelAnnotateVectors', annotateVectors.toLocaleString());
  text('threatIntelHealthySources', `${statuses.ok} / ${feeds.length}`);
  text('threatIntelProblemSources', String(problemSources));
  renderVectorComposition(blockVectors, correlateVectors, annotateVectors);
  // Functional colour only where the value is actionable.
  const problemNode = document.getElementById('threatIntelProblemSources');
  if (problemNode) problemNode.classList.toggle('tone-attention', problemSources > 0);

  renderStatusPill('threatIntelSyncStatusBadge', overallStatus, {
    OK: 'good', PARTIAL: 'warn', STALE: 'warn', ERROR: 'danger', DISABLED: 'muted', NEVER_SYNCED: 'muted'
  });
  renderStatusPill('threatIntelKernelStatusBadge', kernelStatus, {
    APPLIED: 'good', PARTIAL: 'warn', ERROR: 'danger', DIVERGENT: 'danger', NOT_APPLIED: 'muted'
  });

  const generationText = generation > 0 ? `#${generation}` : '---';
  const kernelGenerationText = kernelGeneration > 0 ? `#${kernelGeneration}` : '---';
  const lastAttemptText = formatTimeOrNever(data.last_attempt_at);
  const lastGoodText = formatTimeOrNever(data.last_successful_sync_at);
  const lastPartialText = formatTimeOrNever(data.last_partial_successful_sync_at);
  const lastFullText = formatTimeOrNever(data.last_fully_successful_sync_at);
  const kernelApplyText = validTime(data.kernel_apply_last_at) ? formatTime(data.kernel_apply_last_at) : '---';

  text('threatIntelGeneration', generationText);
  text('threatIntelGenerationDetail', generationText);
  text('threatIntelFingerprint', data.fingerprint || '---');
  text('threatIntelLastAttempt', lastAttemptText);
  text('threatIntelLastSuccess', lastGoodText);
  text('threatIntelLastPartialSync', lastPartialText);
  text('threatIntelLastFullSync', lastFullText);
  text('threatIntelLastFullSyncDetail', lastFullText);
  text('threatIntelKernelGeneration', kernelGenerationText);
  text('threatIntelKernelGenerationDetail', kernelGenerationText);
  text('threatIntelKernelAppliedAt', kernelApplyText);
  text('threatIntelKernelAppliedAtDetail', kernelApplyText);
  text('threatIntelKernelStateText', kernelStatus);
  text('threatIntelKernelDelta', `+${Number(data.last_kernel_added || 0).toLocaleString()} / -${Number(data.last_kernel_deleted || 0).toLocaleString()}`);
  text('threatIntelGenerationRelation', generationRelation(generation, kernelGeneration, kernelStatus));
  text('threatIntelSourceSummary', `${statuses.ok} / ${feeds.length} OK`);
  text('threatIntelFeedOKCount', String(statuses.ok));
  text('threatIntelFeedStaleCount', String(statuses.stale));
  text('threatIntelFeedErrorCount', String(statuses.error));

  const kErrEl = byID('threatIntelKernelErrorRow');
  if (kErrEl) {
    kErrEl.hidden = !data.last_kernel_error;
    if (data.last_kernel_error) text('threatIntelKernelErrorMsg', data.last_kernel_error);
  }

  renderTruthStrip(overallStatus, kernelStatus, statuses, feeds.length, generation, kernelGeneration);
  renderFeedTable(feeds);
}

function renderTruthStrip(overallStatus, kernelStatus, statuses, feedCount, generation, kernelGeneration) {
  const dot = byID('threatIntelTruthDot');
  const title = byID('threatIntelTruthTitle');
  const detail = byID('threatIntelTruthDetail');
  if (!dot || !title || !detail) return;

  let cls = 'muted';
  let heading = t('threatIntel.truthNeverTitle');
  let message = t('threatIntel.truthNeverDetail');

  if (overallStatus === 'DISABLED') {
    heading = t('threatIntel.truthDisabledTitle');
    message = t('threatIntel.truthDisabledDetail');
  } else if (kernelStatus === 'DIVERGENT') {
    cls = 'danger';
    heading = t('threatIntel.truthDivergentTitle');
    message = t('threatIntel.truthDivergentDetail');
  } else if (overallStatus === 'ERROR' || kernelStatus === 'ERROR') {
    cls = 'danger';
    heading = t('threatIntel.truthErrorTitle');
    message = t('threatIntel.truthErrorDetail');
  } else if (overallStatus === 'PARTIAL' || overallStatus === 'STALE' || statuses.stale > 0 || statuses.error > 0 || kernelStatus === 'PARTIAL') {
    cls = 'warning';
    heading = t('threatIntel.truthPartialTitle');
    message = t('threatIntel.truthPartialDetail', { ok: statuses.ok, total: feedCount });
  } else if (overallStatus === 'OK' && kernelStatus === 'APPLIED') {
    cls = 'good';
    heading = t('threatIntel.truthAppliedTitle');
    message = generation === kernelGeneration
      ? t('threatIntel.truthAppliedDetail', { generation })
      : t('threatIntel.truthGenerationMismatch', { generation, kernelGeneration });
  } else if (overallStatus === 'OK') {
    cls = 'warning';
    heading = t('threatIntel.truthKernelPendingTitle');
    message = t('threatIntel.truthKernelPendingDetail', { generation: generation || 0, kernelStatus });
  }

  dot.className = `status-dot ${cls}`;
  title.textContent = heading;
  detail.textContent = message;
}

function renderFeedTable(feeds) {
  const tbody = byID('threatIntelFeedsTableBody');
  if (!tbody) return;
  tbody.replaceChildren();
  if (feeds.length === 0) {
    appendEmptyRow(tbody, t('threatIntel.noSources'));
    return;
  }

  feeds.forEach(feed => {
    const tr = document.createElement('tr');
    const status = String(feed.status || deriveFeedStatus(feed)).toUpperCase();
    const action = String(feed.action || 'correlate').toUpperCase();
    const failures = Number(feed.consecutive_fails || 0);
    const generation = Number(feed.last_good_gen || 0);
    tr.className = `threat-intel-feed-row is-${status.toLowerCase().replace(/[^a-z0-9_-]/g, '')}`;

    const sourceCell = document.createElement('td');
    const sourceWrap = document.createElement('div');
    sourceWrap.className = 'ti-source-cell';
    const sourceName = document.createElement('strong');
    sourceName.className = 'font-mono text-cyan';
    sourceName.textContent = String(feed.name || feed.id || 'Feed');
    const sourceID = document.createElement('span');
    sourceID.className = 'fs-xs text-muted font-mono';
    sourceID.textContent = String(feed.id || '');
    sourceWrap.append(sourceName, sourceID);
    sourceCell.appendChild(sourceWrap);

    const actionCell = document.createElement('td');
    const actionPill = document.createElement('span');
    actionPill.className = `status-pill ${actionClass(action)}`;
    actionPill.textContent = actionLabel(action);
    actionCell.appendChild(actionPill);

    const statusCell = document.createElement('td');
    const statusPill = document.createElement('span');
    statusPill.className = `status-pill ${statusClass(status)}`;
    statusPill.textContent = status;
    statusCell.appendChild(statusPill);

    const vectorsCell = document.createElement('td');
    vectorsCell.className = 'font-mono fs-xs text-right';
    vectorsCell.textContent = Number(feed.last_good_count || 0).toLocaleString();

    const generationCell = document.createElement('td');
    generationCell.className = 'font-mono fs-xs';
    generationCell.textContent = generation > 0 ? `#${generation}` : '---';

    const attemptCell = document.createElement('td');
    attemptCell.className = 'fs-xs';
    attemptCell.textContent = validTime(feed.last_attempt_at) ? formatTime(feed.last_attempt_at) : '---';

    const goodCell = document.createElement('td');
    goodCell.className = 'fs-xs';
    goodCell.textContent = validTime(feed.last_good_at) ? formatTime(feed.last_good_at) : '---';

    const failuresCell = document.createElement('td');
    failuresCell.className = `${failures > 0 ? 'text-danger font-bold' : 'text-muted'} text-center`;
    failuresCell.textContent = String(failures);

    const errorCell = document.createElement('td');
    errorCell.className = 'fs-xs text-muted ti-error-cell';
    errorCell.title = String(feed.last_error || '');
    errorCell.textContent = feed.last_error ? truncate(String(feed.last_error), 72) : '---';

    tr.append(sourceCell, actionCell, statusCell, vectorsCell, generationCell, attemptCell, goodCell, failuresCell, errorCell);
    tbody.appendChild(tr);
  });
}

// renderVectorComposition sizes the share bar from the same three numbers that
// are printed as text rows beside it, so the visualisation never becomes the only
// way to read the value and a total of zero degrades to an empty track.
function renderVectorComposition(block, correlate, annotate) {
  const total = block + correlate + annotate;
  const segments = [
    ['threatIntelBlockSegment', block],
    ['threatIntelCorrelateSegment', correlate],
    ['threatIntelAnnotateSegment', annotate]
  ];
  for (const [id, value] of segments) {
    const node = document.getElementById(id);
    if (!node) continue;
    const share = total > 0 ? (value / total) * 100 : 0;
    node.style.width = `${share}%`;
    node.hidden = share <= 0;
    node.title = `${value.toLocaleString()} (${share.toFixed(1)}%)`;
  }
}

function renderThreatIntelOffline(errMsg) {
  renderStatusPill('threatIntelSyncStatusBadge', 'OFFLINE', { OFFLINE: 'danger' });
  renderStatusPill('threatIntelKernelStatusBadge', 'UNKNOWN', { UNKNOWN: 'muted' });

  for (const id of ['threatIntelTotalVectors', 'threatIntelBlockVectors', 'threatIntelCorrelateVectors', 'threatIntelAnnotateVectors']) text(id, '---');
  text('threatIntelHealthySources', '---');
  text('threatIntelProblemSources', '---');
  text('threatIntelGeneration', '---');
  text('threatIntelGenerationDetail', '---');
  text('threatIntelLastAttempt', '---');
  text('threatIntelLastSuccess', '---');
  text('threatIntelLastFullSync', '---');
  text('threatIntelLastFullSyncDetail', '---');
  // A stale composition bar would keep asserting a distribution the view can no
  // longer substantiate, so the degraded state clears it as well.
  renderVectorComposition(0, 0, 0);
  const problemNode = document.getElementById('threatIntelProblemSources');
  if (problemNode) problemNode.classList.remove('tone-attention');
  text('threatIntelKernelGeneration', '---');
  text('threatIntelKernelGenerationDetail', '---');
  text('threatIntelKernelAppliedAt', '---');
  text('threatIntelKernelAppliedAtDetail', '---');
  text('threatIntelKernelStateText', 'UNKNOWN');
  text('threatIntelGenerationRelation', 'UNKNOWN');
  text('threatIntelSourceSummary', 'OFFLINE');
  text('threatIntelFingerprint', '---');
  text('threatIntelFeedOKCount', '0');
  text('threatIntelFeedStaleCount', '0');
  text('threatIntelFeedErrorCount', '0');

  const dot = byID('threatIntelTruthDot');
  if (dot) dot.className = 'status-dot danger';
  text('threatIntelTruthTitle', t('threatIntel.offlineTitle'));
  text('threatIntelTruthDetail', t('threatIntel.offlineDetail', { error: errMsg }));

  const kErrEl = byID('threatIntelKernelErrorRow');
  if (kErrEl) kErrEl.hidden = true;

  const tbody = byID('threatIntelFeedsTableBody');
  if (tbody) appendEmptyRow(tbody, t('threatIntel.fetchError', { error: errMsg }), 'text-danger');
}

export function handleThreatIntelStreamEvent(event) {
  if (!event || event.source !== 'intelligence' || !String(event.kind || '').startsWith('feeds.')) return;
  const kind = String(event.kind);
  const phases = {
    'feeds.sync_started': ['FETCHING', t('threatIntel.syncPhaseFetching')],
    'feeds.sources_validated': ['VALIDATED', t('threatIntel.syncPhaseValidated')],
    'feeds.sources_partial': ['PARTIAL', event.message || t('threatIntel.syncPhasePartial')],
    'feeds.kernel_applying': ['APPLYING', t('threatIntel.syncPhaseApplying')],
    'feeds.kernel_apply_failed': ['ERROR', event.message || t('threatIntel.syncPhaseKernelError')],
    'feeds.sync_failed': ['ERROR', event.message || t('threatIntel.syncPhaseFailed')],
    'feeds.synced': ['APPLIED', event.message || t('threatIntel.syncPhaseDone')],
    'feeds.auto_synced': ['APPLIED', event.message || t('threatIntel.syncPhaseDone')]
  };
  const phase = phases[kind];
  if (!phase) return;
  renderSyncOperation(phase[0], phase[1]);
}

function renderSyncOperation(state, detail) {
  const strip = byID('threatIntelOperationStrip');
  if (!strip) return;
  strip.hidden = false;
  const normalized = String(state || 'IDLE').toUpperCase();
  renderStatusPill('threatIntelOperationState', normalized, {
    FETCHING: 'warn', VALIDATED: 'good', APPLYING: 'warn', APPLIED: 'good', PARTIAL: 'warn', ERROR: 'danger'
  });
  text('threatIntelOperationDetail', detail || '---');
}

function summarizeFeedStatuses(feeds) {
  const summary = { ok: 0, stale: 0, error: 0, never: 0 };
  feeds.forEach(feed => {
    const status = String(feed.status || deriveFeedStatus(feed)).toUpperCase();
    if (status === 'OK') summary.ok++;
    else if (status === 'STALE' || status === 'PARTIAL') summary.stale++;
    else if (status === 'ERROR' || status === 'OFFLINE') summary.error++;
    else summary.never++;
  });
  return summary;
}

function deriveFeedStatus(feed) {
  if (!validTime(feed.last_attempt_at)) return 'NEVER_SYNCED';
  if (feed.last_error || Number(feed.consecutive_fails || 0) > 0) return Number(feed.last_good_gen || 0) > 0 ? 'STALE' : 'ERROR';
  return 'OK';
}

function generationRelation(feedGeneration, kernelGeneration, kernelStatus) {
  if (kernelStatus === 'DIVERGENT') return 'DIVERGENT';
  if (kernelStatus !== 'APPLIED') return kernelStatus;
  if (!feedGeneration || !kernelGeneration) return 'UNVERIFIED';
  return feedGeneration === kernelGeneration ? 'MATCH' : `#${feedGeneration} / #${kernelGeneration}`;
}

function renderStatusPill(id, value, classes) {
  const el = byID(id);
  if (!el) return;
  const key = String(value || 'UNKNOWN').toUpperCase();
  el.className = `status-pill ${classes[key] || 'muted'}`;
  el.textContent = key;
}

function statusClass(status) {
  if (status === 'OK') return 'good';
  if (status === 'STALE' || status === 'PARTIAL') return 'warn';
  if (status === 'ERROR' || status === 'OFFLINE') return 'danger';
  return 'muted';
}

function actionClass(action) {
  if (action === 'BLOCK') return 'danger';
  if (action === 'CORRELATE' || action === 'CORRELATE_ONLY') return 'warn';
  if (action === 'ANNOTATE' || action === 'ANNOTATE_ONLY') return 'good';
  return 'muted';
}

function actionLabel(action) {
  if (action === 'CORRELATE_ONLY') return 'CORRELATE';
  if (action === 'ANNOTATE_ONLY') return 'ANNOTATE';
  return action;
}

function validTime(value) {
  if (!value || String(value).startsWith('0001-01-01')) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed > 0;
}

function formatTimeOrNever(value) {
  return validTime(value) ? formatTime(value) : t('threatIntel.never');
}

function appendEmptyRow(tbody, message, extraClass = 'text-muted') {
  tbody.replaceChildren();
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 9;
  td.className = `text-center ${extraClass}`;
  td.style.padding = '28px';
  td.textContent = message;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function escapeHTML(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function escapeAttr(value) { return escapeHTML(value); }
function truncate(str, len) { return str && str.length > len ? `${str.substring(0, len)}…` : (str || ''); }
