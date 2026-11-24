// STATUS: DIAMANT VGT SUPREME
'use strict';

// Titan surfaces: executive-gate status, events, review/contain actions and
// Titan quarantine. Split out of the former single app.js module
// (refactoring wave 2a, structure-only).

import {
  APIError,
  containTitanEvent,
  getTitanEvents,
  getTitanQuarantine,
  getTitanStatus,
  reviewTitanEvent,
  setTitanPolicy
} from '../api.js';
import {
  locale,
  t
} from '../i18n.js';
import {
  byID,
  formatTime,
  text,
  toast
} from '../render.js';
import {
  emptyTable,
  handleActionError,
  number,
  on,
  setChecked,
  setValue
} from './navigation.js';

// ------------------------------------------------------------------ GeDefense Titan
// The Titan surface renders only what the control plane actually returns. Reads
// are independent so one missing endpoint cannot blank the page; every write is
// reason-bound and a refusal is displayed verbatim. There is deliberately no
// actor attribution: Titan reports authorization state and correlation quality.

const titanState = {
  status: null,
  statusError: '',
  events: [],
  nextBefore: '',
  eventsLoaded: false,
  eventsError: '',
  quarantine: null,
  quarantineError: '',
  busy: false,
  activeEvent: null,
  lastFocus: null,
  timer: 0
};
const TITAN_EVENT_PAGE = 20;
const TITAN_EVENT_CAP = 100;

function titanVisible() {
  return (location.hash.replace('#', '') || 'overview') === 'titan' && !document.hidden;
}

function titanSetNotice(titleKey, bodyKey, tone = 'warning') {
  const box = byID('titanNotice');
  if (!box) return;
  text('titanNoticeTitle', t(titleKey));
  text('titanNoticeBody', t(bodyKey));
  box.dataset.tone = tone;
  box.hidden = false;
}

function titanClearNotice() {
  const box = byID('titanNotice');
  if (box) box.hidden = true;
}

function titanSetInline(id, message, tone = '') {
  const node = byID(id);
  if (!node) return;
  if (!message) {
    node.hidden = true;
    node.textContent = '';
    return;
  }
  node.hidden = false;
  node.textContent = String(message);
  node.dataset.tone = tone;
}

function titanReason(value) {
  const reason = String(value ?? '').trim();
  if (!reason) return '';
  const bytes = new TextEncoder().encode(reason).length;
  return bytes >= 8 && bytes <= 512 ? reason : '';
}

function titanCount(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

function titanDisplay(value) {
  return value === undefined || value === null || value === '' ? '---' : String(value);
}

function titanModeLabel(mode) {
  switch (String(mode || '').toUpperCase()) {
    case 'OBSERVE': return t('titan.mode.OBSERVE');
    case 'CONTAIN': return t('titan.mode.CONTAIN');
    case 'STRICT': return t('titan.mode.STRICT');
    default: return t('titan.value.unknown');
  }
}

function titanModeTone(mode) {
  switch (String(mode || '').toUpperCase()) {
    case 'OBSERVE': return 'muted';
    case 'CONTAIN': return 'warning';
    case 'STRICT': return 'danger';
    default: return 'muted';
  }
}

function titanSensorLabel(state) {
  switch (String(state || '').toLowerCase()) {
    case 'healthy': return t('titan.sensor.healthy');
    case 'degraded': return t('titan.sensor.degraded');
    case 'disabled': return t('titan.sensor.disabled');
    default: return t('titan.value.unknown');
  }
}

function titanSensorTone(state) {
  switch (String(state || '').toLowerCase()) {
    case 'healthy': return 'good';
    case 'degraded': return 'warning';
    case 'disabled': return 'danger';
    default: return 'muted';
  }
}

function titanTrustLabel(state) {
  switch (String(state || '').toUpperCase()) {
    case 'AUTHORIZED': return t('titan.trust.AUTHORIZED');
    case 'TOLERATED': return t('titan.trust.TOLERATED');
    case 'UNEXPECTED': return t('titan.trust.UNEXPECTED');
    case 'COMPROMISED': return t('titan.trust.COMPROMISED');
    default: return titanDisplay(state);
  }
}

function titanCorrelationLabel(value) {
  switch (String(value || '').toUpperCase()) {
    case 'OBSERVED': return t('titan.correlationQuality.OBSERVED');
    case 'TEMPORAL': return t('titan.correlationQuality.TEMPORAL');
    case 'NONE': return t('titan.correlationQuality.NONE');
    default: return titanDisplay(value);
  }
}

function titanChangeLabel(value) {
  switch (String(value || '').toLowerCase()) {
    case 'created': return t('titan.change.created');
    case 'modified': return t('titan.change.modified');
    case 'removed': return t('titan.change.removed');
    case 'deleted': return t('titan.change.deleted');
    case 'renamed': return t('titan.change.renamed');
    case 'attributes': return t('titan.change.attributes');
    case 'executed': return t('titan.change.executed');
    case 'unknown': return t('titan.change.unknown');
    default: return value ? String(value).toUpperCase() : t('titan.change.other');
  }
}

function titanResponseLabel(value) {
  if (value === undefined || value === null || value === '') return t('titan.events.noResponse');
  switch (String(value).toUpperCase()) {
    case 'OBSERVED': return t('titan.response.OBSERVED');
    case 'CONTAINED': return t('titan.response.CONTAINED');
    case 'CONTAIN_UNAVAILABLE': return t('titan.response.CONTAIN_UNAVAILABLE');
    case 'CONTAIN_FAILED': return t('titan.response.CONTAIN_FAILED');
    case 'NO_ACTION': return t('titan.response.NO_ACTION');
    case 'REVIEW_REQUIRED': return t('titan.response.REVIEW_REQUIRED');
    case 'BLOCKED': return t('titan.response.BLOCKED');
    case 'QUARANTINED': return t('titan.response.QUARANTINED');
    case 'REVIEWED': return t('titan.response.REVIEWED');
    case 'REFUSED': return t('titan.response.REFUSED');
    case 'UNAVAILABLE': return t('titan.response.UNAVAILABLE');
    case 'NOOP': return t('titan.response.NOOP');
    default: return String(value).toUpperCase();
  }
}

function titanAuthorizationLabel(value) {
  if (value === undefined || value === null || value === '') return t('titan.events.noAuthorizationData');
  switch (String(value).toUpperCase()) {
    case 'PACKAGE_MANAGER': return t('titan.authorization.PACKAGE_MANAGER');
    case 'OWNER_POLICY': return t('titan.authorization.OWNER_POLICY');
    case 'FLEET_ALLOWLIST': return t('titan.authorization.FLEET_ALLOWLIST');
    case 'PROTECTED_PATH': return t('titan.authorization.PROTECTED_PATH');
    case 'BASELINE': return t('titan.authorization.BASELINE');
    case 'UNKNOWN': return t('titan.authorization.UNKNOWN');
    case 'NONE': return t('titan.authorization.NONE');
    default: return String(value);
  }
}

function titanSeverityTone(value) {
  const severity = String(value || '').toLowerCase();
  if (['critical', 'high'].includes(severity)) return severity;
  if (['medium', 'warning', 'warn'].includes(severity)) return 'medium';
  if (['low', 'info', 'informational'].includes(severity)) return 'low';
  return '';
}

function renderTitanTrust(trust = {}) {
  const states = ['AUTHORIZED', 'TOLERATED', 'UNEXPECTED', 'COMPROMISED'];
  let total = 0;
  let known = false;
  for (const state of states) {
    const count = titanCount(trust?.[state]);
    const label = count === null ? '---' : number(count);
    const id = state.charAt(0) + state.slice(1).toLowerCase();
    text(`titanTrust${id}`, label);
    if (count !== null) {
      total += count;
      known = true;
    }
  }
  text('titanTrustTotal', known ? number(total) : '---');
  for (const state of states) {
    const id = state.charAt(0) + state.slice(1).toLowerCase();
    const bar = byID(`titanTrust${id}Bar`);
    if (!bar) continue;
    const count = titanCount(trust?.[state]);
    const percent = known && count !== null && total > 0 ? Math.max(1, Math.round((count / total) * 100)) : 0;
    bar.style.width = `${percent}%`;
    bar.parentElement?.setAttribute('title', `${titanTrustLabel(state)}: ${count === null ? '---' : number(count)}`);
  }
}

function renderTitanStatus(payload) {
  titanState.status = payload || {};
  titanState.statusError = '';
  titanClearNotice();
  const status = titanState.status;
  const modeNode = byID('titanModeBadge');
  if (modeNode) {
    modeNode.textContent = titanModeLabel(status.mode);
    modeNode.className = `status-pill ${titanModeTone(status.mode)}`;
  }
  const armedLabel = typeof status.armed === 'boolean' ? (status.armed ? t('titan.value.yes') : t('titan.value.no')) : t('titan.value.unknown');
  const armedNode = byID('titanArmedBadge');
  if (armedNode) {
    armedNode.textContent = armedLabel;
    armedNode.className = `status-pill ${status.armed ? 'warning' : 'muted'}`;
  }
  const sensorBadge = byID('titanSensorBadge');
  if (sensorBadge) {
    sensorBadge.textContent = titanSensorLabel(status.sensor?.state);
    sensorBadge.className = `status-pill ${titanSensorTone(status.sensor?.state)}`;
  }
  text('titanUpdated', status.updated_utc ? formatTime(status.updated_utc) : t('titan.value.notAvailable'));
  renderTitanTrust(status.trust || {});
  text('titanEventsTotal', titanCount(status.events_total) === null ? '---' : number(status.events_total));
  text('titanOpenFindings', titanCount(status.open_findings) === null ? '---' : number(status.open_findings));
  text('titanQuarantineMetric', titanCount(status.quarantine_count) === null ? '---' : number(status.quarantine_count));
  text('titanPolicyMode', titanModeLabel(status.mode));
  text('titanPolicyArmed', typeof status.armed === 'boolean' ? (status.armed ? t('titan.value.yes') : t('titan.value.no')) : t('titan.value.unknown'));
  text('titanPolicyAutoContain', typeof status.auto_contain === 'boolean' ? (status.auto_contain ? t('titan.value.yes') : t('titan.value.no')) : t('titan.value.unknown'));
  const hint = byID('titanPolicyHint');
  if (hint) {
    const mode = String(status.mode || '').toUpperCase();
    hint.textContent = mode === 'OBSERVE'
      ? t('titan.mode.OBSERVE.desc')
      : mode === 'CONTAIN'
        ? t('titan.mode.CONTAIN.desc')
        : mode === 'STRICT'
          ? t('titan.mode.STRICT.desc')
          : t('titan.policy.readOnlyHint');
  }
  text('titanSensorState', titanSensorLabel(status.sensor?.state));
  text('titanSensorLast', status.sensor?.last_observation_utc ? formatTime(status.sensor.last_observation_utc) : t('titan.value.notAvailable'));
  const sensorError = status.sensor?.error ? String(status.sensor.error) : '';
  const sensorNode = byID('titanSensorError');
  if (sensorNode) {
    sensorNode.hidden = !sensorError;
    sensorNode.textContent = sensorError;
    sensorNode.dataset.tone = sensorError ? 'bad' : '';
  }
  text('titanCorrObserved', titanCount(status.correlation?.OBSERVED) === null ? '---' : number(status.correlation.OBSERVED));
  text('titanCorrTemporal', titanCount(status.correlation?.TEMPORAL) === null ? '---' : number(status.correlation.TEMPORAL));
  text('titanCorrNone', titanCount(status.correlation?.NONE) === null ? '---' : number(status.correlation.NONE));
  const policyButton = byID('titanPolicyOpen');
  if (policyButton) policyButton.disabled = false;
}

function renderTitanStatusUnavailable(error) {
  titanState.status = null;
  titanState.statusError = String(error?.message || error || t('titan.value.notAvailable'));
  titanSetNotice('titan.notice.unavailableTitle', 'titan.notice.unavailableBody', 'bad');
  const noticeBody = byID('titanNoticeBody');
  if (noticeBody) noticeBody.textContent = `${t('titan.notice.unavailableBody')} ${titanState.statusError}`;
  for (const id of ['titanModeBadge', 'titanArmedBadge', 'titanSensorBadge', 'titanTrustTotal',
    'titanTrustAuthorized', 'titanTrustTolerated', 'titanTrustUnexpected', 'titanTrustCompromised',
    'titanEventsTotal', 'titanOpenFindings', 'titanQuarantineMetric', 'titanPolicyMode',
    'titanPolicyArmed', 'titanPolicyAutoContain', 'titanSensorState', 'titanSensorLast',
    'titanCorrObserved', 'titanCorrTemporal', 'titanCorrNone']) {
    text(id, '---');
    const node = byID(id);
    if (node && node.classList.contains('status-pill')) {
      node.textContent = t('titan.value.notAvailable');
      node.className = 'status-pill muted';
    }
  }
  text('titanUpdated', t('titan.value.notAvailable'));
  for (const id of ['titanTrustAuthorizedBar', 'titanTrustToleratedBar', 'titanTrustUnexpectedBar', 'titanTrustCompromisedBar']) {
    const bar = byID(id);
    if (bar) bar.style.width = '0%';
  }
  const sensorNode = byID('titanSensorError');
  if (sensorNode) {
    sensorNode.hidden = !titanState.statusError;
    sensorNode.textContent = titanState.statusError;
    sensorNode.dataset.tone = 'bad';
  }
  const policyButton = byID('titanPolicyOpen');
  if (policyButton) policyButton.disabled = true;
}

async function loadTitanStatus() {
  try {
    const payload = await getTitanStatus();
    if (payload && typeof payload === 'object') renderTitanStatus(payload);
    else renderTitanStatusUnavailable(new Error(t('titan.value.notAvailable')));
    return payload;
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
      return null;
    }
    renderTitanStatusUnavailable(error);
    return null;
  }
}

function titanEventButtons(event) {
  const wrapper = document.createElement('div');
  wrapper.className = 'titan-actions';
  const eventID = event?.id === undefined || event?.id === null ? '' : String(event.id);
  const review = document.createElement('button');
  review.type = 'button';
  review.className = 'button button-quiet';
  review.textContent = t('titan.action.review');
  review.disabled = !eventID;
  review.addEventListener('click', () => openTitanReviewDialog(event));
  const contain = document.createElement('button');
  contain.type = 'button';
  contain.className = 'button button-danger';
  contain.textContent = t('titan.action.contain');
  contain.disabled = !eventID;
  contain.addEventListener('click', () => openTitanContainDialog(event));
  wrapper.append(review, contain);
  return wrapper;
}

function renderTitanEvents() {
  const body = byID('titanEventRows');
  if (!body) return;
  const events = Array.isArray(titanState.events) ? titanState.events : [];
  text('titanEventCount', events.length ? t('titan.events.count', { count: number(events.length) }) : '---');
  const countNode = byID('titanEventCount');
  if (countNode) countNode.className = `status-pill ${events.length ? 'info' : 'muted'}`;
  if (titanState.eventsError) {
    titanSetInline('titanEventsNotice', `${t('titan.events.unavailable')} ${titanState.eventsError}`, 'bad');
  } else {
    titanSetInline('titanEventsNotice', '');
  }
  if (!events.length) {
    emptyTable(body, 10, titanState.eventsError ? t('titan.events.unavailable') : t('titan.events.empty'));
    text('titanEventsInfo', titanState.eventsError ? t('titan.events.unavailable') : t('titan.events.emptyHint'));
  } else {
    const rows = events.map(event => {
      const row = document.createElement('tr');
      const timeCell = document.createElement('td');
      timeCell.className = 'mono';
      timeCell.textContent = event.observed_utc ? new Date(event.observed_utc).toLocaleTimeString(locale()) : '---';
      timeCell.title = event.observed_utc ? formatTime(event.observed_utc) : '---';
      const pathCell = document.createElement('td');
      pathCell.className = 'mono titan-path';
      pathCell.textContent = titanDisplay(event.path);
      pathCell.title = titanDisplay(event.path);
      const changeCell = document.createElement('td');
      changeCell.textContent = titanChangeLabel(event.change_type);
      changeCell.title = titanChangeLabel(event.change_type);
      const trustCell = document.createElement('td');
      const trustPill = document.createElement('span');
      const trustState = String(event.trust_state || '').toUpperCase();
      trustPill.className = `titan-state ${['AUTHORIZED', 'TOLERATED', 'UNEXPECTED', 'COMPROMISED'].includes(trustState) ? trustState : 'UNKNOWN'}`;
      trustPill.textContent = titanTrustLabel(event.trust_state);
      trustCell.append(trustPill);
      trustCell.title = titanTrustLabel(event.trust_state);
      const authorizationCell = document.createElement('td');
      authorizationCell.textContent = titanAuthorizationLabel(event.authorization_reason);
      authorizationCell.title = authorizationCell.textContent;
      const correlationCell = document.createElement('td');
      const correlation = document.createElement('span');
      const quality = String(event.correlation_quality || '').toUpperCase();
      correlation.className = `titan-state ${['OBSERVED', 'TEMPORAL', 'NONE'].includes(quality) ? quality : 'NONE'}`;
      correlation.textContent = titanCorrelationLabel(event.correlation_quality);
      correlationCell.append(correlation);
      correlationCell.title = correlation.textContent;
      const responseCell = document.createElement('td');
      responseCell.textContent = titanResponseLabel(event.response);
      responseCell.title = responseCell.textContent;
      const severityCell = document.createElement('td');
      const severityNode = document.createElement('span');
      severityNode.className = `titan-sev ${titanSeverityTone(event.severity)}`.trim();
      severityNode.textContent = String(event.severity || '---').toUpperCase();
      severityCell.append(severityNode);
      severityCell.title = severityNode.textContent;
      const sensorCell = document.createElement('td');
      sensorCell.textContent = titanDisplay(event.sensor);
      sensorCell.title = sensorCell.textContent;
      const actionCell = document.createElement('td');
      actionCell.append(titanEventButtons(event));
      row.append(timeCell, pathCell, changeCell, trustCell, authorizationCell, correlationCell, responseCell, severityCell, sensorCell, actionCell);
      return row;
    });
    body.replaceChildren(...rows);
    const shown = events.length;
    const capped = shown >= TITAN_EVENT_CAP;
    text('titanEventsInfo', t('titan.events.showing', { count: number(shown) }));
    if (capped) text('titanEventsInfo', t('titan.events.cap', { count: number(shown) }));
  }
  const loadMore = byID('titanLoadMore');
  if (loadMore) loadMore.hidden = !titanState.nextBefore || events.length >= TITAN_EVENT_CAP;
  const reset = byID('titanEventsReset');
  if (reset) reset.disabled = titanState.busy;
}

async function loadTitanEvents({ reset = false, append = false } = {}) {
  if (titanState.busy) return;
  titanState.busy = true;
  const before = reset || !append ? '' : titanState.nextBefore;
  const requested = reset || !append ? [] : titanState.events;
  renderTitanEvents();
  try {
    const payload = await getTitanEvents(TITAN_EVENT_PAGE, before);
    const events = Array.isArray(payload?.events) ? payload.events : [];
    const nextBefore = typeof payload?.next_before === 'string' ? payload.next_before : '';
    titanState.eventsError = '';
    titanState.events = [...requested, ...events].slice(0, TITAN_EVENT_CAP);
    titanState.nextBefore = titanState.events.length >= TITAN_EVENT_CAP ? '' : nextBefore;
    titanState.eventsLoaded = true;
    renderTitanEvents();
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
      return;
    }
    titanState.eventsError = String(error?.message || t('titan.events.unavailable'));
    if (!titanState.events.length) titanState.events = [];
    renderTitanEvents();
  } finally {
    titanState.busy = false;
    renderTitanEvents();
  }
}

function renderTitanQuarantine(payload) {
  const body = byID('titanQuarantineRows');
  if (!body) return;
  const items = Array.isArray(payload?.items) ? payload.items : [];
  const count = titanCount(payload?.count);
  text('titanQuarantineCount', count === null ? (items.length ? number(items.length) : '---') : number(count));
  if (titanState.quarantineError) {
    titanSetInline('titanQuarantineNotice', `${t('titan.quarantine.unavailable')} ${titanState.quarantineError}`, 'bad');
  } else {
    titanSetInline('titanQuarantineNotice', '');
  }
  if (!items.length) {
    emptyTable(body, 5, titanState.quarantineError ? t('titan.quarantine.unavailable') : t('titan.quarantine.empty'));
    return;
  }
  const rows = items.slice(0, TITAN_EVENT_CAP).map(item => {
    const row = document.createElement('tr');
    const created = document.createElement('td');
    created.className = 'mono';
    created.textContent = item.created_utc ? formatTime(item.created_utc) : '---';
    created.title = created.textContent;
    const event = document.createElement('td');
    event.className = 'mono';
    event.textContent = titanDisplay(item.event_id);
    const path = document.createElement('td');
    path.className = 'mono titan-path';
    path.textContent = titanDisplay(item.path);
    path.title = titanDisplay(item.path);
    const hash = document.createElement('td');
    hash.className = 'mono';
    hash.textContent = item.sample_sha256 ? `${String(item.sample_sha256).slice(0, 16)}â€¦` : '---';
    hash.title = item.sample_sha256 ? String(item.sample_sha256) : '';
    const state = document.createElement('td');
    state.textContent = titanDisplay(item.state);
    row.append(created, event, path, hash, state);
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadTitanQuarantine() {
  try {
    const payload = await getTitanQuarantine();
    titanState.quarantine = payload || { items: [] };
    titanState.quarantineError = '';
    renderTitanQuarantine(titanState.quarantine);
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
      return;
    }
    titanState.quarantine = { items: [] };
    titanState.quarantineError = String(error?.message || t('titan.quarantine.unavailable'));
    renderTitanQuarantine(titanState.quarantine);
  }
}

async function loadTitanView() {
  titanState.events = [];
  titanState.eventsLoaded = false;
  titanState.eventsError = '';
  titanState.nextBefore = '';
  renderTitanEvents();
  renderTitanQuarantine({ items: [] });
  await loadTitanStatus();
  await Promise.all([
    loadTitanEvents({ reset: true }),
    loadTitanQuarantine()
  ]);
}

function titanRememberFocus() {
  titanState.lastFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
}

function titanOpenDialog(id) {
  const dialog = byID(id);
  if (!dialog) return false;
  titanRememberFocus();
  if (!dialog.open) dialog.showModal();
  return true;
}

function titanCloseDialog(id) {
  const dialog = byID(id);
  if (dialog?.open) dialog.close();
}

function openTitanPolicyDialog() {
  if (!titanState.status) {
    toast(t('titan.notice.unavailableTitle'), 'warning');
    return;
  }
  const status = titanState.status;
  const configuredMode = String(status.mode || 'OBSERVE').toUpperCase();
  setValue('titanPolicyModeInput', ['OBSERVE', 'CONTAIN', 'STRICT'].includes(configuredMode) ? configuredMode : 'OBSERVE');
  setChecked('titanPolicyArmedInput', Boolean(status.armed));
  setChecked('titanPolicyAutoContainInput', Boolean(status.auto_contain));
  setValue('titanPolicyReason', '');
  titanSetInline('titanPolicyError', '');
  if (titanOpenDialog('titanPolicyDialog')) byID('titanPolicyModeInput')?.focus();
}

function openTitanReviewDialog(event) {
  if (!event || event.id === undefined || event.id === null) return;
  titanState.activeEvent = event;
  const summary = byID('titanReviewSummary');
  if (summary) {
    summary.textContent = [
      titanDisplay(event.path),
      titanChangeLabel(event.change_type),
      titanTrustLabel(event.trust_state),
      titanAuthorizationLabel(event.authorization_reason),
      event.observed_utc ? formatTime(event.observed_utc) : '---'
    ].join(' Â· ');
  }
  setValue('titanReviewDecision', 'REVIEWED');
  setValue('titanReviewReason', '');
  titanSetInline('titanReviewError', '');
  if (titanOpenDialog('titanReviewDialog')) byID('titanReviewDecision')?.focus();
}

function openTitanContainDialog(event) {
  if (!event || event.id === undefined || event.id === null) return;
  titanState.activeEvent = event;
  const summary = byID('titanContainSummary');
  if (summary) {
    summary.textContent = [
      titanDisplay(event.path),
      titanChangeLabel(event.change_type),
      titanTrustLabel(event.trust_state),
      titanDisplay(event.sensor),
      event.observed_utc ? formatTime(event.observed_utc) : '---'
    ].join(' Â· ');
  }
  setValue('titanContainReason', '');
  titanSetInline('titanContainError', '');
  if (titanOpenDialog('titanContainDialog')) byID('titanContainReason')?.focus();
}

function titanSetSubmitBusy(id, busy) {
  const button = byID(id);
  if (!button) return;
  button.disabled = busy;
  button.setAttribute('aria-busy', busy ? 'true' : 'false');
}

async function submitTitanPolicy(event) {
  event.preventDefault();
  const reason = titanReason(byID('titanPolicyReason')?.value);
  if (!reason) {
    titanSetInline('titanPolicyError', t('titan.policy.reasonInvalid'), 'bad');
    byID('titanPolicyReason')?.focus();
    return;
  }
  const payload = {
    mode: String(byID('titanPolicyModeInput')?.value || 'OBSERVE').toUpperCase(),
    armed: Boolean(byID('titanPolicyArmedInput')?.checked),
    auto_contain: Boolean(byID('titanPolicyAutoContainInput')?.checked),
    reason
  };
  titanSetSubmitBusy('titanPolicySubmit', true);
  titanSetInline('titanPolicyError', '');
  try {
    const result = await setTitanPolicy(payload);
    if (result && typeof result === 'object') renderTitanStatus(result);
    titanCloseDialog('titanPolicyDialog');
    toast(t('titan.policy.success'), 'good');
    await loadTitanView();
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
    } else {
      titanSetInline('titanPolicyError', `${t('titan.policy.failure')} ${error?.message || ''}`.trim(), 'bad');
    }
  } finally {
    titanSetSubmitBusy('titanPolicySubmit', false);
  }
}

async function submitTitanReview(event) {
  event.preventDefault();
  const active = titanState.activeEvent;
  if (!active || active.id === undefined || active.id === null) return;
  const reason = titanReason(byID('titanReviewReason')?.value);
  if (!reason) {
    titanSetInline('titanReviewError', t('titan.review.reasonInvalid'), 'bad');
    byID('titanReviewReason')?.focus();
    return;
  }
  const payload = { decision: String(byID('titanReviewDecision')?.value || 'REVIEWED'), reason };
  titanSetSubmitBusy('titanReviewSubmit', true);
  titanSetInline('titanReviewError', '');
  try {
    await reviewTitanEvent(active.id, payload);
    titanCloseDialog('titanReviewDialog');
    toast(t('titan.review.success'), 'good');
    await Promise.all([loadTitanStatus(), loadTitanEvents({ reset: true })]);
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
    } else {
      titanSetInline('titanReviewError', `${t('titan.review.failure')} ${error?.message || ''}`.trim(), 'bad');
    }
  } finally {
    titanSetSubmitBusy('titanReviewSubmit', false);
  }
}

async function submitTitanContain(event) {
  event.preventDefault();
  const active = titanState.activeEvent;
  if (!active || active.id === undefined || active.id === null) return;
  const reason = titanReason(byID('titanContainReason')?.value);
  if (!reason) {
    titanSetInline('titanContainError', t('titan.contain.reasonInvalid'), 'bad');
    byID('titanContainReason')?.focus();
    return;
  }
  titanSetSubmitBusy('titanContainSubmit', true);
  titanSetInline('titanContainError', '');
  try {
    const result = await containTitanEvent({ event_id: active.id, reason });
    const outcome = String(result?.status || '').toUpperCase();
    const detail = String(result?.detail || result?.action || '');
    const succeeded = ['CONTAINED', 'QUARANTINED', 'BLOCKED', 'APPLIED', 'ACCEPTED', 'OK'].includes(outcome);
    const refused = ['REJECTED', 'UNAVAILABLE', 'CONTAIN_FAILED', 'REFUSED', 'DENIED', 'FAILED', 'NOOP', 'NO_ACTION', 'NOT_SUPPORTED'].includes(outcome) ||
      /refus|not (available|supported)|noop|denied|rejected|not contained/i.test(detail);
    if (succeeded) {
      titanCloseDialog('titanContainDialog');
      toast(t('titan.contain.success'), 'good');
      await Promise.all([loadTitanStatus(), loadTitanEvents({ reset: true }), loadTitanQuarantine()]);
    } else if (refused) {
      titanSetInline('titanContainError', `${t('titan.contain.refused')} ${detail || outcome}`.trim(), 'bad');
      toast(t('titan.contain.refused'), 'warning');
      await loadTitanStatus();
    } else {
      titanSetInline('titanContainError', t('titan.contain.neutral', { status: outcome || '---', detail: detail || '---' }), '');
      await loadTitanStatus();
    }
  } catch (error) {
    if (error instanceof APIError && error.status === 401) {
      handleActionError(error);
    } else {
      titanSetInline('titanContainError', `${t('titan.contain.failure')} ${error?.message || ''}`.trim(), 'bad');
    }
  } finally {
    titanSetSubmitBusy('titanContainSubmit', false);
  }
}

function initTitanModule() {
  on('titanRefresh', 'click', () => {
    if (titanState.busy) return;
    loadTitanView().catch(handleActionError);
  });
  on('titanNoticeRetry', 'click', () => loadTitanView().catch(handleActionError));
  on('titanPolicyOpen', 'click', openTitanPolicyDialog);
  on('titanEventsReset', 'click', () => loadTitanEvents({ reset: true }).catch(handleActionError));
  on('titanLoadMore', 'click', () => loadTitanEvents({ append: true }).catch(handleActionError));
  on('titanPolicyForm', 'submit', submitTitanPolicy);
  on('titanReviewForm', 'submit', submitTitanReview);
  on('titanContainForm', 'submit', submitTitanContain);
  for (const id of ['titanPolicyDialog', 'titanReviewDialog', 'titanContainDialog']) {
    byID(id)?.addEventListener('close', () => {
      const focus = titanState.lastFocus;
      if (focus instanceof HTMLElement && focus.isConnected) focus.focus();
      titanState.lastFocus = null;
    });
  }
  if (!titanState.timer) {
    titanState.timer = globalThis.setInterval(() => {
      if (!titanVisible() || titanState.busy) return;
      loadTitanStatus().catch(() => undefined);
    }, 20000);
  }
}

export {
  initTitanModule,
  loadTitanView
};
