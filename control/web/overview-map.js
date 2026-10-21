// STATUS: PLATIN
// Overview lifecycle, source inspector and WP-style telemetry stream.
import { getOverviewThreatMap } from './api.js';
import { t, locale } from './i18n.js';
import { normalizePayload, telemetryRows, stateFor, LIMITS } from './overview-map-data.js';
import { OverviewMapRenderer } from './overview-map-renderer.js';

let renderer = null;
let payload = null;
let rows = [];
let filter = 'all';
let paused = false;
let stale = false;
let visible = true;
let running = false;
let timer = null;
let request = null;
let events = null;
let observer = null;
let media = null;
let feedSignature = '';
let selectedIP = '';
let returnFocus = null;
const REFRESH_MS = 5000;
const $ = id => document.getElementById(id);
const text = (id, value) => { const node = $(id); if (node) node.textContent = String(value); };

function clock(value, full = false) {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '—';
  return full ? date.toLocaleString(locale(), { hour12: false }) : date.toLocaleTimeString(locale(), { hour12: false });
}

function active() {
  return running && !paused && visible && !document.hidden &&
    document.querySelector('[data-page].active')?.dataset.page === 'overview';
}

function focusIP(ip) {
  renderer?.focus(ip);
  for (const row of $('overviewMapFeedList')?.rows || []) row.classList.toggle('is-focused', Boolean(ip) && row.dataset.ip === ip);
}

function openCard(source, cluster = [], restoreFocus = true) {
  if (restoreFocus) returnFocus = document.activeElement;
  selectedIP = source.ip;
  const kind = stateFor(source);
  text('overviewCardFlag', source.countryCode || '—');
  text('overviewCardIP', source.ip || source.process || source.host || t('overview.map.local'));
  text('overviewCardBadge', t(`overview.map.state.${kind}`));
  $('overviewCardBadge').className = `overview-threat-card-badge is-${kind}`;
  text('overviewCardCountry', [source.country, source.countryCode].filter(Boolean).join(' · ') || t('overview.map.unknown'));
  text('overviewCardAsn', [source.asn, source.asName].filter(Boolean).join(' · ') || t('overview.map.unknown'));
  text('overviewCardPath', source.path || source.service || source.process || '—');
  text('overviewCardDetail', source.summary || source.rules.join(', ') || '—');
  text('overviewCardSeen', clock(source.time || source.lastSeen, true));
  const clusterNode = $('overviewCardCluster');
  clusterNode.replaceChildren();
  for (const item of cluster.filter(item => item.ip !== source.ip)) {
    const row = document.createElement('div');
    const ip = document.createElement('strong');
    ip.textContent = item.ip;
    const detail = document.createElement('span');
    detail.textContent = item.summary || item.rules.join(', ') || item.area.toUpperCase();
    row.append(ip, detail);
    clusterNode.append(row);
  }
  clusterNode.hidden = clusterNode.childElementCount === 0;
  $('overviewMapCard').hidden = false;
  focusIP(source.ip);
  if (restoreFocus) {
    $('overviewMapCard').scrollIntoView({ block: 'nearest', behavior: 'instant' });
    $('overviewCardClose').focus({ preventScroll: true });
  }
}

export function hideSourceCard(restoreFocus = true) {
  const previousIP = selectedIP;
  const card = $('overviewMapCard');
  if (card) card.hidden = true;
  selectedIP = '';
  focusIP('');
  if (restoreFocus && returnFocus instanceof Element && returnFocus.isConnected && typeof returnFocus.focus === 'function') returnFocus.focus({ preventScroll: true });
  else if (restoreFocus && previousIP) {
    const replacement = [...document.querySelectorAll('.overview-threat-marker')].find(marker => marker.dataset.source === previousIP);
    (replacement || document.querySelector('.overview-world-map'))?.focus({ preventScroll: true });
  }
  returnFocus = null;
}

function cell(row, className, value, tag = 'span') {
  const td = document.createElement('td');
  td.className = className;
  const content = document.createElement(tag);
  content.textContent = value;
  td.append(content);
  row.append(td);
  return { td, content };
}

function feedRow(event, index) {
  const row = document.createElement('tr');
  const kind = stateFor(event);
  row.className = `overview-stream-row is-${kind}`;
  row.dataset.ip = event.ip;
  const time = cell(row, 'overview-col-time', clock(event.time), 'time');
  time.content.dateTime = event.time;
  time.content.title = clock(event.time, true);
  const source = cell(row, 'overview-col-ip', event.ip || event.process || event.host || t('overview.map.local'), 'button');
  source.content.type = 'button';
  source.content.dataset.row = String(index);
  source.content.className = 'overview-source-button';
  source.content.setAttribute('aria-label', `${t('overview.map.details')}: ${source.content.textContent}`);
  const country = document.createElement('span');
  country.className = 'overview-country-code';
  country.textContent = event.countryCode || '—';
  country.title = event.country || t('overview.map.unknown');
  source.td.prepend(country);
  const path = [event.method, event.path || event.service || event.process || event.host].filter(Boolean).join(' ');
  const target = cell(row, 'overview-col-path', path || '—', 'code');
  target.content.title = path;
  const summary = document.createElement('small');
  summary.textContent = event.summary || event.rules.join(', ');
  summary.title = summary.textContent;
  target.td.append(summary);
  const module = cell(row, 'overview-col-module', (event.areas?.length ? event.areas : [event.area]).join(' · ').toUpperCase());
  module.content.className = 'overview-module-chip';
  const action = cell(row, 'overview-col-action', event.decision || t(`overview.map.state.${kind}`));
  action.content.className = `overview-action-badge is-${kind}`;
  action.content.title = event.decision || t(`overview.map.state.${kind}`);
  const network = cell(row, 'overview-col-asn', event.asn || '—', 'strong');
  const organization = document.createElement('span');
  organization.textContent = event.asName || t('overview.map.unknown');
  network.td.append(organization);
  network.td.title = [event.asn, event.asName].filter(Boolean).join(' · ');
  return row;
}

function renderFeed(force = false) {
  if (!payload) return;
  const filtered = rows.map((event, index) => ({ event, index })).filter(({ event }) => filter === 'all' || stateFor(event) === filter);
  const signature = JSON.stringify([filtered, locale()]);
  if (!force && signature === feedSignature) return;
  feedSignature = signature;
  const list = $('overviewMapFeedList');
  const focused = document.activeElement;
  const restore = focused instanceof HTMLButtonElement && list.contains(focused)
    ? rows[Number(focused.dataset.row)] : null;
  list.replaceChildren(...filtered.map(({ event, index }) => feedRow(event, index)));
  text('overviewMapEventCount', t('overview.map.eventCount', { count: filtered.length }));
  $('overviewMapFeedEmpty').hidden = filtered.length > 0;
  text('overviewMapFeedEmpty', t(rows.length ? 'overview.map.filterEmpty' : 'overview.map.feedEmpty'));
  if (restore) {
    const index = rows.findIndex(row => row.ip === restore.ip && row.time === restore.time);
    list.querySelector(`button[data-row="${index}"]`)?.focus({ preventScroll: true });
  }
  focusIP(selectedIP);
}

function renderMetadata() {
  if (!payload) return;
  const { origin, totals, geo } = payload;
  for (const [key, id] of Object.entries({ sources: 'Sources', placed: 'Placed', blocked: 'Blocked', countries: 'Countries', kinetic: 'Kinetic', l7: 'L7', xdr: 'Xdr' })) {
    text(`overviewMap${id}`, totals[key].toLocaleString(locale()));
  }
  text('overviewMapGeo', t(geo.loaded ? 'overview.map.geoReady' : 'overview.map.geoUnloaded', { count: geo.entries.toLocaleString(locale()) }));
  text('overviewMapHost', origin.ip ? `Host ${origin.ip}${origin.country ? ` · ${origin.country}` : ''}` : t('overview.map.originUnknown'));
  text('overviewMapOrigin', origin.known
    ? t('overview.map.originKnown', { place: [origin.country, origin.asName || origin.asn].filter(Boolean).join(' · ') || origin.ip })
    : t('overview.map.originUnknown'));
  text('overviewMapUpdated', t('overview.map.updated', { time: clock(payload.generated) }));
  const placed = payload.sources.some(source => source.position);
  $('overviewMapClean').hidden = payload.sources.length > 0;
  $('overviewMapEmpty').hidden = payload.sources.length === 0 || (placed && origin.known);
  text('overviewMapEmpty', t(!placed ? 'overview.map.empty' : 'overview.map.noOrigin'));
  renderer.hostLabel = t('overview.map.hub');
  renderer.render(payload);
}

function status(kind) {
  const badge = $('overviewMapStatus');
  if (!badge) return;
  badge.dataset.state = kind;
  badge.textContent = t(`overview.map.${kind}`);
  $('overviewThreatPanel')?.classList.toggle('is-stale', stale);
}

export function updateOverviewThreatMap(raw) {
  payload = normalizePayload(raw);
  try { renderTopCountries(payload); } catch (_) { /* panel is optional */ }
  stale = false;
  rows = telemetryRows(payload);
  renderMetadata();
  renderFeed();
  if (selectedIP) {
    const source = payload.sources.find(item => item.ip === selectedIP) || rows.find(item => item.ip === selectedIP);
    if (source) openCard(source, payload.sources.filter(item => item.position && source.position &&
      Math.abs(item.position[0] - source.position[0]) < .01 && Math.abs(item.position[1] - source.position[1]) < .01), false);
    else hideSourceCard(false);
  }
  status(paused ? 'paused' : 'live');
  return payload;
}

export function reportMapFailure(error) {
  console.error('overview threat map refresh failed', error);
  stale = true;
  status('failed');
  $('overviewMapClean').hidden = true;
  $('overviewMapEmpty').hidden = false;
  text('overviewMapEmpty', t(payload ? 'overview.map.stale' : 'overview.map.failedBody'));
  if (!payload) {
    $('overviewMapFeedEmpty').hidden = false;
    text('overviewMapFeedEmpty', t('overview.map.failedBody'));
  }
  renderer?.setMotion(false);
}

async function refresh() {
  if (!active() || request) return;
  const controller = new AbortController();
  request = controller;
  const deadline = setTimeout(() => controller.abort(), 10000);
  try {
    const raw = await getOverviewThreatMap(250, 120, controller.signal);
    if (request !== controller || !active()) return;
    updateOverviewThreatMap(raw);
    renderer?.setMotion(!media.matches);
  } catch (error) {
    if (request === controller && active()) reportMapFailure(error);
  } finally {
    clearTimeout(deadline);
    if (request === controller) request = null;
  }
}

function syncActivity() {
  const enabled = active();
  renderer?.setMotion(enabled && !media.matches && !stale);
  if (!enabled && request) { request.abort(); request = null; }
  if (enabled) void refresh();
}

export function startOverviewThreatMap() {
  if (running) return;
  const container = $('overviewThreatMap');
  if (!container) return;
  running = true;
  events = new AbortController();
  const options = { signal: events.signal };
  media = window.matchMedia('(prefers-reduced-motion: reduce)');
  renderer = new OverviewMapRenderer(container, openCard, t('overview.map.hub'));
  const panel = $('overviewThreatPanel');
  panel.addEventListener('click', event => {
    const target = event.target.closest('button');
    if (!target) return;
    if (target.id === 'overviewMapZoomIn') renderer.setZoom(renderer.zoom + .35);
    if (target.id === 'overviewMapZoomOut') renderer.setZoom(renderer.zoom - .35);
    if (target.id === 'overviewMapZoomReset') renderer.reset();
    if (target.id === 'overviewCardClose') hideSourceCard();
    if (target.id === 'overviewMapPause') {
      paused = !paused;
      target.setAttribute('aria-pressed', String(paused));
      target.setAttribute('aria-label', t(paused ? 'overview.map.resume' : 'overview.map.pause'));
      target.textContent = paused ? '▶' : 'Ⅱ';
      if (paused) status('paused');
      else status('loading');
      syncActivity();
    }
    if (target.dataset.filter) {
      filter = target.dataset.filter;
      for (const button of panel.querySelectorAll('[data-filter]')) {
        button.setAttribute('aria-pressed', String(button.dataset.filter === filter));
      }
      renderFeed();
    }
    if (target.dataset.row !== undefined) {
      const row = rows[Number(target.dataset.row)];
      if (row) openCard(row);
    }
  }, options);
  const highlight = event => {
    const row = event.target.closest('tr[data-ip]');
    if (row) focusIP(row.dataset.ip);
  };
  panel.addEventListener('pointerover', highlight, options);
  panel.addEventListener('focusin', highlight, options);
  panel.addEventListener('pointerleave', () => focusIP(selectedIP), options);
  panel.addEventListener('keydown', event => { if (event.key === 'Escape') hideSourceCard(); }, options);
  document.addEventListener('visibilitychange', syncActivity, options);
  document.addEventListener('gedefense:language', () => {
    const currentStatus = $('overviewMapStatus').dataset.state;
    renderMetadata(); renderFeed(true);
    if (payload) { try { renderTopCountries(payload); } catch (_) { /* panel is optional */ } }
    status(currentStatus || 'loading');
    if (currentStatus === 'failed') {
      $('overviewMapClean').hidden = true;
      $('overviewMapEmpty').hidden = false;
      text('overviewMapEmpty', t(payload ? 'overview.map.stale' : 'overview.map.failedBody'));
    }
    $('overviewMapPause').setAttribute('aria-label', t(paused ? 'overview.map.resume' : 'overview.map.pause'));
    if (selectedIP) {
      const source = rows.find(row => row.ip === selectedIP);
      if (source) openCard(source, [], false);
    }
  }, options);
  media.addEventListener('change', () => renderer.setMotion(active() && !media.matches && !stale), options);
  if (typeof IntersectionObserver === 'function') {
    observer = new IntersectionObserver(entries => {
      const entry = entries[0];
      const changed = visible !== entry.isIntersecting;
      visible = entry.isIntersecting;
      if (changed) syncActivity();
    });
    observer.observe(panel);
  }
  timer = setInterval(() => { if (active()) void refresh(); else renderer?.setMotion(false); }, REFRESH_MS);
  status('loading');
  syncActivity();
}

export function stopOverviewThreatMap() {
  running = false;
  clearInterval(timer);
  timer = null;
  request?.abort();
  request = null;
  events?.abort();
  observer?.disconnect();
  renderer?.destroy();
  renderer = null;
}

export function clearOverviewThreatMap() {
  if (!renderer) return;
  updateOverviewThreatMap({ sources: [], recent: [], origin: {}, totals: {} });
  hideSourceCard(false);
}
export const destroyOverviewThreatMap = stopOverviewThreatMap;
export const overviewMapLimits = () => LIMITS;

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startOverviewThreatMap, { once: true });
else startOverviewThreatMap();

// Top three countries of the last 24 hours. The server publishes the same roll-up under
// countries_24h, so the browser does not repeat the window and the bucket rules on every refresh;
// the source-based aggregation stays as the fallback for a control plane that predates the field.
// The window is explicit in the label, the unit is explicit on every chip (distinct source IPs, not
// hits), and a source without a parseable timestamp is not counted.
function renderTopCountries(payload) {
  const node = document.getElementById('overviewMapTopCountries');
  if (!node) return;
  const top = topCountries24h(payload).slice(0, 3);
  node.replaceChildren();
  if (!top.length) return;
  const label = document.createElement('span');
  label.className = 'top-countries-label';
  label.textContent = t('overview.map.topCountries');
  node.append(label);
  for (const entry of top) {
    const total = Number(entry.total || 0);
    const blocked = Number(entry.blocked || 0);
    const chip = document.createElement('span');
    chip.className = 'top-country';
    const dot = document.createElement('i');
    dot.className = topCountryState(entry);
    dot.setAttribute('aria-hidden', 'true');
    const name = document.createElement('span');
    name.textContent = `${entry.country || entry.countryCode} (${total} ${total === 1 ? 'IP' : 'IPs'})`;
    chip.append(dot, name);
    chip.title = t('overview.map.topCountriesTooltip', { count: total, blocked });
    chip.setAttribute('aria-label', `${entry.country || entry.countryCode}: ${chip.title}`);
    node.append(chip);
  }
}

function topCountries24h(payload) {
  if (Array.isArray(payload?.countries24h) && payload.countries24h.length) return payload.countries24h;
  return aggregateCountries24h(payload?.sources || []);
}

// Fallback for a backend without countries_24h: the same window and the same unit as the server
// roll-up, so an older control plane renders an honest bar instead of an empty one.
function aggregateCountries24h(sources) {
  const cutoff = Date.now() - 24 * 3600 * 1000;
  const byCountry = new Map();
  for (const source of sources) {
    const seen = Date.parse(source.lastSeen || '');
    if (!Number.isFinite(seen) || seen < cutoff) continue;
    const country = source.country || source.countryCode;
    if (!country) continue;
    const key = source.countryCode || country;
    let entry = byCountry.get(key);
    if (!entry) {
      entry = { country, countryCode: source.countryCode || '', total: 0, blocked: 0, kinetic: 0, l7: 0, xdr: 0, severity: '' };
      byCountry.set(key, entry);
    }
    entry.total += 1;
    if (source.blocked) entry.blocked += 1;
    if (source.area === 'kinetic') entry.kinetic += 1;
    if (source.area === 'l7') entry.l7 += 1;
    if (source.area === 'xdr') entry.xdr += 1;
    if (severityRank(source.severity) > severityRank(entry.severity)) entry.severity = source.severity;
  }
  return [...byCountry.values()].sort((left, right) => right.total - left.total || left.countryCode.localeCompare(right.countryCode));
}

function severityRank(value) {
  switch (String(value || '').toLowerCase()) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}

// The dot keeps the map legend's meaning instead of a rank colour: red only when every source from
// that country is blocked, amber when something was blocked or a high/critical finding is present,
// cyan otherwise.
function topCountryState(entry) {
  const total = Number(entry.total || 0);
  const blocked = Number(entry.blocked || 0);
  const severity = String(entry.severity || '').toLowerCase();
  if (total > 0 && blocked >= total) return 'blocked';
  if (blocked > 0 || severity === 'critical' || severity === 'high') return 'suspicious';
  return 'tracked';
}
