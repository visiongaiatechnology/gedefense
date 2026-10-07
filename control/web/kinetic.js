// GeDefense 4.1 Kinetic Defense live operations view.
'use strict';

import { GEO_MAP_LIMITS, updateKineticGeoMap } from './geo-map.js';

import { getKineticLive, reconcileKinetic } from './api.js';
import { t } from './i18n.js';
import { byID, formatTime, text, toast } from './render.js';

const REFRESH_MS = 1500;
const SOURCE_LIMIT = 200;
const MAP_SOURCE_LIMIT = 96;

let kineticTimer = null;
let kineticLoadInFlight = false;
let kineticReloadPending = false;
let currentWindow = 'live';
let currentStateFilter = 'all';
let latest = null;



export function initKineticModule() {
  const reconcileBtn = byID('kineticReconcileBtn');
  if (reconcileBtn) {
    reconcileBtn.addEventListener('click', async () => {
      reconcileBtn.disabled = true;
      try {
        const res = await reconcileKinetic();
        toast(t('kinetic.reconciled', { count: res.reconciled || 0 }), 'good');
        await loadKineticView(true);
      } catch (err) {
        toast(t('kinetic.reconcileFailed', { error: err?.message || err }), 'danger');
      } finally {
        reconcileBtn.disabled = false;
      }
    });
  }

  document.querySelectorAll('[data-kinetic-window]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-kinetic-window]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentWindow = btn.getAttribute('data-kinetic-window') || 'live';
      text('kineticCurrentWindow', currentWindow.toUpperCase());
      loadKineticView(true).catch(() => {});
    });
  });

  document.querySelectorAll('[data-kinetic-state]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-kinetic-state]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentStateFilter = btn.getAttribute('data-kinetic-state') || 'all';
      loadKineticView(true).catch(() => {});
    });
  });

  const drawerCloseBtn = byID('kineticDrawerClose');
  if (drawerCloseBtn) {
    drawerCloseBtn.addEventListener('click', () => {
      const drawer = byID('kineticDetailDrawer');
      if (drawer) drawer.hidden = true;
    });
  }

  if (kineticTimer) clearInterval(kineticTimer);
  kineticTimer = setInterval(() => {
    if (!document.hidden && isKineticVisible()) loadKineticView(false).catch(() => {});
  }, REFRESH_MS);
}

export async function loadKineticView(force = false) {
  if (kineticLoadInFlight) {
    if (force) kineticReloadPending = true;
    return;
  }
  kineticLoadInFlight = true;
  try {
    latest = await getKineticLive(currentWindow, SOURCE_LIMIT, currentStateFilter);
    currentWindow = String(latest?.window || currentWindow || 'live').toLowerCase();
    currentStateFilter = String(latest?.state_filter || currentStateFilter || 'all').toLowerCase();
    text('kineticCurrentWindow', currentWindow.toUpperCase());
    renderCurrentData();
  } catch (err) {
    renderTransportFailure(err);
  } finally {
    kineticLoadInFlight = false;
    if (kineticReloadPending) {
      kineticReloadPending = false;
      queueMicrotask(() => loadKineticView(false).catch(() => {}));
    }
  }
}

// Which hook the kernel actually attached, and what the path has done with it.
//
// The mode is read from the core's own INGRESS_HEALTH response, not from configuration:
// what was configured and what the driver accepted are different facts, and only the
// second one describes this host. The counters come from the same telemetry the engine
// already keeps; none of them are recomputed here.
function renderEnforcement(status) {
  const mode = String(status?.ingress_mode || '');
  const badge = byID('kineticIngressMode');
  if (badge) {
    if (!mode) {
      badge.textContent = t('kinetic.enforcement.modeUnknown');
      badge.className = 'status-pill warn';
    } else if (mode === 'NATIVE_XDP') {
      badge.textContent = t('kinetic.enforcement.modeNative');
      badge.className = 'status-pill good';
    } else if (mode === 'GENERIC_XDP') {
      badge.textContent = t('kinetic.enforcement.modeGeneric');
      badge.className = 'status-pill warn';
    } else if (mode === 'TC_INGRESS') {
      badge.textContent = t('kinetic.enforcement.modeTc');
      badge.className = 'status-pill warn';
    } else {
      badge.textContent = mode;
      badge.className = 'status-pill muted';
    }
  }

  // The note states what the mode means for this host. A native hook drops before the
  // kernel allocates a socket buffer; the fallbacks drop later, which is a real
  // difference under load and not a detail worth hiding behind a green pill.
  const note = byID('kineticIngressNote');
  if (note) {
    note.textContent = !mode
      ? t('kinetic.enforcement.noteUnknown')
      : mode === 'NATIVE_XDP'
        ? t('kinetic.enforcement.noteNative')
        : mode === 'GENERIC_XDP'
          ? t('kinetic.enforcement.noteGeneric')
          : mode === 'TC_INGRESS'
            ? t('kinetic.enforcement.noteTc')
            : t('kinetic.enforcement.noteOther');
  }

  const number = value => formatNumber(Number(value || 0));
  const fill = (hostID, rows) => {
    const host = byID(hostID);
    if (!host) return;
    host.replaceChildren(...rows.map(([label, value, tone]) => {
      const row = document.createElement('div');
      row.className = 'kinetic-enforcement-fact';
      const term = document.createElement('dt');
      term.textContent = label;
      const detail = document.createElement('dd');
      detail.textContent = value;
      if (tone) detail.setAttribute('data-tone', tone);
      row.append(term, detail);
      return row;
    }));
  };

  // Kernel path: is the channel keeping up, and is it losing anything.
  const ringDrops = Number(status?.kernel_ring_drops || 0);
  const trackFailures = Number(status?.kernel_track_insert_failures || 0);
  const trackingDrops = Number(status?.tracking_drops_total || 0);
  fill('kineticKernelFacts', [
    [t('kinetic.enforcement.fact.events'), number(status?.kernel_events_emitted), ''],
    [t('kinetic.enforcement.fact.ringDrops'), number(ringDrops), ringDrops > 0 ? 'warn' : 'good'],
    [t('kinetic.enforcement.fact.trackFailures'), number(trackFailures), trackFailures > 0 ? 'warn' : 'good'],
    [t('kinetic.enforcement.fact.trackingCapacity'), number(status?.active_tracking_ips) + ' / ' + number(status?.tracking_capacity), '']
  ]);

  // Detection: what the engine recognised, by kind, so a busy host is legible.
  fill('kineticDetectionFacts', [
    [t('kinetic.enforcement.fact.hits'), number(status?.hits_total), ''],
    [t('kinetic.enforcement.fact.velocity'), number(status?.velocity_bursts_total), ''],
    [t('kinetic.enforcement.fact.portscans'), number(status?.portscans_total), ''],
    [t('kinetic.enforcement.fact.subnet'), number(status?.subnet_strikes_total), ''],
    [t('kinetic.enforcement.fact.l7'), number(status?.l7_strikes_total), '']
  ]);

  // Response: what was actually done, and what was refused. A suppression is not a
  // failure and a failure is not a suppression, so they are listed apart.
  const failed = Number(status?.response_failed_total || 0);
  fill('kineticResponseFacts', [
    [t('kinetic.enforcement.fact.bansEnforced'), number(status?.bans_enforced_total), ''],
    [t('kinetic.enforcement.fact.bansExpired'), number(status?.bans_expired_total), ''],
    [t('kinetic.enforcement.fact.applied'), number(status?.response_applied_total), 'good'],
    [t('kinetic.enforcement.fact.suppressed'), number(status?.response_suppressed_total), ''],
    [t('kinetic.enforcement.fact.failed'), number(failed), failed > 0 ? 'bad' : 'good'],
    [t('kinetic.enforcement.fact.trackingDrops'), number(trackingDrops), trackingDrops > 0 ? 'warn' : 'good']
  ]);
}

function renderCurrentData() {
  const live = latest || {};
  const status = live.status || {};
  const sources = Array.isArray(live.sources) ? live.sources : [];
  const events = Array.isArray(live.events) ? live.events : [];
  renderKineticKPIs(live, sources, events);
  renderCoverage(status);
  renderEnforcement(status);
  renderHistoryTruth(live);
  renderGeoStatus(live.geo);
  renderKineticMap(live, sources);
  renderTopCountries(Array.isArray(live.countries) ? live.countries : []);
  renderTopPorts(Array.isArray(live.top_ports) ? live.top_ports : []);
  renderTopRules(Array.isArray(live.top_rules) ? live.top_rules : []);
  renderSensorMatrix(status);
  renderSources(sources);
  renderKineticFeed(events);
}

function renderKineticKPIs(live, sources, events) {
  const status = live?.status || {};
  const traffic = live?.traffic || {};
  text('kineticHitsTotal', formatNumber(traffic.hits));
  text('kineticAttemptsWindow', formatNumber(traffic.attempts));
  text('kineticActiveTrackingIPs', formatNumber(status.active_tracking_ips ?? sources.length));
  text('kineticPortscans', formatNumber(events.filter(e => ['NET.INGRESS.PORT_SCAN', 'NET.INGRESS.LOW_SLOW_SCAN'].includes(String(e.rule_id))).length));
  text('kineticVelocityBursts', formatNumber(events.filter(e => ['NET.INGRESS.IP_VELOCITY', 'NET.INGRESS.SYN_FLOOD'].includes(String(e.rule_id))).length));
  text('kineticSubnetStrikes', formatNumber(events.filter(e => ['NET.INGRESS.SUBNET_V4', 'NET.INGRESS.SUBNET_V6', 'NET.INGRESS.WIDE_V4'].includes(String(e.rule_id))).length));
  const drops = Number(status.tracking_drops_total || 0);
  const activeBlocks = Number(live.active_blocks ?? sources.filter(s => s.blocked).length);
  text('kineticTrackingDrops', formatNumber(status.tracking_drops_total));
  text('kineticTrackingCapacity', formatNumber(status.tracking_capacity || 0));
  text('kineticActiveBlocks', formatNumber(activeBlocks));
  // Functional colour is earned by the value, not assigned to the label. A zero
  // in red is an alarm that never fires, and colour that is always on carries no
  // information at all.
  toneWhenActive('kineticActiveBlocks', activeBlocks > 0 ? 'attention' : '');
  toneWhenActive('kineticTrackingDrops', drops > 0 ? 'critical' : '');
  text('kineticTrackerPressure', `Drops ${formatNumber(status.tracking_drops_total)} · Source Evictions ${formatNumber(status.tracking_evictions_total)} · Aggregate Evictions ${formatNumber(status.aggregate_evictions_total)}`);

  const ingress = status.layers?.ingress_network || status.layers?.['ingress_network'];
  text('kineticEnforcementMode', String(ingress?.enforcement_mode || 'observe').toUpperCase());
}

// toneWhenActive sets or clears a functional tone class on a telemetry value.
function toneWhenActive(id, tone) {
  const node = document.getElementById(id);
  if (!node) return;
  node.classList.remove('tone-attention', 'tone-critical');
  if (tone) node.classList.add(`tone-${tone}`);
}

function renderHistoryTruth(live) {
  const bounds = live?.bounds || {};
  const traffic = live?.traffic || {};
  const eventComplete = Boolean(bounds.event_history_complete);
  const sourceComplete = Boolean(bounds.source_history_complete);
  const aggregationComplete = bounds.aggregation_history_complete !== false;
  const trafficComplete = Boolean(traffic.history_complete);
  const fullyComplete = eventComplete && sourceComplete && aggregationComplete && trafficComplete;
  const badge = byID('kineticHistoryBadge');
  if (badge) {
    badge.className = `status-pill ${fullyComplete ? 'good' : 'warning'}`;
    badge.textContent = fullyComplete ? 'HISTORY COMPLETE' : 'HISTORY BOUNDED';
    badge.title = fullyComplete
      ? 'Das gewählte Fenster liegt vollständig innerhalb der verfügbaren bounded Historie.'
      : 'Mindestens ein Datenstrom ist im gewählten Fenster absichtlich bounded oder noch nicht vollständig warm.';
  }
  text('kineticWindowTruth', `SERVER WINDOW // ${String(live?.window || currentWindow).toUpperCase()} · ${traffic.bucket_resolution || 'n/a'}`);
  const notes = [];
  if (!trafficComplete) notes.push(`Traffic-Warmup ${formatNumber(traffic.runtime_seconds)}s`);
  if (!sourceComplete) notes.push(`Source-Retention ${formatNumber(bounds.source_retention_seconds)}s`);
  if (!eventComplete) notes.push(`Event-Ring Drops ${formatNumber(bounds.event_drops_total)}`);
  if (!aggregationComplete) notes.push(`Aggregate Evictions ${formatNumber(bounds.aggregate_evictions_total)}`);
  if (!notes.length) notes.push('Traffic, Source-State und Event-Historie im gewählten Fenster vollständig.');
  text('kineticHistoryNote', notes.join(' · '));
}

function renderCoverage(data) {
  const badge = byID('kineticCoverageBadge');
  const dot = byID('kineticSensorDot');
  const summary = byID('kineticSensorSummary');
  const reason = byID('kineticSensorReason');
  const coverage = data?.coverage || {};
  const st = String(coverage.overall_status || 'offline').toLowerCase();
  const klass = statusClass(st);

  if (badge) {
    badge.className = `status-pill ${klass}`;
    badge.textContent = st.toUpperCase();
    badge.title = coverage.summary || '';
  }
  if (dot) dot.className = `status-dot ${statusDotClass(st)}`;
  if (summary) summary.textContent = coverage.summary || `Ingress Coverage ${st.toUpperCase()}`;

  const sensor = coverage.sensors?.xdp_ingress || data?.coverage?.sensors?.['xdp_ingress'];
  if (reason) reason.textContent = sensor?.coverage_reason || sensor?.last_error || 'Keine verifizierte Sensorbegründung verfügbar.';
}

function renderGeoStatus(geo) {
  const badge = byID('kineticGeoBadge');
  const loaded = Boolean(geo?.loaded);
  if (badge) {
    badge.className = `status-pill ${loaded ? 'good' : 'warning'}`;
    badge.textContent = loaded ? 'GEO ONLINE' : 'GEO OFFLINE';
    badge.title = loaded
      ? `${formatNumber(geo.entries)} lokale GeoIP/ASN-Einträge · Cache ${formatNumber(geo.cache_entries)}/${formatNumber(geo.cache_capacity)} · Quelle ${geo?.source_modified_at ? formatAge(geo.source_modified_at) : 'Alter unbekannt'}`
      : (geo?.last_error || 'Lokale GeoIP-Datenbank nicht geladen');
  }
  const modified = geo?.source_modified_at ? formatAge(geo.source_modified_at) : 'Alter unbekannt';
  text('kineticGeoEntries', `${formatNumber(geo?.entries || 0)} Einträge · ${modified}`);
}

// renderKineticMap drives the vendored SVG map. The hand-drawn equirectangular SVG
// it replaces could only plot a bubble per source; the vendored map carries real
// country geometry, so the same snapshot now produces a choropleth by event rate
// plus two separately bounded marker layers.
//
// This function owns no rendering state: bounds, marker classes and the pulse are
// enforced inside the adapter, which is also what the dashboard reports, so the
// displayed number and the enforced number can never disagree.
function renderKineticMap(mapData, sources) {
  const empty = byID('kineticMapEmpty');
  const geoLoaded = Boolean(mapData?.geo?.loaded);
  const mappable = sources.filter(hasCoordinates);

  text('kineticGeoMappable', `${formatNumber(mappable.length)} Quellen`);

  const placed = updateKineticGeoMap({
    countries: Array.isArray(mapData?.countries) ? mapData.countries : [],
    sources: mappable,
    origin: mapData?.origin,
    origin_note: mapData?.origin_note
  });

  if (empty) {
    empty.hidden = geoLoaded && mappable.length > 0;
    const title = empty.querySelector('strong');
    const detail = empty.querySelector('span');
    if (!geoLoaded) {
      if (title) title.textContent = 'Lokale GeoIP/ASN-Datenbank nicht verfügbar';
      if (detail) detail.textContent = mapData?.geo?.last_error || 'Live-Quellen werden erfasst, geografische Einordnung ist derzeit jedoch nicht verifiziert.';
    } else if (!mappable.length) {
      if (title) title.textContent = 'Keine kartierbaren Quellen im gewählten Fenster';
      if (detail) detail.textContent = 'Die Geo-Datenbank ist geladen. Im aktuellen Server-Fenster liegen jedoch keine öffentlichen Quellen mit lokalem Geo-Match vor.';
    }
  }

  // The layer note states the enforced bound rather than a decorative total, so the
  // operator can see when the map is showing less than the feed reported.
  const limits = GEO_MAP_LIMITS;
  const note = byID('kineticGeoLayerNote');
  if (note) {
    const shown = placed ? placed.tracked + placed.blocked : 0;
    const bounds = `Grenzen ${limits.tracked} Tracking / ${limits.blocked} Blockiert`;
    const counts = mappable.length > shown
      ? `${formatNumber(shown)} von ${formatNumber(mappable.length)} Quellen kartiert`
      : `${formatNumber(shown)} Quellen kartiert`;
    // The origin state is part of the note, so an unresolved host position is stated
    // rather than silently leaving the arcs out.
    const originPart = placed && placed.originKnown && placed.originNote ? ` · ${placed.originNote}` : '';
    note.textContent = `${counts} · ${bounds}${originPart}`;
  }

  const countries = Array.isArray(mapData?.countries) ? mapData.countries : [];
  text('kineticHotCountry', countries[0] ? `${countries[0].code} · ${formatNumber(countries[0].hits)} Hits` : '---');
}

function renderTopCountries(countries) {
  const host = byID('kineticTopCountries');
  if (!host) return;
  host.replaceChildren();
  const list = countries || [];
  text('kineticCountryCount', `${list.length} ${list.length === 1 ? 'COUNTRY' : 'COUNTRIES'}`);
  if (!list.length) {
    host.appendChild(emptyRank('Keine geografisch zuordenbaren Quellen im Server-Fenster.'));
    return;
  }
  const max = Math.max(1, ...list.map(c => Number(c.hits || 0)));
  list.slice(0, 7).forEach((country, index) => {
    host.appendChild(rankRow(
      `${index + 1}`,
      `${country.code || '??'} · ${country.name || 'Unknown'}`,
      `${formatNumber(country.hits)} Hits · ${formatNumber(country.blocked)} blocked`,
      Math.max(4, Math.round((Number(country.hits || 0) / max) * 100))
    ));
  });
}

function renderTopPorts(topPorts) {
  const host = byID('kineticTopPorts');
  if (!host) return;
  host.replaceChildren();
  const sorted = topPorts || [];
  text('kineticHotPort', sorted[0] ? `${sorted[0].port}/tcp` : '---');
  if (!sorted.length) {
    host.appendChild(emptyRank('Noch keine attack-relevanten Zielports im Server-Fenster.'));
    return;
  }
  const max = Math.max(1, Number(sorted[0]?.count || 1));
  sorted.slice(0, 7).forEach((row, index) => {
    host.appendChild(rankRow(`${index + 1}`, `${row.port}/tcp`, `${serviceName(row.port)} · ${formatNumber(row.count)} Events`, Math.max(4, Math.round((Number(row.count || 0) / max) * 100))));
  });
}

function renderTopRules(topRules) {
  const host = byID('kineticTopRules');
  if (!host) return;
  host.replaceChildren();
  const rows = topRules || [];
  if (!rows.length) {
    host.appendChild(emptyRank('Keine Detection-Regeln im gewählten Server-Fenster ausgelöst.'));
    return;
  }
  const max = Math.max(1, Number(rows[0]?.count || 1));
  rows.slice(0, 7).forEach((row, index) => {
    host.appendChild(rankRow(`${index + 1}`, row.rule_id || 'UNKNOWN', `${formatNumber(row.count)} Events`, Math.max(4, Math.round((Number(row.count || 0) / max) * 100))));
  });
}

function renderSensorMatrix(status) {
  const host = byID('kineticSensorMatrix');
  if (!host) return;
  host.replaceChildren();
  const sensors = status?.coverage?.sensors || {};
  const entries = Object.entries(sensors);
  if (!entries.length) {
    host.appendChild(emptyRank('Keine Sensor-Coverage gemeldet.'));
    return;
  }
  entries.forEach(([key, sensor]) => {
    const row = document.createElement('div');
    row.className = 'kinetic-sensor-row';
    const name = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = String(sensor?.name || key);
    const detail = document.createElement('span');
    detail.textContent = String(sensor?.coverage_reason || sensor?.self_test || '---');
    name.append(strong, detail);
    const pill = document.createElement('span');
    const st = String(sensor?.status || 'offline').toLowerCase();
    pill.className = `status-pill ${statusClass(st)}`;
    pill.textContent = st.toUpperCase();
    row.append(name, pill);
    host.appendChild(row);
  });
}

function renderSources(sources) {
  const tbody = byID('kineticSourcesTableBody');
  if (!tbody) return;
  tbody.replaceChildren();
  if (!sources.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 10;
    cell.className = 'empty-row';
    cell.textContent = 'Keine aktiven Ingress-Quellen im gewählten Live-Fenster.';
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  sources.slice(0, SOURCE_LIMIT).forEach(src => {
    const row = document.createElement('tr');
    row.className = 'kinetic-source-row';
    row.tabIndex = 0;
    row.addEventListener('click', () => openSourceInspector(src));
    row.addEventListener('keydown', evt => {
      if (evt.key === 'Enter' || evt.key === ' ') openSourceInspector(src);
    });
    const ports = (src.ports || []).slice(0, 6).join(', ') || '---';
    const geo = [src.country_code, src.asn].filter(Boolean).join(' · ') || 'Unknown';
    const last = formatTime(src.last_seen);

    const stateCell = document.createElement('td');
    const statePill = document.createElement('span');
    statePill.className = `status-pill ${sourcePillClass(src)}`;
    statePill.textContent = String(src.state || 'TRACKING');
    stateCell.appendChild(statePill);

    const ipCell = document.createElement('td');
    const ipStrong = document.createElement('strong');
    ipStrong.className = 'font-mono text-cyan';
    ipStrong.textContent = String(src.source_ip || '---');
    const ipMeta = document.createElement('small');
    ipMeta.className = 'kinetic-ip-meta';
    ipMeta.textContent = `IPv${Number(src.family) === 6 ? '6' : '4'} · ${formatNumber(src.window_hits ?? src.hits)} window hits`;
    ipCell.append(ipStrong, ipMeta);

    const geoCell = document.createElement('td');
    const geoMain = document.createElement('span');
    geoMain.className = 'kinetic-geo-cell';
    geoMain.textContent = geo;
    const geoSub = document.createElement('small');
    geoSub.textContent = String(src.as_name || src.country || '');
    geoCell.append(geoMain, geoSub);

    const rateCell = tableTextCell(`${formatNumber(src.rate_per_sec)}/s`, 'font-mono');
    const synCell = tableTextCell(formatNumber(src.window_syns ?? src.syns), 'font-mono');
    const portsCell = tableTextCell(ports, 'font-mono fs-xs');
    const subnetCell = tableTextCell(String(src.subnet || '---'), 'font-mono fs-xs');

    const scoreCell = document.createElement('td');
    const scoreStrong = document.createElement('strong');
    const score = Number(src.score || 0);
    scoreStrong.className = `font-mono ${score >= 90 ? 'text-danger' : score >= 60 ? 'text-warning' : ''}`;
    scoreStrong.textContent = formatNumber(score);
    scoreCell.appendChild(scoreStrong);

    const lastCell = tableTextCell(last, 'font-mono fs-xs');
    const ruleCell = tableTextCell(String(src.last_rule || 'tracking'), 'fs-xs');
    row.append(stateCell, ipCell, geoCell, rateCell, synCell, portsCell, subnetCell, scoreCell, lastCell, ruleCell);
    tbody.appendChild(row);
  });
}

function renderKineticFeed(events) {
  const tbody = byID('kineticEventsTableBody');
  if (!tbody) return;
  tbody.replaceChildren();
  text('kineticEventCountBadge', `${events.length} ${events.length === 1 ? 'EVENT' : 'EVENTS'}`);

  if (!events.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'empty-row';
    td.textContent = t('kinetic.noEvents');
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  const sorted = [...events].sort((a, b) => dateValue(b.time) - dateValue(a.time)).slice(0, 80);
  sorted.forEach(evt => {
    const tr = document.createElement('tr');
    tr.className = 'kinetic-event-row';
    tr.tabIndex = 0;
    tr.addEventListener('click', () => openKineticInspector(evt));
    tr.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') openKineticInspector(evt);
    });

    const sevClass = severityClass(evt.severity);
    const actClass = actionClass(evt.action);
    const timeCell = tableTextCell(formatTime(evt.time), 'font-mono fs-xs');

    const ruleCell = document.createElement('td');
    const rulePill = document.createElement('span');
    rulePill.className = `status-pill ${sevClass}`;
    rulePill.textContent = String(evt.rule_id || 'NET.INGRESS');
    ruleCell.appendChild(rulePill);

    const sourceCell = document.createElement('td');
    const sourceStrong = document.createElement('strong');
    sourceStrong.className = 'font-mono text-cyan';
    sourceStrong.textContent = String(evt.source_ip || '---');
    sourceCell.appendChild(sourceStrong);

    const proto = String(evt.protocol || '---');
    const portText = Number(evt.port) > 0 ? `${Number(evt.port)} (${proto})` : proto;
    const portCell = tableTextCell(portText, 'fs-xs');
    const hitsCell = tableTextCell(`${formatNumber(evt.hits || 1)} (${formatRate(evt.rate_per_sec)})`, 'font-mono fs-xs');

    const actionCell = document.createElement('td');
    const actionPill = document.createElement('span');
    actionPill.className = `status-pill ${actClass}`;
    actionPill.textContent = String(evt.action || 'track').toUpperCase();
    actionCell.appendChild(actionPill);

    const decisionCell = tableTextCell(truncate(String(evt.decision || ''), 56), 'fs-xs text-muted');
    decisionCell.title = String(evt.decision || '');
    tr.append(timeCell, ruleCell, sourceCell, portCell, hitsCell, actionCell, decisionCell);
    tbody.appendChild(tr);
  });
}

function openKineticInspector(evt) {
  const drawer = byID('kineticDetailDrawer');
  if (!drawer) return;
  drawer.hidden = false;
  setInspectorState(evt.action === 'block' ? 'BLOCKED' : String(evt.severity || 'TRACKING').toUpperCase(), actionClass(evt.action));
  text('drawerTargetIP', evt.source_ip || '---');
  text('drawerGeo', 'Event / Evidence');
  text('drawerRuleID', evt.rule_id || '---');
  text('drawerSeverity', String(evt.severity || '---').toUpperCase());
  text('drawerScore', `${Number(evt.score || 0)} pts`);
  text('kineticDrawerAction', String(evt.action || 'track').toUpperCase());
  text('drawerTime', formatTime(evt.time));
  text('drawerPortProtocol', evt.port > 0 ? `${evt.port} / ${evt.protocol || '---'}` : (evt.protocol || '---'));
  text('drawerSubnet', evt.subnet || '---');
  text('drawerHitsRate', `${formatNumber(evt.hits || 1)} / ${formatRate(evt.rate_per_sec)}`);
  text('kineticDrawerDecision', evt.decision || '---');
  text('drawerFingerprint', evt.fingerprint || evt.evidence_id || '---');
  drawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function openSourceInspector(src) {
  const drawer = byID('kineticDetailDrawer');
  if (!drawer) return;
  drawer.hidden = false;
  setInspectorState(src.state || 'TRACKING', sourcePillClass(src));
  text('drawerTargetIP', src.source_ip || '---');
  text('drawerGeo', [src.country || src.country_code, src.asn, src.as_name].filter(Boolean).join(' · ') || 'Geo/ASN unbekannt');
  text('drawerRuleID', src.last_rule || 'tracking');
  text('drawerSeverity', sourceSeverity(src));
  text('drawerScore', `${Number(src.score || 0)} pts`);
  text('kineticDrawerAction', src.blocked ? 'BLOCKED' : 'OBSERVE');
  text('drawerTime', `${formatTime(src.first_seen)} → ${formatTime(src.last_seen)}`);
  text('drawerPortProtocol', `${(src.ports || []).join(', ') || '---'} / ${src.service || 'mixed'}`);
  text('drawerSubnet', src.subnet || '---');
  text('drawerHitsRate', `${formatNumber(src.window_hits ?? src.hits)} hits · ${formatNumber(src.window_attempts ?? src.attempts)} attempts · ${formatNumber(src.rate_per_sec)}/s · SYN ${formatNumber(src.window_syns ?? src.syns)}`);
  text('kineticDrawerDecision', src.last_rule ? `Letzter Trigger: ${src.last_rule}` : 'Quelle wird beobachtet; noch keine Regel ausgelöst.');
  text('drawerFingerprint', src.blocked ? 'Aktiver Containment-State' : 'Live-Tracking-State');
  drawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setInspectorState(label, klass) {
  const pill = byID('drawerState');
  if (!pill) return;
  pill.className = `status-pill ${klass || 'muted'}`;
  pill.textContent = String(label || 'TRACKING').toUpperCase();
}


function tableTextCell(value, className = '') {
  const td = document.createElement('td');
  td.className = className;
  td.textContent = String(value ?? '');
  return td;
}

function rankRow(rank, title, meta, width) {
  const row = document.createElement('div');
  row.className = 'kinetic-rank-row';
  const rankEl = document.createElement('span');
  rankEl.className = 'kinetic-rank-number font-mono';
  rankEl.textContent = rank;
  const body = document.createElement('div');
  body.className = 'kinetic-rank-body';
  const head = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = title;
  const small = document.createElement('span');
  small.textContent = meta;
  head.append(strong, small);
  const meter = document.createElement('div');
  meter.className = 'kinetic-rank-meter';
  const fill = document.createElement('i');
  fill.style.width = `${Math.max(0, Math.min(100, width))}%`;
  meter.appendChild(fill);
  body.append(head, meter);
  row.append(rankEl, body);
  return row;
}

function emptyRank(label) {
  const el = document.createElement('div');
  el.className = 'empty-state compact';
  el.textContent = label;
  return el;
}


function hasCoordinates(source) {
  return Number.isFinite(Number(source?.latitude)) && Number.isFinite(Number(source?.longitude));
}

function sourcePillClass(src) {
  if (src?.blocked || String(src?.state).toUpperCase() === 'BLOCKED') return 'danger';
  const state = String(src?.state || '').toUpperCase();
  if (['THREAT', 'SCAN', 'BURST'].includes(state) || Number(src?.score || 0) >= 80) return 'danger';
  if (state === 'SUSPICIOUS' || Number(src?.score || 0) >= 40) return 'warning';
  if (state === 'TRACKING') return 'active';
  return 'muted';
}


function sourceSeverity(src) {
  const score = Number(src?.score || 0);
  if (src?.blocked || score >= 90) return 'CRITICAL';
  if (score >= 70) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'INFO';
}

function severityClass(severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical' || value === 'high') return 'danger';
  if (value === 'medium') return 'warning';
  if (value === 'low') return 'good';
  return 'muted';
}

function actionClass(action) {
  const value = String(action || '').toLowerCase();
  if (value === 'block' || value === 'drop') return 'danger';
  if (value === 'contain' || value === 'warn') return 'warning';
  if (value === 'track') return 'active';
  return 'muted';
}

function statusClass(status) {
  if (status === 'online') return 'good';
  if (status === 'degraded') return 'warning';
  if (status === 'offline') return 'danger';
  if (status === 'disabled' || status === 'not_applicable') return 'muted';
  return 'muted';
}

function statusDotClass(status) {
  if (status === 'online') return 'online';
  if (status === 'degraded') return 'warning';
  if (status === 'offline') return 'offline';
  return 'warning';
}

function serviceName(port) {
  const known = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 2222: 'SSH-alt', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-alt', 8443: 'HTTPS-alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
  };
  return known[Number(port)] || 'Unknown / custom service';
}

function renderTransportFailure(err) {
  const badge = byID('kineticCoverageBadge');
  if (badge) {
    badge.className = 'status-pill danger';
    badge.textContent = 'API OFFLINE';
    badge.title = String(err?.message || err || 'Kinetic API unavailable');
  }
  const history = byID('kineticHistoryBadge');
  if (history) {
    history.className = 'status-pill danger';
    history.textContent = 'HISTORY UNKNOWN';
  }
  text('kineticSensorSummary', 'Kinetic API nicht erreichbar');
  text('kineticSensorReason', String(err?.message || err || 'Keine Antwort vom Control Plane API.'));
  text('kineticHistoryNote', 'Keine verifizierte Live-Antwort vom Control Plane API.');
}

function isKineticVisible() {
  const section = document.querySelector('[data-page="kinetic"]');
  return Boolean(section && !section.hidden);
}

function dateValue(value) {
  const parsed = value ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatNumber(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) ? n.toLocaleString() : '0';
}

function formatRate(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) && n > 0 ? `${n.toFixed(1)}/s` : '---';
}

function formatAge(value) {
  const ts = dateValue(value);
  if (!ts) return 'Alter unbekannt';
  const seconds = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (seconds < 60) return `${seconds}s alt`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m alt`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h alt`;
  return `${Math.floor(seconds / 86400)}d alt`;
}

function truncate(str, len) {
  const value = String(str || '');
  return value.length > len ? `${value.substring(0, len)}…` : value;
}

function escapeHTML(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}
