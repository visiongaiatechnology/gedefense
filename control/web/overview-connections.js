// STATUS: DIAMANT VGT SUPREME
'use strict';

// Full-width real-time Websites/Apps -> Remote Peers GeoIP connections panel (10/page).
import { api } from './api.js';
import { locale, t } from './i18n.js';
import { formatBytes } from './render.js';

const POLL_MS = 6000;
const state = {
  page: 1,
  pageSize: 10,
  filter: 'all',
  query: '',
  timer: null,
  controller: null,
  bound: false,
  debounce: null
};

const byId = id => document.getElementById(id);

function isOverviewActive() {
  const page = document.querySelector('[data-page="overview"]');
  return Boolean(page && !page.hidden && page.classList.contains('active') && !document.hidden);
}

function makeEl(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== '' && text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

function setText(id, value) {
  const node = byId(id);
  if (node) node.textContent = String(value ?? '—');
}

function verdictTone(verdict) {
  switch (String(verdict || '').toLowerCase()) {
    case 'blocked':
    case 'storm':
      return 'danger';
    case 'throttled':
    case 'flagged':
      return 'warn';
    default:
      return 'good';
  }
}

function renderSummary(data) {
  const sum = data.summary || {};
  const loc = locale();
  setText('overviewConnTotal', Number(sum.total || 0).toLocaleString(loc));
  setText('overviewConnWeb', Number(sum.web || 0).toLocaleString(loc));
  setText('overviewConnApps', Number(sum.apps || 0).toLocaleString(loc));
  setText('overviewConnExternal', Number(sum.external || 0).toLocaleString(loc));
  setText('overviewConnBlocked', Number(sum.blocked || 0).toLocaleString(loc));
  setText('overviewConnCountries', Number(sum.countries || 0).toLocaleString(loc));
  const geoBadge = byId('overviewConnGeoBadge');
  if (geoBadge) {
    geoBadge.textContent = data.geo_loaded ? t('overview.conn.geoLocal') : t('overview.conn.geoMissing');
    geoBadge.className = `status-pill ${data.geo_loaded ? 'good' : 'muted'}`;
  }
}

function renderRows(data) {
  const body = byId('overviewConnRows');
  if (!body) return;
  const items = Array.isArray(data.items) ? data.items : [];
  body.replaceChildren();
  if (!items.length) {
    const tr = document.createElement('tr');
    const td = makeEl('td', 'v61-empty', t('overview.conn.empty'));
    td.colSpan = 6;
    tr.append(td);
    body.append(tr);
    return;
  }

  for (const item of items) {
    const tr = document.createElement('tr');

    // 1. Website / Application
    const tdApp = document.createElement('td');
    const appWrap = makeEl('div', 'overview-conn-app');
    const title = item.host ? `${item.app} · ${item.host}` : item.app;
    appWrap.append(makeEl('strong', '', title || 'system'));
    const subParts = [
      item.service_type === 'web' ? 'WEB' : 'APP',
      item.local_port ? `:${item.local_port}` : '',
      item.pid ? `PID ${item.pid}` : '',
      item.user ? item.user : ''
    ].filter(Boolean);
    appWrap.append(makeEl('small', '', subParts.join(' · ')));
    tdApp.append(appWrap);

    // 2. Direction & Protocol
    const tdProto = document.createElement('td');
    const dirLabel = item.direction === 'inbound' ? t('overview.conn.dirIn') : t('overview.conn.dirOut');
    tdProto.append(makeEl('span', `status-pill ${item.direction === 'inbound' ? 'muted' : 'warn'}`, dirLabel));
    const protoSub = [item.protocol, item.alpn ? `ALPN ${item.alpn}` : ''].filter(Boolean).join(' · ');
    if (protoSub) tdProto.append(makeEl('div', 'fs-xs text-muted mt-xs v61-mono', protoSub));

    // 3. Remote IP & Port
    const tdPeer = document.createElement('td');
    const peerAddr = item.remote_port ? `${item.remote_ip}:${item.remote_port}` : item.remote_ip;
    tdPeer.append(makeEl('code', 'v61-mono', peerAddr || '—'));

    // 4. GeoIP
    const tdGeo = document.createElement('td');
    const geoWrap = makeEl('div', 'overview-conn-app');
    const geoRow = makeEl('div', 'overview-conn-geo');
    geoRow.append(
      makeEl('span', 'overview-conn-cc', item.country_code || '—'),
      makeEl('span', '', item.country || t('overview.map.unknown'))
    );
    geoWrap.append(geoRow);
    const asnText = [item.asn, item.as_name].filter(Boolean).join(' · ');
    if (asnText) geoWrap.append(makeEl('small', '', asnText));
    tdGeo.append(geoWrap);

    // 5. Volume
    const tdVol = document.createElement('td');
    const rx = Number(item.rx_bytes || 0);
    const tx = Number(item.tx_bytes || 0);
    if (rx > 0 || tx > 0) {
      const volWrap = makeEl('div', 'overview-conn-app');
      volWrap.append(
        makeEl('strong', 'v61-mono', `RX ${formatBytes(rx)} / TX ${formatBytes(tx)}`),
        makeEl('small', '', item.packets ? `${Number(item.packets).toLocaleString(locale())} pkts` : (item.source || 'kernel'))
      );
      tdVol.append(volWrap);
    } else {
      tdVol.append(makeEl('span', 'text-muted fs-xs v61-mono', item.state || 'ACTIVE'));
    }

    // 6. Status & Verdict
    const tdStatus = document.createElement('td');
    tdStatus.append(makeEl('span', `status-pill ${verdictTone(item.verdict)}`, String(item.verdict || 'active').toUpperCase()));
    if (item.state && (rx > 0 || tx > 0)) {
      tdStatus.append(makeEl('div', 'fs-xs text-muted mt-xs v61-mono', item.state));
    }

    tr.append(tdApp, tdProto, tdPeer, tdGeo, tdVol, tdStatus);
    body.append(tr);
  }
}

function renderPagination(data) {
  const page = Number(data.page || 1);
  const totalPages = Math.max(1, Number(data.total_pages || 1));
  const total = Number(data.total || 0);
  state.page = page;
  const start = total === 0 ? 0 : (page - 1) * Number(data.page_size || 10) + 1;
  const end = Math.min(total, start + (Array.isArray(data.items) ? data.items.length : 0) - 1);
  setText('overviewConnPageInfo', t('overview.conn.pageInfo', {
    start,
    end: Math.max(0, end),
    total: total.toLocaleString(locale()),
    page,
    pages: totalPages
  }));
  const prev = byId('overviewConnPrev');
  const next = byId('overviewConnNext');
  if (prev) prev.disabled = page <= 1;
  if (next) next.disabled = page >= totalPages;
}

export async function refreshOverviewConnections() {
  if (!byId('overviewConnRows')) return;
  if (state.controller) state.controller.abort();
  state.controller = new AbortController();
  const params = new URLSearchParams({
    page: String(state.page),
    limit: String(state.pageSize),
    filter: state.filter
  });
  if (state.query) params.set('q', state.query);
  try {
    const data = await api(`/api/v1/overview/connections?${params.toString()}`, { signal: state.controller.signal });
    renderSummary(data);
    renderRows(data);
    renderPagination(data);
  } catch (err) {
    if (err?.name === 'AbortError') return;
    setText('overviewConnPageInfo', t('overview.conn.loadError'));
  }
}

const SITUATION_CODES = new Set([
  'calm_protected',
  'calm_mitigated',
  'elevated_activity',
  'partial_protection',
  'fim_new_files',
  'emergency_stop',
  'lockdown_active',
  'worker_crash_storm',
  'tls_control_storm',
  'critical_unmitigated',
  'core_offline_in_enforce',
  'fim_tamper'
]);

const REASON_CODES = new Set([
  'emergency_stop',
  'lockdown',
  'worker_storm',
  'tls_storm',
  'unmitigated_crit',
  'core_offline',
  'fim_tampered',
  'protection_phase',
  'fim_new_files',
  'xdr_degraded',
  'activity_24h',
  'styx_egress',
  'exposure_cve',
  'mitigated',
  'nominal'
]);

export async function refreshOverviewSituation() {
  const ampel = byId('heroAmpel');
  if (!ampel) return;
  try {
    const data = await api('/api/v1/overview/situation');
    const level = ['green', 'yellow', 'red'].includes(data.level) ? data.level : 'yellow';
    ampel.dataset.level = level;
    const ampelBadge = byId('heroAmpelBadge');
    if (ampelBadge) {
      ampelBadge.textContent = level === 'green' ? t('overview.hero.levelGreen') : level === 'red' ? t('overview.hero.levelRed') : t('overview.hero.levelYellow');
      ampelBadge.className = `status-pill ${level === 'green' ? 'good' : level === 'red' ? 'danger' : 'warn'}`;
    }
    const m = data.metrics || {};
    const loc = locale();
    const params = {
      blocked: Number((m.blocked_24h || 0) + (m.l7_blocked || 0)).toLocaleString(loc),
      incidents: Number(m.incidents_24h || 0).toLocaleString(loc),
      phase: String(m.protection_phase || 'observe').toUpperCase(),
      fim_new: Number(m.fim_new || 0).toLocaleString(loc),
      storms: Number(m.worker_storms || 0).toLocaleString(loc),
      styx: Number(m.styx_flagged || 0).toLocaleString(loc),
      cves: Number(m.exposure_cves || 0).toLocaleString(loc)
    };
    const statusCode = String(data.status_code || '');
    const headline = SITUATION_CODES.has(statusCode)
      ? t(`overview.sit.head.${statusCode}`, params)
      : (data.headline || '—');
    const firstReason = Array.isArray(data.reasons) && data.reasons[0] ? String(data.reasons[0].code || '') : '';
    const summary = REASON_CODES.has(firstReason)
      ? t(`overview.sit.reason.${firstReason}`, params)
      : (data.summary || '—');
    setText('overviewHeading', headline);
    setText('heroSituationSummary', summary);
    setText('heroKpiIncidents', Number(m.incidents_24h || 0).toLocaleString(loc));
    setText('heroKpiBlocked', Number((m.blocked_24h || 0) + (m.l7_blocked || 0)).toLocaleString(loc));
    setText('heroKpiSensors', `${Number(m.exposure_servers || 0).toLocaleString(loc)} / ${Number(m.tls_handshakes || 0).toLocaleString(loc)}`);
    setText('heroKpiCoverage', `${Number(m.coverage_percent || 0)}%`);

    const strip = byId('heroLayersStrip');
    if (strip && Array.isArray(data.layers)) {
      strip.replaceChildren();
      for (const layer of data.layers) {
        const pill = makeEl('span', `hero-layer-pill is-${layer.state || 'off'}`);
        const label = ['xdp', 'l7', 'web', 'xdr', 'styx', 'integrity'].includes(layer.id)
          ? t(`overview.sit.layer.${layer.id}`)
          : layer.label;
        pill.append(
          makeEl('strong', '', `${label}:`),
          makeEl('span', '', layer.metric || layer.state || '—')
        );
        strip.append(pill);
      }
    }
  } catch (_) {
    /* keep last situational state on transient error */
  }
}

export function initOverviewConnections() {
  if (state.bound) return;
  const panel = byId('overviewConnectionsPanel');
  if (!panel) return;
  state.bound = true;

  panel.addEventListener('click', event => {
    const filterBtn = event.target.closest('[data-conn-filter]');
    if (filterBtn) {
      state.filter = filterBtn.dataset.connFilter || 'all';
      state.page = 1;
      for (const btn of panel.querySelectorAll('[data-conn-filter]')) {
        btn.setAttribute('aria-pressed', String(btn === filterBtn));
      }
      void refreshOverviewConnections();
      return;
    }
    if (event.target.closest('#overviewConnPrev') && state.page > 1) {
      state.page -= 1;
      void refreshOverviewConnections();
    } else if (event.target.closest('#overviewConnNext')) {
      state.page += 1;
      void refreshOverviewConnections();
    } else if (event.target.closest('#overviewConnRefresh')) {
      void refreshOverviewConnections();
      void refreshOverviewSituation();
    }
  });

  const searchInput = byId('overviewConnSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(state.debounce);
      state.debounce = setTimeout(() => {
        state.query = searchInput.value.trim();
        state.page = 1;
        void refreshOverviewConnections();
      }, 220);
    });
  }

  document.addEventListener('gedefense:language', () => {
    if (isOverviewActive()) {
      void refreshOverviewConnections();
      void refreshOverviewSituation();
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (isOverviewActive()) {
      void refreshOverviewConnections();
      void refreshOverviewSituation();
    }
  });

  state.timer = setInterval(() => {
    if (isOverviewActive()) {
      void refreshOverviewConnections();
      void refreshOverviewSituation();
    }
  }, POLL_MS);

  void refreshOverviewConnections();
  void refreshOverviewSituation();
}
