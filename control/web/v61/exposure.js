// STATUS: DIAMANT VGT SUPREME
'use strict';

// Module A — web exposure & posture.
//
// The view never infers a posture. The control plane answers with `scanned`,
// `reason` and per-server facts (version, ALPN probe, listener reachability,
// matched advisories); this module only arranges them and names the missing
// capability when the scan could not run. Reachability decides whether an
// advisory counts as exposure, so the two are always shown together.

import { t } from '../i18n.js';
import { toast } from '../render.js';
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
  sendJSON,
  setNotice,
  setText,
  setTone,
  severityTone,
  showRefusal
} from './v6.js';

const STATUS_PATH = '/api/v1/web-exposure/status';
const SCAN_PATH = '/api/v1/web-exposure/scan';
const ADVISORY_PATH = '/api/v1/web-exposure/advisories';

let latest = null;
let advisoryRequested = false;

export function initExposureModule() {
  initV61Shared();
  bindAction('exposureScanBtn', scan);
}

export async function loadExposureView() {
  await refresh();
  await loadAdvisories();
}

async function scan() {
  setNotice('exposureReason', '');
  try {
    const result = await sendJSON(SCAN_PATH, 'POST', {});
    const accepted = asBool(result?.scanned) || result?.status === 'accepted' || result?.accepted === true;
    if (result?.reason) setNotice('exposureReason', result.reason, accepted ? 'warn' : 'bad');
    toast(t(accepted ? 'v61.exposure.scanAccepted' : 'v61.exposure.scanRequested'), accepted ? 'good' : 'warning');
  } catch (error) {
    showRefusal('exposureReason', error, 'v61.exposure.scanFailed');
    return;
  }
  await refresh();
  await loadAdvisories(true);
}

async function refresh() {
  try {
    const data = await getJSON(STATUS_PATH);
    latest = data;
    renderStatus(data);
  } catch (error) {
    setNotice('exposureReason', refusalText(error, 'v61.exposure.unavailable'));
    setTone('exposurePill', t('v61.v6.common.unavailable'), 'danger');
  }
}

async function loadAdvisories(force = false) {
  if (advisoryRequested && !force) return;
  advisoryRequested = true;
  try {
    const payload = asObject(await getJSON(ADVISORY_PATH));
    // The advisories endpoint answers {generated_at, catalogue, matches}. Read the
    // catalogue first and keep the older keys as fallbacks so a stale gateway does
    // not empty the table.
    const items = asArray(payload.catalogue || payload.advisories || payload.items || payload);
    setNotice('exposureAdvisoryNote', '', 'warn');
    if (items.length) {
      renderRows('exposureAdvisoryRows', 4, items.map(item => advisoryRow(asObject(item))), 'v61.exposure.empty.advisories');
    } else {
      renderRows('exposureAdvisoryRows', 4, [], 'v61.exposure.empty.advisories');
      setNotice('exposureAdvisoryNote', t('v61.exposure.advisory.empty'), 'warn');
    }
  } catch (error) {
    renderRows('exposureAdvisoryRows', 4, [], 'v61.exposure.empty.advisories');
    setNotice('exposureAdvisoryNote', refusalText(error, 'v61.exposure.advisory.unavailable'), 'warn');
  }
}

function advisoryRow(item) {
  return [
    { text: item.id, cls: 'v61-mono' },
    { pill: { label: dashOr(item.severity, t('v61.v6.common.unknown')), tone: severityTone(item.severity) } },
    { text: item.summary, cls: 'v61-tight', title: String(item.summary || '') },
    { text: item.workaround || item.mitigation || item.mitigation_text, cls: 'v61-tight', title: String(item.workaround || item.mitigation || '') }
  ];
}

function dashOr(value, fallback) {
  return value === null || value === undefined || value === '' ? fallback : value;
}

function renderStatus(data) {
  const source = asObject(data);
  const servers = asArray(source.servers).map(asObject);
  const summary = asObject(source.summary);
  const evidence = asArray(source.evidence);
  const configs = [];
  const affected = [];
  let reachable = 0;
  for (const server of servers) {
    for (const config of asArray(server.configs)) {
      configs.push({ server: server.comm || server.binary || '', config: asObject(config) });
    }
    for (const advisory of asArray(server.affected)) {
      affected.push({ server: server.comm || '', advisory: asObject(advisory) });
    }
    if (asBool(server.reachable)) reachable += 1;
  }

  const exposed = servers.filter(server => String(server.posture || '').toLowerCase() === 'exposed').length;
  const grade = summary.grade || '';
  const postureRank = { exposed: 6, reachable: 5, internal: 4, loopback: 3, filtered: 2, observed: 1 };
  let posture = '';
  let bestRank = -1;
  for (const srv of servers) {
    const p = String(srv.posture || '').toLowerCase();
    const r = postureRank[p] ?? 0;
    if (r > bestRank) {
      bestRank = r;
      posture = srv.posture || '';
    }
  }
  const cveCount = Number(summary.affected_cves ?? affected.length);
  setTone('exposurePill', postureLabel(posture), postureTone(posture, cveCount > 0));

  setText('exposureServersKpi', formatCount(summary.servers ?? servers.length));
  setText('exposureExposedKpi', formatCount(summary.exposed ?? exposed));
  setText('exposureReachableKpi', formatCount(reachable));
  setText('exposureCvesKpi', formatCount(cveCount));
  setText('exposureScoreKpi', source.scanned ? formatCount(summary.score) : '—');
  setTone('exposureGradePill', grade || '—', severityTone(grade === 'A' || grade === 'B' ? 'low' : grade === 'C' ? 'medium' : grade ? 'high' : 'muted'));
  setText('exposureConfigKpi', formatCount(configs.length));
  setText('exposureEvidenceKpi', formatCount(evidence.length));
  setText('exposureUpdatedKpi', formatStamp(source.generated_at));
  setTone(
    'exposureScannedKpi',
    t(asBool(source.scanned) ? 'v61.exposure.scanned' : 'v61.exposure.notScanned'),
    asBool(source.scanned) ? 'good' : 'warn'
  );

  setNotice('exposureReason', source.reason || '', asBool(source.scanned) ? 'warn' : 'bad');

  renderRows('exposureServerRows', 8, servers.map(serverRow), 'v61.exposure.empty.servers');
  renderRows('exposureConfigRows', 4, configs.map(configRow), 'v61.exposure.empty.configs');
  renderRows('exposureAffectedRows', 5, affected.map(affectedRow), 'v61.exposure.empty.affected');
}

function postureTone(posture, hasCVEs = false) {
  switch (String(posture || '').toLowerCase()) {
    case 'exposed':
      return hasCVEs ? 'danger' : 'warn';
    case 'reachable':
    case 'observed':
      return 'warn';
    case 'loopback':
    case 'filtered':
    case 'internal':
      return 'good';
    default:
      return 'muted';
  }
}

// postureLabel keeps every translation key a literal so the catalogue contract
// can verify it; a composed key would be invisible to that check.
function postureLabel(posture) {
  switch (String(posture || '').toLowerCase()) {
    case 'exposed':
      return t('v61.exposure.posture.exposed');
    case 'reachable':
      return t('v61.exposure.posture.reachable');
    case 'observed':
      return t('v61.exposure.posture.observed');
    case 'loopback':
      return t('v61.exposure.posture.loopback');
    case 'filtered':
      return t('v61.exposure.posture.filtered');
    case 'internal':
      return t('v61.exposure.posture.internal');
    default:
      return t('v61.v6.common.unknown');
  }
}

function serverRow(server) {
  const alpn = asObject(server.alpn);
  const alpnLabel = alpn.checked || alpn.protocol
    ? dashOr(alpn.protocol, asArray(alpn.offered).join(' / ') || '—')
    : t('v61.exposure.alpn.notChecked');
  return [
    { text: server.comm || '—', cls: 'v61-mono' },
    { text: server.version || '—', cls: 'v61-mono v61-nowrap' },
    { text: server.binary || '—', cls: 'v61-tight', title: String(server.binary || '') },
    { list: asArray(server.listen) },
    { text: alpnLabel, cls: 'v61-mono' },
    { pill: { label: t(asBool(server.quic) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(server.quic) ? 'warn' : 'muted' } },
    { pill: { label: t(asBool(server.http2) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(server.http2) ? 'warn' : 'muted' } },
    { pill: { label: t(asBool(server.reachable) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), tone: asBool(server.reachable) ? (asArray(server.affected).length > 0 ? 'danger' : 'warn') : 'good' } }
  ];
}

function configRow(entry) {
  return [
    { text: entry.config.path || '—', cls: 'v61-mono v61-tight', title: String(entry.config.path || '') },
    { text: formatCount(entry.config.line), cls: 'v61-mono' },
    { text: entry.config.directive || '—', cls: 'v61-mono' },
    { badges: asArray(entry.config.flags).map(flag => ({ label: flag })) }
  ];
}

function affectedRow(entry) {
  const advisory = entry.advisory;
  return [
    { text: entry.server || '—', cls: 'v61-mono' },
    { text: advisory.id || '—', cls: 'v61-mono' },
    { pill: { label: dashOr(advisory.severity, t('v61.v6.common.unknown')), tone: severityTone(advisory.severity) } },
    { text: advisory.summary || '—', cls: 'v61-tight', title: String(advisory.summary || '') },
    { text: advisory.workaround || '—', cls: 'v61-tight', title: String(advisory.workaround || '') }
  ];
}
