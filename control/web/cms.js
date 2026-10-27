'use strict';

import { api } from './api.js';
import { t } from './i18n.js';
import { byID, text } from './render.js';

let latest = null;

function fmtTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function renderDetections(status) {
  const host = byID('cmsDetections');
  if (!host) return;
  const items = Array.isArray(status?.detections) ? status.detections : [];
  host.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-note';
    empty.textContent = t('cms.detection.empty');
    host.append(empty);
    return;
  }
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'cms-detection';
    const kind = document.createElement('b');
    kind.textContent = String(item.kind || 'cms').toUpperCase();
    const site = document.createElement('span');
    site.textContent = item.host || '—';
    const confidence = document.createElement('span');
    confidence.textContent = `${Number(item.confidence || 0)}%`;
    const seen = document.createElement('small');
    seen.textContent = fmtTime(item.last_seen);
    row.append(kind, site, confidence, seen);
    host.append(row);
  }
}

function renderLeases(status) {
  const host = byID('cmsLeases');
  if (!host) return;
  const items = Array.isArray(status?.leases) ? status.leases : [];
  host.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-note';
    empty.textContent = t('cms.bridge.leaseEmpty');
    host.append(empty);
    return;
  }
  for (const lease of items) {
    const row = document.createElement('div');
    row.className = 'cms-lease';
    const title = document.createElement('b');
    title.textContent = `${lease.ip || '?'} → ${lease.host || '?'}`;
    const detail = document.createElement('small');
    detail.textContent = `${lease.user || 'master'} · ${fmtTime(new Date((lease.expires_at || 0) * 1000).toISOString())}`;
    row.append(title, detail);
    host.append(row);
  }
}

function fill(form, status) {
  const settings = status?.settings || {};
  const values = {
    cmsEnabled: settings.enabled,
    cmsAutoRelax: settings.auto_relax,
    cmsRelaxAdmin: settings.relax_admin,
    cmsBridgeEnabled: settings.bridge_enabled
  };
  for (const [id, value] of Object.entries(values)) {
    const input = byID(id);
    if (input) input.checked = Boolean(value);
  }
  const numbers = {
    cmsRatePerMinute: settings.relax_client_rate_per_minute,
    cmsRateBurst: settings.relax_client_rate_burst,
    cmsTTL: settings.trusted_admin_ttl_seconds
  };
  for (const [id, value] of Object.entries(numbers)) {
    const input = byID(id);
    if (input && value != null) input.value = String(value);
  }
  const bridgePath = byID('cmsBridgePath');
  if (bridgePath) bridgePath.value = settings.bridge_log_path || '';
  text('cmsBridgePill', status?.bridge_key_set && settings.bridge_enabled ? t('cms.bridge.connected') : t('cms.bridge.disconnected'));
  const pill = byID('cmsBridgePill');
  if (pill) pill.className = `status-pill ${status?.bridge_key_set && settings.bridge_enabled ? 'good' : 'muted'}`;
  text('cmsBridgeKey', status?.bridge_key_fingerprint || t('cms.bridge.noKey'));
  renderDetections(status);
  renderLeases(status);
}

function readForm() {
  return {
    enabled: Boolean(byID('cmsEnabled')?.checked),
    auto_relax: Boolean(byID('cmsAutoRelax')?.checked),
    relax_admin: Boolean(byID('cmsRelaxAdmin')?.checked),
    relax_client_rate_per_minute: Number(byID('cmsRatePerMinute')?.value || 1200),
    relax_client_rate_burst: Number(byID('cmsRateBurst')?.value || 200),
    trusted_admin_ttl_seconds: Number(byID('cmsTTL')?.value || 7200),
    bridge_enabled: Boolean(byID('cmsBridgeEnabled')?.checked),
    bridge_log_path: byID('cmsBridgePath')?.value || '/var/lib/vgt/gedefense-wp-bridge/events.log',
    bridge_max_skew_seconds: 300
  };
}

async function refresh() {
  latest = await api('/api/v1/cms');
  fill(null, latest);
  return latest;
}

async function save() {
  const status = await api('/api/v1/cms', { method: 'PUT', json: { settings: readForm() } });
  latest = status;
  fill(null, status);
  text('cmsSaveStatus', t('cms.saved'));
}

async function rotate() {
  const result = await api('/api/v1/cms/bridge/rotate', { method: 'POST', json: {} });
  const box = byID('cmsSecretBox');
  const input = byID('cmsSecret');
  if (box && input) {
    input.value = result.secret || '';
    box.hidden = false;
  }
  await refresh();
}

async function revoke() {
  await api('/api/v1/cms/bridge/revoke', { method: 'POST', json: {} });
  await refresh();
}

async function copySecret() {
  const input = byID('cmsSecret');
  if (!input || !input.value) return;
  try {
    await navigator.clipboard.writeText(input.value);
  } catch (_) {
    input.select();
  }
}

export function initCMSModule() {
  ['cmsEnabled', 'cmsAutoRelax', 'cmsRelaxAdmin', 'cmsBridgeEnabled', 'cmsRatePerMinute', 'cmsRateBurst', 'cmsTTL', 'cmsBridgePath'].forEach(id => {
    byID(id)?.addEventListener('change', () => text('cmsSaveStatus', ''));
  });
  byID('cmsSave')?.addEventListener('click', () => save().catch(error => text('cmsSaveStatus', error?.message || t('api.controlUnavailable'))));
  byID('cmsRotateKey')?.addEventListener('click', () => rotate().catch(error => text('cmsSaveStatus', error?.message || t('api.controlUnavailable'))));
  byID('cmsRevokeLeases')?.addEventListener('click', () => revoke().catch(error => text('cmsSaveStatus', error?.message || t('api.controlUnavailable'))));
  byID('cmsCopySecret')?.addEventListener('click', () => copySecret());
}

export async function loadCMSView() {
  return refresh();
}