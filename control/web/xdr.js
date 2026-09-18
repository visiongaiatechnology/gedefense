// STATUS: DIAMANT VGT SUPREME
'use strict';

import {
  acknowledgeIncident,
  getProfiles,
  getStatus,
  getXDRIntegrity,
  recoverXDRIntegrity,
  verifyXDRIntegrity
} from './api.js';
import { t } from './i18n.js';
import { byID, el, formatTime, text, toast } from './render.js';

let integrityReport = null;
let lastIntegrityFetch = 0;

export function initXDRModule() {
  const loadProfilesBtn = byID('loadProfiles');
  if (loadProfilesBtn) {
    loadProfilesBtn.addEventListener('click', async () => {
      try {
        const data = await getProfiles();
        renderBehaviorProfiles(data.profiles || []);
        toast(t('toast.profilesLoaded'), 'good');
      } catch (err) {
        toast(err.message, 'danger', err.errorID);
      }
    });
  }

  byID('verifyXDRIntegrity')?.addEventListener('click', async () => {
    try {
      integrityReport = await verifyXDRIntegrity();
      lastIntegrityFetch = Date.now();
      renderIntegrityReport(integrityReport);
      toast(integrityReport.ledger?.healthy ? t('xdr.integrity.verifyHealthy') : t('xdr.integrity.verifyDegraded'), integrityReport.ledger?.healthy ? 'good' : 'danger');
    } catch (err) {
      toast(err.message, 'danger', err.errorID);
    }
  });

  byID('recoverXDRIntegrity')?.addEventListener('click', () => {
    if (!integrityReport?.recovery_allowed) return;
    const reason = byID('xdrRecoveryReason');
    if (reason) reason.value = '';
    byID('xdrRecoveryDialog')?.showModal();
  });

  byID('xdrRecoveryForm')?.addEventListener('submit', async event => {
    event.preventDefault();
    if (!integrityReport?.recovery_allowed) return;
    const reason = String(byID('xdrRecoveryReason')?.value || '').trim();
    if (reason.length < 8 || reason.length > 240) {
      toast(t('xdr.recovery.reasonInvalid'), 'danger');
      return;
    }
    const button = byID('xdrRecoveryConfirm');
    if (button) button.disabled = true;
    try {
      const result = await recoverXDRIntegrity(reason);
      byID('xdrRecoveryDialog')?.close();
      integrityReport = await getXDRIntegrity();
      lastIntegrityFetch = Date.now();
      renderIntegrityReport(integrityReport);
      toast(t('xdr.recovery.success', { archive: result.archive_id || '---' }), 'good');
    } catch (err) {
      toast(err.message, 'danger', err.errorID);
    } finally {
      if (button) button.disabled = false;
    }
  });
}

export async function loadXDRView(snap) {
  let snapshot = snap;
  if (!snapshot) {
    try {
      snapshot = await getStatus();
    } catch (_) {
      return;
    }
  }

  const xdr = snapshot.xdr || {};
  text('xdrProcesses', String(xdr.processes || 0));
  text('xdrConnections', String(xdr.open_connections || 0));
  text('evaluationCount', Number(xdr.evaluations_total || 0).toLocaleString());
  text('queueDepth', `${xdr.queue_depth || 0} / ${xdr.queue_capacity || 0}`);
  text('queueDrops', t('dynamic.drops', { value: xdr.evaluation_drops || 0 }));
  text('profileCount', String(xdr.profiles_total || 0));
  text('warmProfiles', t('dynamic.warm', { value: xdr.profiles_warm || 0 }));

  const modeBadge = byID('xdrModeBadge');
  if (modeBadge) {
    modeBadge.className = `status-pill ${xdr.degraded ? 'danger' : (xdr.mode === 'observe' ? 'warn' : 'good')}`;
    modeBadge.textContent = xdr.degraded ? 'DEGRADED' : String(xdr.mode || 'observe').toUpperCase();
  }

  if (xdr.degraded || integrityReport?.ledger?.quarantined) {
    await refreshIntegrityReport();
  } else {
    integrityReport = null;
    renderIntegrityReport(null);
  }

  renderModernIncidents(snapshot.incidents || []);
}

async function refreshIntegrityReport(force = false) {
  const now = Date.now();
  if (!force && integrityReport && now - lastIntegrityFetch < 5000) {
    renderIntegrityReport(integrityReport);
    return integrityReport;
  }
  integrityReport = await getXDRIntegrity();
  lastIntegrityFetch = now;
  renderIntegrityReport(integrityReport);
  return integrityReport;
}

function renderIntegrityReport(report) {
  const panel = byID('xdrIntegrityPanel');
  if (!panel) return;
  const ledger = report?.ledger || null;
  const unhealthy = Boolean(report && (!ledger?.healthy || report.xdr_degraded));
  panel.hidden = !unhealthy;
  if (!unhealthy) return;

  const badge = byID('xdrIntegrityBadge');
  if (badge) {
    badge.className = 'status-pill danger';
    badge.textContent = ledger?.quarantined ? 'QUARANTINED' : 'DEGRADED';
  }
  text('xdrIntegritySummary', ledger?.recoverable ? t('xdr.integrity.recoverable') : t('xdr.integrity.manual'));
  const code = String(ledger?.reason_code || 'INTEGRITY_FAILURE');
  const translated = t(`xdr.integrity.code.${code}`);
  text('xdrIntegrityReason', translated.startsWith('xdr.integrity.code.') ? code : translated);
  text('xdrIntegrityRecord', ledger?.failure_record ? String(ledger.failure_record) : '---');
  text('xdrIntegrityVerified', String(ledger?.verified_records || 0));

  const recover = byID('recoverXDRIntegrity');
  if (recover) recover.disabled = !report?.recovery_allowed;
}

export function renderModernIncidents(incidents = []) {
  const root = byID('incidents');
  if (!root) return;

  if (!incidents.length) {
    const tr = el('tr');
    const td = el('td', 'empty-cell', t('dynamic.noIncidents'));
    td.colSpan = 7;
    tr.append(td);
    root.replaceChildren(tr);
    return;
  }

  const rows = incidents.map(inc => {
    const tr = el('tr', inc.acknowledged ? 'incident-acknowledged' : 'incident-unacknowledged');

    const tdTime = el('td', 'mono', formatTime(inc.time));

    const tdScore = el('td');
    const scoreVal = el('b', 'score-cell', String(inc.score || 0));
    const sevPill = el('span', `severity-badge ${inc.severity || 'info'}`, (inc.severity || 'info').toUpperCase());
    tdScore.append(scoreVal, el('br'), sevPill);

    const tdProc = el('td', 'mono');
    const procName = el('div', 'proc-name', inc.process || inc.executable || (inc.http_host ? `${inc.http_method} ${inc.http_host}` : 'system'));
    const pid = inc.pid ? el('small', 'text-muted', `PID ${inc.pid}`) : null;
    tdProc.append(procName);
    if (pid) tdProc.append(pid);

    const tdSignals = el('td');
    const signals = inc.categories || inc.rule_ids || [];
    if (signals.length > 0) {
      const pill = el('span', 'signal-badge', t('xdr.signalCategories', { count: signals.length, preview: signals.slice(0, 2).join(', ') }));
      tdSignals.append(pill);
    } else {
      tdSignals.textContent = '---';
    }

    const tdDecision = el('td');
    const decisionPill = el('span', inc.action === 'deny-request' || inc.decision === 'deny-http' || inc.action === 'kill' ? 'status-pill danger' : 'status-pill muted');
    decisionPill.textContent = (inc.decision || 'alert').toUpperCase();
    tdDecision.append(decisionPill);

    const tdResult = el('td', 'cell-result', inc.outcome || inc.summary || '---');

    const tdAction = el('td');
    if (!inc.acknowledged) {
      const ackBtn = el('button', 'button button-quiet compact', t('dynamic.acknowledge'));
      ackBtn.type = 'button';
      ackBtn.addEventListener('click', async evt => {
        evt.stopPropagation();
        try {
          await acknowledgeIncident(inc.id);
          toast(t('toast.incidentAck'), 'good');
          inc.acknowledged = true;
          tr.className = 'incident-acknowledged';
          ackBtn.remove();
        } catch (err) {
          toast(err.message, 'danger', err.errorID);
        }
      });
      tdAction.append(ackBtn);
    } else {
      const ackMark = el('span', 'text-muted mono', 'ACK');
      tdAction.append(ackMark);
    }

    tr.append(tdTime, tdScore, tdProc, tdSignals, tdDecision, tdResult, tdAction);
    return tr;
  });

  root.replaceChildren(...rows);
}

function renderBehaviorProfiles(profiles = []) {
  const root = byID('profiles');
  if (!root) return;

  if (!profiles.length) {
    const tr = el('tr');
    const td = el('td', 'empty-cell', t('dynamic.noProfiles'));
    td.colSpan = 6;
    tr.append(td);
    root.replaceChildren(tr);
    return;
  }

  const rows = profiles.map(p => {
    const tr = el('tr');
    tr.append(
      el('td', 'mono', p.executable || t('dynamic.unknown')),
      el('td', 'mono', String(p.connection_count?.samples || 0)),
      el('td', 'mono', Number(p.connection_count?.mean || 0).toFixed(1)),
      el('td', 'mono', Number(p.unique_remotes?.mean || 0).toFixed(1)),
      el('td', 'mono', String(p.remote_ports ? Object.keys(p.remote_ports).length : 0)),
      el('td', 'mono', formatTime(p.last_seen))
    );
    return tr;
  });

  root.replaceChildren(...rows);
}
