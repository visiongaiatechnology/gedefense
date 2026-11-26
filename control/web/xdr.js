// STATUS: DIAMANT VGT SUPREME
'use strict';

import {
  acknowledgeIncident,
  ackReviewEntry,
  deletePermit,
  deleteReviewEntry,
  getChameleonStatus,
  getPermits,
  getProfiles,
  getReviewQueue,
  getSBCFusion,
  getSecCritStatus,
  getStatus,
  getXDRIntegrity,
  recoverXDRIntegrity,
  revealChameleon,
  upsertPermit,
  verifyXDRIntegrity
} from './api.js';
import { t } from './i18n.js';
import { withCriticalStepUp } from './js/navigation.js';
import { badge, byID, el, formatTime, isXDROperationallyDegraded, text, toast } from './render.js';

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

  byID('reviewQueueRefresh')?.addEventListener('click', () => {
    refreshV63XDRPanels().catch(err => toast(err.message, 'danger', err.errorID));
  });

  byID('chameleonRevealBtn')?.addEventListener('click', async () => {
    try {
      const res = await withCriticalStepUp(t('chameleon.reveal'), proof =>
        revealChameleon('Operator Chameleon commitment verification', 'REVEAL CHAMELEON', proof)
      );
      if (!res) return;
      text('chameleonIdentityMeta', `${res.install_id || '---'} · ${res.mapping_hash || '---'}`);
      toast(t('chameleon.revealed'), 'good');
    } catch (err) {
      toast(err.message, 'danger', err.errorID);
    }
  });

  byID('permitForm')?.addEventListener('submit', async event => {
    event.preventDefault();
    const permitID = String(byID('permitIDInput')?.value || '').trim().toLowerCase();
    const exePath = String(byID('permitPathInput')?.value || '').trim();
    const reason = String(byID('permitReasonInput')?.value || '').trim();
    if (!exePath || !reason) return;
    if (permitID && !/^[0-9a-f]{32,64}$/.test(permitID) && !/^([0-9a-f]{2}){16,32}$/.test(permitID)) {
      toast(t('xdr.permits.invalidId') || 'Permit-ID muss leer bleiben (auto) oder 32-64 Hex-Zeichen enthalten.', 'danger');
      return;
    }
    try {
      const label = permitID || exePath;
      const outcome = await withCriticalStepUp(`${t('xdr.permits.create')}: ${label}`, proof =>
        upsertPermit({
          schema: 'vgt-gedefense-permit-v1',
          permit_id: permitID,
          trust_level: 'TOLERATED',
          path: exePath,
          reason,
          scope: { rules: ['XDR.TEMP_EXEC', 'BASELINE.PARENT_MISMATCH'] },
          auto_invalidate_on: ['binary_changed']
        }, proof)
      );
      if (!outcome) return;
      byID('permitForm')?.reset();
      toast(t('xdr.permits.saved'), 'good');
      await refreshV63XDRPanels();
    } catch (err) {
      toast(err.message, 'danger', err.errorID);
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
  const depth = Number(xdr.queue_depth || 0);
  const cap = Number(xdr.queue_capacity || 0);
  const drops = Number(xdr.evaluation_drops || 0);
  text('queueDepth', `${depth.toLocaleString()} / ${cap.toLocaleString()}`);
  const dropEl = byID('queueDrops');
  if (dropEl) {
    dropEl.textContent = drops > 0
      ? t('dynamic.drops', { value: drops.toLocaleString() })
      : `${drops} Drops · optimal`;
    dropEl.className = drops > 0 ? 'text-danger font-semibold' : 'text-muted';
  }
  const behavior = xdr.behavior || {};
  const profileCount = behavior.profiles ?? xdr.profiles_total ?? 0;
  const warmCount = behavior.warm_profiles ?? xdr.profiles_warm ?? 0;
  text('profileCount', Number(profileCount).toLocaleString());
  text('warmProfiles', Number(warmCount).toLocaleString());

  const xdrDegraded = isXDROperationallyDegraded(xdr);
  const modeBadge = byID('xdrModeBadge');
  if (modeBadge) {
    modeBadge.className = `status-pill ${xdrDegraded ? 'danger' : (xdr.mode === 'observe' ? 'warn' : 'good')}`;
    modeBadge.textContent = xdrDegraded ? 'DEGRADED' : String(xdr.mode || 'observe').toUpperCase();
  }

  if (xdrDegraded || integrityReport?.ledger?.quarantined) {
    await refreshIntegrityReport();
  } else {
    integrityReport = null;
    renderIntegrityReport(null);
  }

  renderModernIncidents(snapshot.incidents || []);
  refreshV63XDRPanels().catch(() => {});
}

async function refreshV63XDRPanels() {
  const [secCrit, sbc, chameleon, review, permits] = await Promise.all([
    getSecCritStatus().catch(() => null),
    getSBCFusion().catch(() => null),
    getChameleonStatus().catch(() => null),
    getReviewQueue(100).catch(() => null),
    getPermits().catch(() => null)
  ]);
  if (secCrit) renderSecCritPanel(secCrit);
  if (sbc) renderSBCPanel(sbc);
  if (chameleon) renderChameleonPanel(chameleon);
  if (review) renderReviewQueue(review);
  if (permits) renderPermits(permits);
}

function renderSecCritPanel(secCrit) {
  const state = String(secCrit?.state || 'unavailable');
  badge('secCritStateBadge', state.toUpperCase(), state === 'active' ? 'good' : state === 'degraded' ? 'danger' : 'warning');
  const q = secCrit?.quotas || {};
  text('secCritQuotaSummary',
    `enforced=${Boolean(q.enforced)} · events=${Number(secCrit?.events || 0)} · suppressed=${Number(secCrit?.suppressed || 0)} · drops=${Number(secCrit?.drops || 0)}`
  );
}

function renderSBCPanel(sbc) {
  const state = String(sbc?.state || 'unavailable');
  badge('sbcStateBadge', state.toUpperCase(), state === 'active' ? 'good' : 'warning');
  text('sbcSummaryMeta',
    `entities=${Number(sbc?.entities || 0)} · corr=${Number(sbc?.corroboration_events || 0)} · obs=${Number(sbc?.observations || 0)}`
  );
}

function renderChameleonPanel(chameleon) {
  const active = Boolean(chameleon?.active);
  badge('chameleonStateBadge', active ? 'CHAMELEON' : 'STANDARD', active ? 'good' : '');
  const meta = active
    ? `${chameleon.install_id || '---'} · ${chameleon.core_socket || '---'}`
    : `${chameleon.core_socket || '/run/vgt-gedefense/core.sock'}`;
  text('chameleonIdentityMeta', meta);
  const btn = byID('chameleonRevealBtn');
  if (btn) btn.hidden = !active;
}

function renderReviewQueue(payload) {
  const body = byID('reviewQueueRows');
  if (!body) return;
  const entries = Array.isArray(payload?.entries) ? payload.entries : [];
  if (!entries.length) {
    const row = el('tr');
    const td = el('td', 'empty-cell', t('xdr.review.empty'));
    td.colSpan = 5;
    row.append(td);
    body.replaceChildren(row);
    return;
  }
  const rows = entries.map(entry => {
    const row = el('tr');
    row.append(
      el('td', 'mono', String(entry.id || '').slice(0, 16)),
      el('td', 'mono', entry.process || entry.executable || '---'),
      el('td', `severity-${String(entry.severity || 'info').toLowerCase()}`, String(entry.severity || 'info').toUpperCase()),
      el('td', 'mono', entry.acknowledged ? 'ACK' : `OPEN (${entry.repeat_count || 1}x)`)
    );
    const actions = el('td');
    if (!entry.acknowledged) {
      const ackBtn = el('button', 'button button-quiet compact', t('dynamic.acknowledge'));
      ackBtn.type = 'button';
      ackBtn.addEventListener('click', async () => {
        try {
          const outcome = await withCriticalStepUp(`${t('dynamic.acknowledge')}: ${String(entry.id).slice(0, 12)}`, proof =>
            ackReviewEntry(entry.id, proof)
          );
          if (outcome === null) return;
          toast(t('toast.incidentAck'), 'good');
          await refreshV63XDRPanels();
        } catch (err) {
          toast(err.message, 'danger', err.errorID);
        }
      });
      actions.append(ackBtn);
    }
    const delBtn = el('button', 'button button-danger compact ml-xs', t('xdr.review.delete'));
    delBtn.type = 'button';
    delBtn.addEventListener('click', async () => {
      try {
        const outcome = await withCriticalStepUp(`${t('xdr.review.delete')}: ${String(entry.id).slice(0, 12)}`, proof =>
          deleteReviewEntry(entry.id, proof)
        );
        if (outcome === null) return;
        toast(t('xdr.review.deleted'), 'good');
        await refreshV63XDRPanels();
      } catch (err) {
        toast(err.message, 'danger', err.errorID);
      }
    });
    actions.append(delBtn);
    row.append(actions);
    return row;
  });
  body.replaceChildren(...rows);
}

function renderPermits(payload) {
  const report = payload?.report || {};
  badge('permitBrokerBadge', String(report.signature_status || 'absent').toUpperCase(), report.loaded && !report.corrupt ? 'good' : 'warning');
  const body = byID('permitRows');
  if (!body) return;
  const permits = Array.isArray(payload?.permits) ? payload.permits : [];
  if (!permits.length) {
    const row = el('tr');
    const td = el('td', 'empty-cell', t('xdr.permits.empty'));
    td.colSpan = 5;
    row.append(td);
    body.replaceChildren(row);
    return;
  }
  const rows = permits.map(permit => {
    const row = el('tr');
    row.append(
      el('td', 'mono', permit.permit_id || '---'),
      el('td', 'mono', permit.path || '---'),
      el('td', 'mono', permit.trust_level || 'ANALYST_MODE'),
      el('td', 'mono', formatTime(permit.valid_until))
    );
    const action = el('td');
    const delBtn = el('button', 'button button-danger compact', t('xdr.review.delete'));
    delBtn.type = 'button';
    delBtn.addEventListener('click', async () => {
      try {
        const outcome = await withCriticalStepUp(`${t('xdr.permits.remove')}: ${permit.permit_id}`, proof =>
          deletePermit(permit.permit_id, proof)
        );
        if (outcome === null) return;
        toast(t('xdr.permits.deleted'), 'good');
        await refreshV63XDRPanels();
      } catch (err) {
        toast(err.message, 'danger', err.errorID);
      }
    });
    action.append(delBtn);
    row.append(action);
    return row;
  });
  body.replaceChildren(...rows);
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

  // The cause has to be the cause. This panel reported the incident ledger's reason code -
  // and, when the ledger had none because it was perfectly healthy, the literal
  // "INTEGRITY_FAILURE" - while XDR was in fact degraded by something else entirely, such
  // as a protected object that no longer matched its baseline. The operator was sent to
  // examine a ledger that had nothing wrong with it. When the ledger is not the unhealthy
  // part, the report's own degraded_reason is what is shown.
  const ledgerIsCause = Boolean(ledger && !ledger.healthy);
  const reportReason = String(report?.degraded_reason || '').trim();
  if (ledgerIsCause || !reportReason) {
    const code = String(ledger?.reason_code || 'INTEGRITY_FAILURE');
    const translated = t(`xdr.integrity.code.${code}`);
    text('xdrIntegrityReason', translated.startsWith('xdr.integrity.code.') ? code : translated);
  } else {
    text('xdrIntegrityReason', reportReason);
  }
  text('xdrIntegrityRecord', ledger?.failure_record ? String(ledger.failure_record) : '---');
  text('xdrIntegrityVerified', String(ledger?.verified_records || 0));

  const recover = byID('recoverXDRIntegrity');
  if (recover) recover.disabled = !report?.recovery_allowed;
}

export function renderModernIncidents(incidents = []) {
  const root = byID('incidents');
  if (!root) return;

  // The XDR timeline and the generic incident table renderer share this tbody. Both used to draw
  // on every snapshot; on a 250-row log that replaced the whole table every second, and the scroll
  // pane returned to the top each time. The signature makes an unchanged frame a no-op, and the
  // owner marker keeps the generic renderer away from this table while XDR is the active page.
  const signature = incidents
    .map(inc => [inc?.id || '', inc?.acknowledged ? 1 : 0, inc?.score || 0, inc?.severity || '', inc?.decision || '', inc?.outcome || '', (inc?.categories || []).join(',')].join('|'))
    .join(';');
  if (root.dataset.owner === 'xdr' && root.dataset.renderSignature === signature) return;
  root.dataset.owner = 'xdr';
  root.dataset.renderSignature = signature;

  const wrap = root.closest('.table-wrap');
  const scrollTop = wrap ? wrap.scrollTop : 0;

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
    const sevPill = el('span', `severity-badge ${String(inc.severity || 'info').toLowerCase()}`, (inc.severity || 'info').toUpperCase());
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
  if (wrap && scrollTop) wrap.scrollTop = scrollTop;
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
