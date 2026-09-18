// STATUS: DIAMANT VGT SUPREME
'use strict';

import { acknowledgeIncident, getProfiles, getStatus } from './api.js';
import { t } from './i18n.js';
import { byID, el, formatTime, text, toast } from './render.js';

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
  text('queueDrops', `${xdr.evaluation_drops || 0} Drops`);
  text('profileCount', String(xdr.profiles_total || 0));
  text('warmProfiles', `${xdr.profiles_warm || 0} warm`);

  renderModernIncidents(snapshot.incidents || []);
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
      const pill = el('span', 'signal-badge', `${signals.length} categories (${signals.slice(0, 2).join(', ')})`);
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
      el('td', 'mono', p.executable || 'unknown'),
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
