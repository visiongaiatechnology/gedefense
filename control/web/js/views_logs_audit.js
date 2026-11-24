// STATUS: DIAMANT VGT SUPREME
'use strict';

// Integrity/log surfaces: FIM, the evidence ledger, package integrity and
// boot trust. Split out of the former single app.js module
// (refactoring wave 2a, structure-only).

import {
  createFIMBaseline,
  getBootTrust,
  getEvidence,
  getFIM,
  getPackageIntegrity,
  scanFIM,
  scanPackageIntegrity,
  verifyEvidence
} from '../api.js';
import { t } from '../i18n.js';
import {
  badge,
  byID,
  formatTime,
  text,
  toast
} from '../render.js';
import { refresh } from './state.js';
import {
  emptyTable,
  handleActionError,
  number,
  on
} from './navigation.js';
import { loadHardening } from './views_overview.js';
import { renderMalwareProtection } from './views_xdr_spyware.js';

// The FIM engine reports VERIFIED / PENDING / NO_BASELINE / TAMPERED /
// DEGRADED / QUARANTINED. "HEALTHY" is the evidence-ledger vocabulary and was
// never produced here, so a perfectly verified baseline used to be rendered as
// an action-required failure.
const FIM_TONE = {
  VERIFIED: 'good',
  PENDING: 'warn',
  NO_BASELINE: 'warn',
  TAMPERED: 'danger',
  DEGRADED: 'danger',
  QUARANTINED: 'danger'
};

function fimState(status) {
  const health = String(status?.health || 'UNAVAILABLE').toUpperCase();
  return { health, tone: FIM_TONE[health] || 'muted', verified: health === 'VERIFIED' };
}

function renderFIM(status) {
  const state = fimState(status);
  badge('fimHealth', state.health, state.tone);
  text('fimBaselineCount', number(status?.baseline_count));
  text('fimGeneration', number(status?.generation));
  const findings = Array.isArray(status?.last_scan?.findings) ? status.last_scan.findings : [];
  text('fimFindings', number(findings.length));
  text('fimRoots', Array.isArray(status?.roots) && status.roots.length ? status.roots.join(' Â· ') : t('fim.noPaths'));
  const body = byID('fimRows');
  if (!findings.length) {
    emptyTable(body, 5, t('fim.noFindings'));
    return;
  }
  const rows = findings.map(finding => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [finding.status, `posture-state ${String(finding.status || '').toLowerCase()}`],
      [finding.path, 'mono'],
      [finding.size, ''],
      [finding.mode, 'mono'],
      [finding.message, '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

function renderEvidence(payload) {
  const status = payload?.status || payload || {};
  const records = Array.isArray(payload?.records) ? payload.records : [];
  // A full ledger and a damaged ledger both stop every mutation, and the remedies have
  // nothing in common: one is a retention budget the operator owns, the other is not
  // something they can clear from the interface. Reporting both as DEGRADED left the
  // operator with a blocked product and no route forward, which is the state this panel
  // was found in.
  if (status.full && status.healthy) {
    badge('evidenceHealth', t('evidence.state.full'), 'warning');
  } else if (status.healthy) {
    badge('evidenceHealth', t('evidence.state.verified'), 'good');
  } else {
    badge('evidenceHealth', t('evidence.state.damaged'), 'danger');
  }
  // The remedy is stated where the condition is reported. It is a setting the operator
  // owns, and saying which one is the difference between a locked product and a fixable
  // one. The budget path is exempt from the evidence gate, so it works while the ledger
  // is full - the operator is not being sent somewhere they cannot reach.
  const fullNotice = byID('evidenceFullNotice');
  if (fullNotice) {
    if (status.full) {
      fullNotice.hidden = false;
      text('evidenceFullDetail', t('evidence.fullDetail', {
        stored: number(status.stored_bytes),
        budget: number(status.max_bytes)
      }));
    } else {
      fullNotice.hidden = true;
    }
  }
  text('evidenceRecords', number(status.records));
  text('evidenceBytes', `${number(status.stored_bytes)} B`);
  text('evidenceHead', status.head_hash ? String(status.head_hash).slice(0, 16) : '---');
  text('evidenceKey', status.public_key ? `Ed25519 ${status.public_key}` : t('dynamic.noSigner'));
  const body = byID('evidenceRows');
  if (!records.length) {
    emptyTable(body, 6, t('evidence.noRecords'));
    return;
  }
  const rows = records.map(record => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [record.sequence, 'mono'],
      [formatTime(record.time), ''],
      [record.severity, ''],
      [record.kind, 'mono'],
      [record.source, ''],
      [record.message, '']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

function renderPackageIntegrity(status) {
  const clean = Boolean(status?.last_scan) && !status?.running &&
    Number(status?.modified || 0) === 0 && Number(status?.missing || 0) === 0 &&
    Number(status?.errors || 0) === 0;
  const state = status?.running ? t('dynamic.scanning') : clean ? t('dynamic.verified') : status?.last_scan ? t('dynamic.deviation') : t('dynamic.notChecked');
  badge('packageIntegrityHealth', state, status?.running ? 'warning' : clean ? 'good' : 'danger');
  text('packageIntegrityPackages', number(status?.packages));
  text('packageIntegrityFiles', number(status?.files));
  text('packageIntegrityDeviations', number(Number(status?.modified || 0) + Number(status?.missing || 0) + Number(status?.errors || 0)));
  text('packageIntegrityDetail', status?.last_scan ? `Letzter Scan ${formatTime(status.last_scan)}` : 'Pacman-MTREE-Vertrauensbasis');
  const findings = Array.isArray(status?.findings) ? status.findings : [];
  const body = byID('packageIntegrityRows');
  if (!findings.length) {
    emptyTable(body, 3, status?.running ? t('package.scanning') : t('package.noFindings'));
    return;
  }
  const rows = findings.map(finding => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [finding.status, `posture-state ${String(finding.status || '').toLowerCase()}`],
      [finding.package, 'mono'],
      [finding.path, 'mono']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value || '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadIntegrity() {
  const [fim, evidence, packages] = await Promise.all([getFIM(), getEvidence(), getPackageIntegrity()]);
  renderFIM(fim);
  renderEvidence(evidence);
  renderPackageIntegrity(packages);
  const packageHealthy = !packages?.last_scan ||
    (!packages?.running && Number(packages?.modified || 0) === 0 &&
      Number(packages?.missing || 0) === 0 && Number(packages?.errors || 0) === 0);
  const healthy = fimState(fim).verified && Boolean(evidence?.status?.healthy) && packageHealthy && renderMalwareProtection();
  badge('integrityHealth', healthy ? t('hardening.state.protected') : t('dynamic.actionRequired'), healthy ? 'good' : 'danger');
  return { fim, evidence, packages };
}

function renderBootTrust(report) {
  badge('bootClaim', String(report?.claim_level || 'EVIDENCE ONLY'), report?.astraeaos ? 'good' : 'warning');
  text('bootPlatform', report?.platform || '---');
  text('bootDistro', report?.distro_name || report?.distro_id || '---');
  text('bootGaia', report?.astraeaos ? t('dynamic.detected') : t('dynamic.notDetected'));
  text('bootVersion', report?.version_id || '---');
  text('bootSummary', report?.summary || '---');
  text('bootGenerated', report?.generated_at ? formatTime(report.generated_at) : '---');
  const body = byID('bootRows');
  const items = Array.isArray(report?.items) ? report.items : [];
  if (!items.length) {
    emptyTable(body, 5, t('boot.noEvidence'));
    return;
  }
  const rows = items.map(item => {
    const row = document.createElement('tr');
    for (const [value, className] of [
      [item.id, 'mono'],
      [item.state, `posture-state ${String(item.state || '').toLowerCase()}`],
      [item.summary, ''],
      [item.source, 'mono'],
      [item.digest || item.evidence || '---', 'mono']
    ]) {
      const cell = document.createElement('td');
      cell.textContent = String(value ?? '---');
      if (className) cell.className = className;
      row.append(cell);
    }
    return row;
  });
  body.replaceChildren(...rows);
}

async function loadBootTrust() {
  const report = await getBootTrust();
  renderBootTrust(report);
  return report;
}


function bindLogsAuditActions() {
  on('refreshBoot', 'click', () => loadBootTrust().catch(handleActionError));
  on('fimScan', 'click', async () => {
    try {
      await scanFIM();
      toast(t('toast.fimCompleted'), 'good');
      await Promise.all([loadIntegrity(), loadHardening(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  on('fimBaseline', 'click', async () => {
    try {
      await createFIMBaseline();
      toast(t('toast.fimBaselineCreated'), 'good');
      await Promise.all([loadIntegrity(), loadHardening(), refresh()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  on('evidenceVerify', 'click', async () => {
    try {
      await verifyEvidence();
      toast(t('toast.evidenceVerified'), 'good');
      await Promise.all([loadIntegrity(), loadHardening()]);
    } catch (error) {
      handleActionError(error);
    }
  });
  on('packageIntegrityScan', 'click', async () => {
    try {
      await scanPackageIntegrity();
      toast(t('toast.packageScanStarted'), 'good');
      await loadIntegrity();
    } catch (error) {
      handleActionError(error);
    }
  });
}

export {
  bindLogsAuditActions,
  loadBootTrust,
  loadIntegrity
};
