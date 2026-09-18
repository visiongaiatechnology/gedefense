// STATUS: DIAMANT VGT SUPREME
'use strict';

import {
  clearEmergencyStop,
  emergencyStop,
  getRelease,
  getReleaseReadiness,
  getStatus,
  transitionRelease
} from './api.js';
import { t } from './i18n.js';
import { byID, el, text, toast } from './render.js';

let currentPhase = 'observe';
let countdownTimer = 0;
let soakTargetTime = 0;

export function initProtectionCenter() {
  const activateModal = byID('activateProtectionDialog');
  const emergencyModal = byID('emergencyStopDialog');
  const emergencyClearModal = byID('emergencyClearDialog');

  const btnActivateCanary = byID('btnActivateCanary');
  const btnActivateEnforce = byID('btnActivateEnforce');
  const btnReturnObserve = byID('btnReturnObserve');
  const btnEmergency = byID('btnTriggerEmergency');
  const btnClearEmergency = byID('btnClearEmergency');

  if (btnActivateCanary) {
    btnActivateCanary.addEventListener('click', () => openActivationDialog('canary'));
  }
  if (btnActivateEnforce) {
    btnActivateEnforce.addEventListener('click', () => openActivationDialog('enforce'));
  }
  if (btnReturnObserve) {
    btnReturnObserve.addEventListener('click', () => openActivationDialog('observe'));
  }
  if (btnEmergency) {
    btnEmergency.addEventListener('click', () => openEmergencyDialog());
  }
  if (btnClearEmergency) {
    btnClearEmergency.addEventListener('click', () => openClearEmergencyDialog());
  }

  // Topbar Emergency Stop Button if present
  const topEmergency = byID('topEmergencyBtn');
  if (topEmergency) {
    topEmergency.addEventListener('click', () => openEmergencyDialog());
  }

  // Form handlers
  const activateForm = byID('activateProtectionForm');
  if (activateForm) {
    activateForm.addEventListener('submit', handleActivationSubmit);
  }
  const emergencyForm = byID('emergencyStopForm');
  if (emergencyForm) {
    emergencyForm.addEventListener('submit', handleEmergencySubmit);
  }
  const emergencyClearForm = byID('emergencyClearFormModal');
  if (emergencyClearForm) {
    emergencyClearForm.addEventListener('submit', handleEmergencyClearSubmit);
  }
}

export async function loadProtectionState(snap) {
  let snapshot = snap;
  if (!snapshot) {
    try {
      snapshot = await getStatus();
    } catch (_) {
      return;
    }
  }
  const rel = snapshot.release || {};
  currentPhase = String(rel.phase || 'observe').toLowerCase();

  updateTopEmergencyVisibility(currentPhase, rel.emergency_stop);
  renderProtectionHero(snapshot);
  await renderProtectionStepper(snapshot);
}

function updateTopEmergencyVisibility(phase, isEmergency) {
  const topEmergency = byID('topEmergencyBtn');
  if (!topEmergency) return;
  const isProtected = phase === 'enforce' || phase === 'canary' || isEmergency;
  topEmergency.hidden = !isProtected;
  if (isEmergency) {
    topEmergency.classList.add('pulse-danger');
  } else {
    topEmergency.classList.remove('pulse-danger');
  }
}

function renderProtectionHero(snapshot) {
  const rel = snapshot.release || {};
  const phase = String(rel.phase || 'observe').toLowerCase();
  const isEmergency = Boolean(rel.emergency_stop);

  const heroBadge = byID('heroProtectionBadge');
  const heroTitle = byID('heroProtectionTitle');
  const heroDesc = byID('heroProtectionDesc');
  const heroBtn = byID('heroProtectionAction');

  if (isEmergency) {
    if (heroBadge) {
      heroBadge.textContent = t('overview.hero.emergencyBadge');
      heroBadge.className = 'status-pill danger';
    }
    if (heroTitle) heroTitle.textContent = t('emergency.title');
    if (heroDesc) heroDesc.textContent = t('overview.hero.emergencyDesc');
    if (heroBtn) {
      heroBtn.textContent = t('emergency.clearBtn');
      heroBtn.className = 'button button-danger';
      heroBtn.onclick = () => openClearEmergencyDialog();
    }
    return;
  }

  if (phase === 'enforce') {
    if (heroBadge) {
      heroBadge.textContent = t('overview.hero.enforceBadge');
      heroBadge.className = 'status-pill good';
    }
    if (heroTitle) heroTitle.textContent = t('overview.hero.enforceBadge');
    if (heroDesc) heroDesc.textContent = t('overview.hero.enforceDesc');
    if (heroBtn) {
      heroBtn.textContent = t('overview.hero.btnActive');
      heroBtn.className = 'button button-quiet';
      heroBtn.onclick = () => {
        const target = byID('protectionView');
        if (target) location.hash = 'protection';
      };
    }
  } else if (phase === 'canary') {
    if (heroBadge) {
      heroBadge.textContent = t('overview.hero.canaryBadge');
      heroBadge.className = 'status-pill warn';
    }
    if (heroTitle) heroTitle.textContent = t('overview.hero.canaryBadge');
    if (heroDesc) heroDesc.textContent = t('overview.hero.canaryDesc');
    if (heroBtn) {
      heroBtn.textContent = t('overview.hero.btnEnforce');
      heroBtn.className = 'button button-primary';
      heroBtn.onclick = () => openActivationDialog('enforce');
    }
  } else if (phase === 'degraded') {
    if (heroBadge) {
      heroBadge.textContent = t('overview.hero.degradedBadge');
      heroBadge.className = 'status-pill danger';
    }
    if (heroTitle) heroTitle.textContent = t('overview.hero.degradedBadge');
    if (heroDesc) heroDesc.textContent = t('overview.hero.degradedDesc');
    if (heroBtn) {
      heroBtn.textContent = t('overview.hero.btnActivate');
      heroBtn.className = 'button button-warning';
      heroBtn.onclick = () => openActivationDialog('canary');
    }
  } else {
    // Observe
    if (heroBadge) {
      heroBadge.textContent = t('overview.hero.observeBadge');
      heroBadge.className = 'status-pill muted';
    }
    if (heroTitle) heroTitle.textContent = t('overview.hero.observeBadge');
    if (heroDesc) heroDesc.textContent = t('overview.hero.observeDesc');
    if (heroBtn) {
      heroBtn.textContent = t('overview.hero.btnActivate');
      heroBtn.className = 'button button-primary';
      heroBtn.onclick = () => openActivationDialog('canary');
    }
  }
}

async function renderProtectionStepper(snapshot) {
  const stepperContainer = byID('protectionStepperContainer');
  if (!stepperContainer) return;

  let readinessCanary = null;
  let readinessEnforce = null;

  try {
    readinessCanary = await getReleaseReadiness('canary');
    readinessEnforce = await getReleaseReadiness('enforce');
  } catch (err) {
    // Graceful fallback if server unavailable
  }

  const rel = snapshot.release || {};
  const isEmergency = Boolean(rel.emergency_stop);
  const phase = String(rel.phase || 'observe').toLowerCase();

  // Emergency banner
  const emergencyBanner = byID('emergencyBanner');
  if (emergencyBanner) {
    emergencyBanner.hidden = !isEmergency;
  }

  // Update context bar current badge
  const currentBadge = byID('protectionCurrentBadge');
  if (currentBadge) {
    if (isEmergency) {
      currentBadge.textContent = t('emergency.topBtn');
      currentBadge.className = 'status-pill danger pulse-danger';
    } else if (phase === 'enforce') {
      currentBadge.textContent = 'ENFORCE';
      currentBadge.className = 'status-pill good';
    } else if (phase === 'canary') {
      currentBadge.textContent = 'CANARY';
      currentBadge.className = 'status-pill warn';
    } else if (phase === 'degraded') {
      currentBadge.textContent = 'DEGRADED';
      currentBadge.className = 'status-pill danger';
    } else {
      currentBadge.textContent = 'OBSERVE';
      currentBadge.className = 'status-pill muted';
    }
  }

  // Update phase cards
  const cardObserve = byID('stepCardObserve');
  const cardCanary = byID('stepCardCanary');
  const cardEnforce = byID('stepCardEnforce');

  const pillObserve = byID('stepPillObserve');
  const pillCanary = byID('stepPillCanary');
  const pillEnforce = byID('stepPillEnforce');

  // Clear previous state classes
  [cardObserve, cardCanary, cardEnforce].forEach(card => {
    if (card) card.className = 'step-card glass-panel';
  });

  if (cardObserve && pillObserve) {
    if (phase === 'observe') {
      cardObserve.classList.add('is-current');
      pillObserve.textContent = t('stepper.status.active');
      pillObserve.className = 'status-pill active';
    } else {
      cardObserve.classList.add('is-passed');
      pillObserve.textContent = '✓';
      pillObserve.className = 'status-pill passed';
    }
  }

  if (cardCanary && pillCanary) {
    if (phase === 'canary') {
      cardCanary.classList.add('is-current');
      pillCanary.textContent = t('stepper.status.active');
      pillCanary.className = 'status-pill active';
    } else if (phase === 'enforce') {
      cardCanary.classList.add('is-passed');
      pillCanary.textContent = '✓';
      pillCanary.className = 'status-pill passed';
    } else if (readinessCanary && readinessCanary.ready) {
      cardCanary.classList.add('is-ready');
      pillCanary.textContent = t('stepper.status.ready');
      pillCanary.className = 'status-pill good';
    } else {
      cardCanary.classList.add('is-locked');
      pillCanary.textContent = t('stepper.status.locked');
      pillCanary.className = 'status-pill muted';
    }
  }

  if (cardEnforce && pillEnforce) {
    if (phase === 'enforce') {
      cardEnforce.classList.add('is-current');
      pillEnforce.textContent = t('stepper.status.active');
      pillEnforce.className = 'status-pill active';
    } else if (readinessEnforce && readinessEnforce.ready) {
      cardEnforce.classList.add('is-ready');
      pillEnforce.textContent = t('stepper.status.ready');
      pillEnforce.className = 'status-pill good';
    } else {
      cardEnforce.classList.add('is-locked');
      pillEnforce.textContent = t('stepper.status.locked');
      pillEnforce.className = 'status-pill muted';
    }
  }

  // Update Soak timers
  renderSoakTimers(readinessCanary, readinessEnforce, phase);

  // Update buttons
  const btnActivateCanary = byID('btnActivateCanary');
  const btnActivateEnforce = byID('btnActivateEnforce');
  const btnReturnObserve = byID('btnReturnObserve');

  if (btnActivateCanary) {
    btnActivateCanary.hidden = phase !== 'observe' && phase !== 'degraded';
    btnActivateCanary.disabled = Boolean(isEmergency || (readinessCanary && !readinessCanary.ready));
  }
  if (btnActivateEnforce) {
    btnActivateEnforce.hidden = phase !== 'canary';
    btnActivateEnforce.disabled = Boolean(isEmergency || (readinessEnforce && !readinessEnforce.ready));
  }
  if (btnReturnObserve) {
    btnReturnObserve.hidden = phase === 'observe';
  }

  // Update blockers list
  renderActiveBlockers(snapshot, readinessCanary, readinessEnforce);
}

function renderSoakTimers(canary, enforce, phase) {
  const canaryTimer = byID('canarySoakTimer');
  const enforceTimer = byID('enforceSoakTimer');

  if (canaryTimer) {
    if (canary && canary.soak_remaining_seconds > 0) {
      canaryTimer.textContent = formatDuration(canary.soak_remaining_seconds);
      canaryTimer.parentElement.hidden = false;
    } else {
      canaryTimer.parentElement.hidden = true;
    }
  }

  if (enforceTimer) {
    if (enforce && enforce.soak_remaining_seconds > 0) {
      enforceTimer.textContent = formatDuration(enforce.soak_remaining_seconds);
      enforceTimer.parentElement.hidden = false;
    } else {
      enforceTimer.parentElement.hidden = true;
    }
  }
}

function renderActiveBlockers(snapshot, canary, enforce) {
  const root = byID('protectionBlockersList');
  if (!root) return;

  const currentBlockers = [];
  if (canary && !canary.ready && currentPhase === 'observe') {
    currentBlockers.push(...canary.blockers);
  }
  if (enforce && !enforce.ready && currentPhase === 'canary') {
    currentBlockers.push(...enforce.blockers);
  }

  if (currentBlockers.length === 0) {
    const li = el('li', 'state-good', t('dynamic.allGates'));
    root.replaceChildren(li);
    return;
  }

  const items = currentBlockers.map(b => el('li', 'state-warn', b));
  root.replaceChildren(...items);
}

function formatDuration(totalSeconds) {
  const s = Math.max(0, Math.floor(totalSeconds));
  const hrs = Math.floor(s / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  if (hrs > 0) {
    return `${hrs}h ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`;
  }
  return `${mins}m ${String(secs).padStart(2, '0')}s`;
}

// Dialog flows
let pendingActivationTarget = 'canary';

export async function openActivationDialog(target) {
  pendingActivationTarget = target;
  const dialog = byID('activateProtectionDialog');
  if (!dialog) return;

  text('dialogTargetPhase', target.toUpperCase());
  const descEl = byID('dialogTargetDesc');
  if (descEl) {
    if (target === 'canary') descEl.textContent = t('stepper.canary.desc');
    else if (target === 'enforce') descEl.textContent = t('stepper.enforce.desc');
    else descEl.textContent = t('stepper.observe.desc');
  }

  // Preflight check
  const preflightRoot = byID('dialogPreflightList');
  if (preflightRoot) {
    const item = el('li', 'preflight-item preflight-loading');
    const spinner = el('span', 'preflight-spinner');
    spinner.setAttribute('aria-hidden', 'true');
    const label = el('span', 'preflight-text', t('dialog.activate.preflightRunning'));
    item.append(spinner, label);
    preflightRoot.replaceChildren(item);
  }

  try {
    const readiness = await getReleaseReadiness(target);
    renderPreflightList(preflightRoot, readiness);
    const confirmBtn = byID('btnConfirmActivation');
    if (confirmBtn) {
      confirmBtn.disabled = !readiness.ready;
    }
  } catch (err) {
    if (preflightRoot) {
      const item = el('li', 'preflight-item state-danger');
      const mark = el('span', 'preflight-mark', '!');
      const label = el('span', 'preflight-text', `${t('dialog.activate.preflightFailed')}: ${err.message || t('connection.offlineDetail')}`);
      item.append(mark, label);
      preflightRoot.replaceChildren(item);
    }
  }

  const reasonInput = byID('activationReasonInput');
  if (reasonInput) {
    reasonInput.value = '';
    setTimeout(() => reasonInput.focus(), 50);
  }

  dialog.showModal();
}

function renderPreflightList(root, readiness) {
  if (!root) return;
  root.replaceChildren();

  const checks = [
    { label: t('dialog.activate.coreOk'), ok: !readiness.blockers.some(b => b.includes('core')) },
    { label: t('dialog.activate.policyOk'), ok: !readiness.blockers.some(b => b.includes('policy')) },
    { label: t('dialog.activate.evidenceOk'), ok: !readiness.blockers.some(b => b.includes('evidence')) },
    { label: t('dialog.activate.l7Ok'), ok: !readiness.blockers.some(b => b.includes('L7')) },
    { label: t('dialog.activate.allowlistOk'), ok: !readiness.blockers.some(b => b.includes('allowlist')) },
    { label: t('dialog.activate.soakOk'), ok: !readiness.blockers.some(b => b.includes('soak')) }
  ];

  checks.forEach(c => {
    const li = el('li', `preflight-item ${c.ok ? 'state-good' : 'state-warn'}`);
    const mark = el('span', 'preflight-mark', c.ok ? '✓' : '✗');
    const txt = el('span', 'preflight-text', c.label);
    li.append(mark, txt);
    root.append(li);
  });
}

async function handleActivationSubmit(evt) {
  evt.preventDefault();
  const reasonInput = byID('activationReasonInput');
  const reason = String(reasonInput?.value || '').trim();

  if (reason.length < 8) {
    toast(t('validation.reasonMin8'), 'warning');
    return;
  }

  // Generate internal confirmation token safely based on invariant requirements
  let confirmation = `PROMOTE:${pendingActivationTarget.toUpperCase()}`;
  if (pendingActivationTarget === 'observe') {
    confirmation = 'RETURN:OBSERVE';
  }

  const dialog = byID('activateProtectionDialog');
  const submitBtn = byID('btnConfirmActivation');
  if (submitBtn) submitBtn.disabled = true;

  try {
    await transitionRelease({
      target: pendingActivationTarget,
      confirmation,
      reason
    });
    toast(t('toast.phaseChanged'), 'good');
    dialog?.close();
    // Dispatch reload event
    document.dispatchEvent(new CustomEvent('gedefense:reload'));
  } catch (err) {
    toast(err.message, 'danger', err.errorID);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

export function openEmergencyDialog() {
  const dialog = byID('emergencyStopDialog');
  if (!dialog) return;
  const reasonInput = byID('emergencyStopReasonInput');
  if (reasonInput) {
    reasonInput.value = '';
    setTimeout(() => reasonInput.focus(), 50);
  }
  dialog.showModal();
}

async function handleEmergencySubmit(evt) {
  evt.preventDefault();
  const reasonInput = byID('emergencyStopReasonInput');
  const reason = String(reasonInput?.value || '').trim();

  if (reason.length < 8) {
    toast(t('validation.emergencyReasonMin8'), 'warning');
    return;
  }

  const dialog = byID('emergencyStopDialog');
  try {
    await emergencyStop(reason);
    toast(t('toast.emergencyActive'), 'danger');
    dialog?.close();
    document.dispatchEvent(new CustomEvent('gedefense:reload'));
  } catch (err) {
    toast(err.message, 'danger', err.errorID);
  }
}

export function openClearEmergencyDialog() {
  const dialog = byID('emergencyClearDialog');
  if (!dialog) return;
  const reasonInput = byID('emergencyClearReasonInput');
  if (reasonInput) {
    reasonInput.value = '';
    setTimeout(() => reasonInput.focus(), 50);
  }
  dialog.showModal();
}

async function handleEmergencyClearSubmit(evt) {
  evt.preventDefault();
  const reasonInput = byID('emergencyClearReasonInput');
  const reason = String(reasonInput?.value || '').trim();

  if (reason.length < 8) {
    toast(t('validation.clearReasonMin8'), 'warning');
    return;
  }

  // Exact confirmation token generated safely after explicit user review
  const confirmation = 'CLEAR:EMERGENCY-STOP';
  const dialog = byID('emergencyClearDialog');

  try {
    await clearEmergencyStop(confirmation, reason);
    toast(t('toast.emergencyCleared'), 'good');
    dialog?.close();
    document.dispatchEvent(new CustomEvent('gedefense:reload'));
  } catch (err) {
    toast(err.message, 'danger', err.errorID);
  }
}
