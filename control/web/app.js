// STATUS: DIAMANT VGT SUPREME
'use strict';

// The overview threat map owns its own refresh cycle and only runs while the overview is visible.

import { startOverviewThreatMap } from './overview-map.js';
import { initOverviewConnections } from './overview-connections.js';
import { initSetupWizard } from './setup-wizard.js';
import { initCMSModule } from './cms.js';
import {
  addBlock,
  clearEmergencyStop,
  emergencyStop,
  exportForensics,
  getProfiles,
  getStatus,
  getToken,
  restartSystem,
  setToken,
  syncFeeds,
  transitionRelease,
  updateSettings
} from './api.js';
import { drawTraffic } from './charts.js';
import {
  initializeI18n,
  locale,
  setLanguage,
  t
} from './i18n.js';
import { initProtectionCenter } from './protection.js';
import { initL7Module } from './l7.js';
import { initL7IntegrationModule } from './l7-integration.js';
import { initKineticModule } from './kinetic.js';
import { initThreatIntelModule } from './threat-intel.js';
import { initXDRModule } from './xdr.js';
import { initOperationFeedback } from './operations.js';
import { initFabricSettingsTabs } from './fabric-settings.js';
import { initFabricSurface } from './fabric-surface.js';
import { initExposureModule } from './v61/exposure.js';
import { initWorkersModule } from './v61/workers.js';
import { initTLSModule } from './v61/tls.js';
import { initLPEModule } from './v61/lpe.js';
import { initEdgeModule } from './v61/edge.js';
import { initStyxModule } from './v61/v6-styx.js';
import { initTitanExecModule } from './v61/v6-titan.js';
import { initCellsModule } from './v61/v6-cells.js';
import { initLockdownModule } from './v61/v6-lockdown.js';
import { initWitnessModule } from './v61/v6-witness.js';
import {
  byID,
  renderProfiles,
  text,
  toast
} from './render.js';

import {
  connectStream,
  refresh,
  snapshot,
  updateSnapshot
} from './js/state.js';
import {
  activateView,
  dismissUndo,
  downloadJSON,
  handleActionError,
  on,
  openAuthDialog,
  populateAuthFacts,
  setAuthState,
  setRestartState,
  submitProtectionRemoval,
  undoProtectionRemoval
} from './js/navigation.js';
import {
  applySettings,
  bindHardeningActions,
  bindSettingsActions,
  bindTransactionActions,
  settingsPayload
} from './js/views_overview.js';
import {
  bindForensicActions,
  bindMalwareScanActions
} from './js/views_xdr_spyware.js';
import { bindLogsAuditActions } from './js/views_logs_audit.js';
import { initTitanModule } from './js/views_titan_styx.js';
import { initAntispywareModule } from './js/views_antispyware.js';

// authorizeSession presents a candidate key and verifies it before claiming anything.
//
// The previous flow stored whatever was typed, closed the dialog and reported success
// without ever contacting the control plane - so a wrong key produced a confirmation
// and a locked dashboard. A credential is now proven against a protected endpoint
// first, and the dialog only closes once the control plane has accepted it. On refusal
// the previous key is restored, so a failed attempt cannot silently replace a working
// session with a broken one.
async function authorizeSession() {
  const input = byID('tokenInput');
  const submit = byID('saveToken');
  const candidate = input ? String(input.value || '').trim() : '';

  if (!candidate) {
    setAuthState('rejected', t('auth.empty'));
    input?.focus();
    return;
  }

  const previous = getToken();
  setAuthState('pending', t('auth.verifying'));
  if (submit) {
    submit.setAttribute('aria-busy', 'true');
    submit.disabled = true;
  }
  setToken(candidate);

  try {
    await getStatus();
    setAuthState('accepted', t('auth.accepted'));
    byID('authDialog')?.close();
    toast(t('toast.sessionUpdated'), 'good');
    refresh();
    connectStream();
  } catch (error) {
    setToken(previous);
    const status = error && typeof error.status === 'number' ? error.status : 0;
    if (status === 401 || status === 403) {
      setAuthState('rejected', t('auth.rejected'));
    } else if (status === 0) {
      setAuthState('unreachable', t('auth.unreachable'));
    } else {
      setAuthState('unreachable', t('auth.refused').replace('{status}', String(status)));
    }
    input?.focus();
    input?.select();
  } finally {
    if (submit) {
      submit.removeAttribute('aria-busy');
      submit.disabled = false;
    }
  }
}

function bindActions() {
  document.querySelectorAll('[data-view]').forEach(button => {
    button.addEventListener('click', () => activateView(button.getAttribute('data-view')));
  });
  on('authButton', 'click', () => {
    const input = byID('tokenInput');
    if (input) input.value = getToken();
    openAuthDialog();
  });
  on('supportButton', 'click', () => byID('supportDialog')?.showModal());
  on('languageSelect', 'change', event => setLanguage(event.currentTarget.value));
  document.querySelectorAll('.copy-address').forEach(button => {
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy || '');
        toast(t('support.copied'), 'good');
      } catch (_) {
        toast(t('toast.operationFailed'), 'danger');
      }
    });
  });
  on('authForm', 'submit', event => {
    event.preventDefault();
    void authorizeSession();
  });
  // Internal restart. The platform's answer is reported verbatim, including a refusal:
  // the endpoint declines while protection is enforcing, while no supervisor would bring
  // the process back, or while the evidence ledger is unavailable, and each of those has
  // a different remedy. Paraphrasing them here would hide the one the operator needs.
  on('btnRestartControl', 'click', async () => {
    const input = byID('restartReason');
    const button = byID('btnRestartControl');
    const reason = input ? String(input.value || '').trim() : '';
    if (reason.length < 8) {
      setRestartState('rejected', t('system.restart.needsReason'));
      input?.focus();
      return;
    }
    if (button) {
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    }
    setRestartState('pending', t('system.restart.pending'));
    try {
      const result = await restartSystem(reason);
      const seconds = Math.max(1, Math.round(Number(result?.pending_milliseconds || 0) / 1000));
      setRestartState('accepted', t('system.restart.accepted', { seconds }));
      toast(t('system.restart.acceptedToast'), 'good');
    } catch (error) {
      const status = error && typeof error.status === 'number' ? error.status : 0;
      setRestartState('rejected', status === 429
        ? t('system.restart.rateLimited')
        : status === 409
          ? t('system.restart.blockedByPhase')
          : status === 503
            ? t('system.restart.unavailable')
            : (error && error.message) || t('toast.operationFailed'));
      if (button) {
        button.disabled = false;
        button.removeAttribute('aria-busy');
      }
    }
  });
  on('connectionRetry', 'click', () => {
    refresh();
    connectStream();
  });
  on('blockForm', 'submit', async event => {
    event.preventDefault();
    const target = byID('target')?.value.trim();
    const reason = byID('reason')?.value.trim();
    const ttlSeconds = Number.parseInt(byID('ttl')?.value || '3600', 10);
    try {
      await addBlock({ target, reason, ttl_seconds: ttlSeconds });
      text('actionMessage', t('message.policySet'));
      event.currentTarget.reset();
      toast(t('toast.policyActivated'), 'good');
      await refresh();
    } catch (error) {
      text('actionMessage', error.message || t('message.policyFailed'));
      handleActionError(error);
    }
  });
  on('syncFeeds', 'click', async () => {
    try {
      await syncFeeds();
      toast(t('toast.feedStarted'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
      await refresh();
    }
  });
  on('loadProfiles', 'click', async () => {
    try {
      const payload = await getProfiles();
      renderProfiles(Array.isArray(payload) ? payload : payload.profiles || []);
      toast(t('toast.profilesLoaded'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  on('exportForensics', 'click', async () => {
    try {
      const payload = await exportForensics();
      downloadJSON(`gedefense-forensics-${new Date().toISOString().replaceAll(':', '-')}.json`, payload);
      toast(t('toast.forensicsCreated'), 'good');
    } catch (error) {
      handleActionError(error);
    }
  });
  on('releaseForm', 'submit', async event => {
    event.preventDefault();
    try {
      const target = byID('releaseTarget')?.value;
      const reason = byID('releaseReason')?.value.trim();
      const confirmation = byID('releaseConfirmation')?.value.trim();
      if (!target || !reason || !confirmation) return;
      await transitionRelease({ target, reason, confirmation });
      toast(t('toast.phaseChanged'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
  on('emergencyForm', 'submit', async event => {
    event.preventDefault();
    try {
      const reason = byID('emergencyReason')?.value.trim();
      if (!reason) return;
      await emergencyStop(reason);
      toast(t('toast.emergencyActive'), 'danger');
      await refresh();
    } catch (error) {
      handleActionError(error);
      await refresh();
    }
  });
  on('emergencyClearForm', 'submit', async event => {
    event.preventDefault();
    try {
      const confirmation = byID('emergencyClearConfirmation')?.value.trim();
      const reason = byID('emergencyClearReason')?.value.trim();
      if (!confirmation || !reason) return;
      await clearEmergencyStop(confirmation, reason);
      toast(t('toast.emergencyCleared'), 'good');
      await refresh();
    } catch (error) {
      handleActionError(error);
    }
  });
  on('settingFeeds', 'change', event => {
    const auto = byID('settingAutoFeeds');
    if (auto && !event.currentTarget.checked) auto.checked = false;
  });
  on('settingAutoFeeds', 'change', event => {
    const feeds = byID('settingFeeds');
    if (feeds && event.currentTarget.checked) feeds.checked = true;
  });
  on('settingsForm', 'submit', async event => {
    event.preventDefault();
    const payload = settingsPayload();
    try {
      const saved = await updateSettings(payload);
      applySettings(saved);
      text('settingsMessage', t('message.settingsSaved'));
      toast(t('toast.settingsActivated'), 'good');
      await refresh();
    } catch (error) {
      text('settingsMessage', error.message || t('message.settingsFailed'));
      handleActionError(error);
    }
  });

  // The view-owned DOM wiring lives with its view; registration order is
  // unchanged because these calls replace the original inline blocks 1:1.
  bindHardeningActions();
  bindLogsAuditActions();
  bindMalwareScanActions();
  bindForensicActions();
  bindTransactionActions();
  bindSettingsActions();

  on('protectionRemovalForm', 'submit', event => {
    submitProtectionRemoval(event).catch(handleActionError);
  });
  on('undoAction', 'click', () => undoProtectionRemoval().catch(handleActionError));
  on('undoDismiss', 'click', dismissUndo);
  const mobileToggle = byID('mobileMenuToggle');
  const sidebar = byID('sidebar');
  const backdrop = byID('sidebarMobileBackdrop');
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = sidebar.classList.toggle('mobile-open');
      if (backdrop) backdrop.classList.toggle('active', isOpen);
    });
  }
  if (backdrop && sidebar) {
    backdrop.addEventListener('click', () => {
      sidebar.classList.remove('mobile-open');
      backdrop.classList.remove('active');
    });
  }
  on('overviewToL7Btn', 'click', () => activateView('l7'));
  on('heroProtectionAction', 'click', () => activateView('protection'));
  on('overviewFeedCard', 'click', () => activateView('threat-intel'));
  on('overviewBlockCard', 'click', () => activateView('network'));
  on('overviewAnomalyCard', 'click', () => activateView('xdr'));
  // The kinetic counters lead to the view that explains them. A row carrying the
  // navigation trail has to navigate: a control that looks like a link and does nothing
  // is the defect this row was rebuilt to avoid.
  on('overviewBansCard', 'click', () => activateView('kinetic'));
  on('overviewHitsCard', 'click', () => activateView('kinetic'));
  on('overviewPortscansCard', 'click', () => activateView('kinetic'));
  on('overviewXdrCard', 'click', () => activateView('xdr'));
  document.querySelectorAll('[data-dialog-close]').forEach(button => {
    button.addEventListener('click', () => button.closest('dialog')?.close());
  });

  document.addEventListener('gedefense:language', () => {
    const currentView = location.hash.replace('#', '') || 'overview';
    activateView(currentView);
  // A failure while starting the overview map must not take the rest of the dashboard down with it,
  // and it must not look like a quiet network: the reason is written into the panel itself.
  try {
    startOverviewThreatMap();
  } catch (error) {
    console.error('overview threat map: start failed', error);
    const host = document.getElementById('overviewMapHost');
    if (host) host.textContent = `Kartenfehler: ${error?.message || error}`;
  }
    if (snapshot) updateSnapshot(snapshot);
  });
  globalThis.addEventListener('resize', () => {
    const chart = byID('trafficChart');
    if (chart) drawTraffic(chart);
  });
}

function initialize() {
  try { initializeI18n(); } catch (_) {}
  try { initProtectionCenter(); } catch (_) {}
  try { initL7Module(); } catch (_) {}
  try { initL7IntegrationModule(); } catch (_) {}
  try { initCMSModule(); } catch (_) {}
  // The attested facts do not change during a session, so they are filled once at
  // startup rather than only on the path that opens the dialog. Populating them on a
  // single entry point left them blank whenever the surface was reached another way.
  try { populateAuthFacts(); } catch (_) {}
  try { initKineticModule(); } catch (_) {}
  try { initThreatIntelModule(); } catch (_) {}
  try { initXDRModule(); } catch (_) {}
  try { initAntispywareModule(); } catch (_) {}
  try { initTitanModule(); } catch (_) {}
  // The V6.1 modules bind their refresh/action controls before the settings
  // workbench mounts, so the shared confirmation dialog exists before the first
  // destructive action is reachable.
  try { initExposureModule(); } catch (_) {}
  try { initWorkersModule(); } catch (_) {}
  try { initTLSModule(); } catch (_) {}
  try { initLPEModule(); } catch (_) {}
  try { initEdgeModule(); } catch (_) {}
  try { initStyxModule(); } catch (_) {}
  try { initTitanExecModule(); } catch (_) {}
  try { initCellsModule(); } catch (_) {}
  try { initLockdownModule(); } catch (_) {}
  try { initWitnessModule(); } catch (_) {}
  try { initOverviewConnections(); } catch (_) {}
  try { initSetupWizard(); } catch (_) {}
  try { initOperationFeedback(); } catch (_) {}
  Promise.resolve()
    .then(() => initFabricSettingsTabs())
  .then(() => initFabricSurface())
    .catch(() => undefined);
  try { bindActions(); } catch (_) {}
  const requested = location.hash.replace('#', '');
  activateView(requested || 'overview');
  globalThis.setInterval(() => text('clock', new Date().toLocaleTimeString(locale())), 1000);
  refresh();
  connectStream();
}

document.addEventListener('DOMContentLoaded', initialize, { once: true });
