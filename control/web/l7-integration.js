// STATUS: DIAMANT VGT SUPREME
'use strict';

// Application Defense — traffic-path integration panel.
//
// Two operator actions, both read-only with respect to the host:
//
//   Self-test   sends one synthetic request through the configured inspection path and
//               reports whether the engine answered and its counter moved. It is the
//               only evidence in this view that inspection actually happens.
//   Integration generates web-server configuration for this host. It writes nothing:
//               the operator copies it, applies it and then re-runs the self-test.
//
// The panel never states that an application is protected. Detection is context; only
// a passing self-test is evidence, and even then it is evidence about one synthetic
// request, not about production traffic.

import { getL7Integration, runL7SelfTest } from './api.js';
import { t } from './i18n.js';
import { byID, el } from './render.js';

let selfTestRunning = false;
let integrationRunning = false;

export function initL7IntegrationModule() {
  const selfTestBtn = byID('btnL7SelfTest');
  if (selfTestBtn) {
    selfTestBtn.addEventListener('click', () => { void runSelfTest(); });
  }
  const integrationBtn = byID('btnL7Integration');
  if (integrationBtn) {
    integrationBtn.addEventListener('click', () => { void loadIntegration(); });
  }
  renderSelfTest(null);
}

async function runSelfTest() {
  if (selfTestRunning) return;
  selfTestRunning = true;
  const button = byID('btnL7SelfTest');
  if (button) button.disabled = true;
  renderSelfTest({ pending: true });
  try {
    renderSelfTest(await runL7SelfTest());
  } catch (error) {
    // A refusal by the platform is not a verdict about the traffic path. Reporting a
    // closed evidence gate or a rejected token as "the inspection path is not proven"
    // diagnoses the wrong subsystem and sends the operator looking in the wrong place,
    // so those cases carry their own outcome and their own wording.
    const status = error && typeof error.status === 'number' ? error.status : 0;
    renderSelfTest({
      outcome: status === 503 ? 'BLOCKED' : 'FAIL',
      detail: status === 503
        ? t('l7.integration.selfTestBlocked')
        : status === 401 || status === 403
          ? t('l7.integration.selfTestUnauthorized')
          : (error && error.message) || t('l7.integration.selfTestFailed'),
      ran: false
    });
  } finally {
    selfTestRunning = false;
    if (button) button.disabled = false;
  }
}

async function loadIntegration() {
  if (integrationRunning) return;
  integrationRunning = true;
  const button = byID('btnL7Integration');
  if (button) button.disabled = true;
  try {
    renderIntegration(await getL7Integration());
  } catch (error) {
    renderIntegration({ generated: false, reason: error && error.message ? error.message : t('l7.integration.generateFailed') });
  } finally {
    integrationRunning = false;
    if (button) button.disabled = false;
  }
}

// outcomeClass keeps the verdict readable without relying on colour alone: the text
// label beside the pill carries the same information.
function outcomeClass(outcome) {
  switch (String(outcome || '').toUpperCase()) {
    case 'PASS': return 'good';
    case 'FAIL': return 'danger';
    case 'BLOCKED': return 'warn';
    // Inspection works and forwarding cannot. That is a deployment gap rather than a
    // broken engine, and colouring it like a failure would send the operator to the
    // wrong half of the path.
    case 'UPSTREAM_UNREACHABLE': return 'warn';
    case 'DISABLED': return 'muted';
    default: return 'warn';
  }
}

function renderSelfTest(result) {
  const host = byID('l7SelfTestResult');
  if (!host) return;
  host.replaceChildren();

  if (!result) {
    host.hidden = true;
    return;
  }
  host.hidden = false;

  if (result.pending) {
    host.append(el('p', 'l7-selftest-line', t('l7.integration.selfTestRunning')));
    return;
  }

  const outcome = String(result.outcome || 'FAIL').toUpperCase();
  const head = el('div', 'l7-selftest-head');
  const pill = el('span', `status-pill ${outcomeClass(outcome)}`, outcome);
  head.append(pill);
  head.append(el('span', 'l7-selftest-path', result.path ? t('l7.integration.pathLabel') + ' ' + String(result.path).toUpperCase() : ''));
  host.append(head);

  host.append(el('p', 'l7-selftest-line', result.detail || ''));

  // The counter delta is the part that distinguishes "the socket answered" from
  // "the request was actually inspected", so it is always shown as numbers.
  const facts = el('dl', 'l7-selftest-facts');
  const addFact = (label, value) => {
    facts.append(el('dt', '', label));
    facts.append(el('dd', 'font-mono', value));
  };
  addFact(t('l7.integration.counterBefore'), String(result.requests_before ?? 0));
  addFact(t('l7.integration.counterAfter'), String(result.requests_after ?? 0));
  addFact(t('l7.integration.counterMoved'), result.counter_moved ? t('dynamic.active') : t('l7.integration.no'));
  if (result.http_status) addFact(t('l7.integration.httpStatus'), String(result.http_status));
  if (typeof result.latency_millis === 'number') addFact(t('l7.integration.latency'), `${result.latency_millis} ms`);
  if (result.engine_answer) addFact(t('l7.integration.engineAnswer'), String(result.engine_answer));

  // The forwarding leg is a separate fact from the inspection verdict, so it gets its own
  // row rather than being folded into the outcome. An operator reading PASS needs to know
  // whether the path can actually carry the traffic the inspection just approved.
  if (result.upstream) {
    addFact(t('l7.integration.upstreamLabel'), String(result.upstream));
    addFact(
      t('l7.integration.upstreamReachable'),
      result.upstream_reachable ? t('l7.integration.reachable') : t('l7.integration.unreachable')
    );
    if (result.upstream_detail) addFact(t('l7.integration.upstreamDetail'), String(result.upstream_detail));
  }
  host.append(facts);

  // The "without PASS there is no evidence" hint only applies when the test actually
  // reached a verdict. After a BLOCKED result the missing thing is a different one, and
  // repeating the traffic-path hint would misdirect the operator.
  if (outcome === 'FAIL') {
    host.append(el('p', 'l7-selftest-hint', t('l7.integration.selfTestHint')));
  }
  if (outcome === 'UPSTREAM_UNREACHABLE') {
    host.append(el('p', 'l7-selftest-hint', t('l7.integration.selfTestUpstreamHint')));
  }
}

function renderIntegration(plan) {
  const host = byID('l7IntegrationResult');
  if (!host) return;
  host.replaceChildren();
  host.hidden = false;

  if (!plan || !plan.generated) {
    host.append(el('p', 'l7-selftest-line', (plan && plan.reason) || t('l7.integration.generateFailed')));
    return;
  }

  // What was observed on this host, stated as observation.
  const detection = el('div', 'l7-integration-detect');
  detection.append(el('span', 'eyebrow', t('l7.integration.detected')));
  const list = el('ul', 'l7-integration-list');
  for (const entry of plan.detection || []) {
    list.append(el('li', '', entry));
  }
  detection.append(list);
  if (plan.socket) {
    detection.append(el('p', 'l7-selftest-line font-mono', `inspect.sock ${plan.socket}`));
  }
  if (plan.inline_socket) {
    detection.append(el('p', 'l7-selftest-line font-mono', `edge.sock ${plan.inline_socket} → ${plan.upstream}`));
  }
  host.append(detection);

  for (const warning of plan.warnings || []) {
    host.append(el('p', 'l7-integration-warning', warning));
  }

  for (const snippet of plan.snippets || []) {
    host.append(buildSnippet(snippet));
  }

  if (plan.self_test_hint) {
    host.append(el('p', 'l7-selftest-hint', plan.self_test_hint));
  }
}

function buildSnippet(snippet) {
  const wrap = el('details', 'l7-snippet');
  const summary = el('summary', '', snippet.title || snippet.target);
  wrap.append(summary);

  const steps = el('ol', 'l7-snippet-steps');
  for (const step of snippet.steps || []) {
    steps.append(el('li', '', step));
  }
  wrap.append(steps);

  for (const note of snippet.notes || []) {
    wrap.append(el('p', 'l7-snippet-note', note));
  }

  if (snippet.requires_root) {
    wrap.append(el('p', 'l7-snippet-note', t('l7.integration.requiresRoot')));
  }

  // The body is rendered as text, never as markup: it is generated content that ends
  // up in a privileged configuration file, and this panel only displays it.
  const pre = el('pre', 'l7-snippet-body mono');
  pre.textContent = snippet.body || '';
  wrap.append(pre);

  const actions = el('div', 'l7-snippet-actions');
  const copy = el('button', 'button button-quiet fs-xs', t('l7.integration.copy'));
  copy.type = 'button';
  copy.addEventListener('click', () => {
    void copySnippet(snippet.body || '', copy);
  });
  actions.append(copy);
  wrap.append(actions);

  if (snippet.verify_hint) {
    wrap.append(el('p', 'l7-snippet-note', snippet.verify_hint));
  }
  return wrap;
}

// copySnippet uses the async clipboard when the page is in a secure context and falls
// back to selecting the text, because a loopback dashboard over plain HTTP is not a
// secure context in every browser.
async function copySnippet(body, button) {
  const label = button.textContent;
  try {
    if (navigator.clipboard && globalThis.isSecureContext) {
      await navigator.clipboard.writeText(body);
      button.textContent = t('l7.integration.copied');
      setTimeout(() => { button.textContent = label; }, 1500);
      return;
    }
  } catch (error) {
    // Fall through to the selection path rather than reporting a copy that did not happen.
  }
  const area = document.createElement('textarea');
  area.value = body;
  area.setAttribute('readonly', 'readonly');
  area.className = 'l7-copy-shim';
  document.body.append(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch (error) {
    copied = false;
  }
  area.remove();
  button.textContent = copied ? t('l7.integration.copied') : t('l7.integration.copyFailed');
  setTimeout(() => { button.textContent = label; }, 1500);
}

// refreshL7IntegrationPanel is called by the view when it becomes visible, so the
// detected surface is current rather than whatever it was at page load.
export function refreshL7IntegrationPanel() {
  const host = byID('l7IntegrationResult');
  if (host && !host.hidden) {
    void loadIntegration();
  }
}

// Kept for symmetry with the other view modules; the panel holds no timer of its own.
export function disposeL7IntegrationModule() {
  selfTestRunning = false;
  integrationRunning = false;
}
