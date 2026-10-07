'use strict';

// VisionGaiaTechnology — Fabric Settings workbench.
//
// The surface is rendered entirely from the server-side settings schema
// (/api/v1/settings/schema), so the dashboard can never advertise a setting the
// backend does not enforce, and the backend can never add a setting the
// dashboard cannot render. No setting name, bound or apply class is duplicated
// in the client.
//
// Composition: a domain rail for orientation, a field editor for the primary
// task, and a docked preview sidecar for the confirmation step. Grouping is
// carried by spacing, alignment and hairlines rather than by nested containers.

import {
  getFabricSettings,
  getFabricSettingsHistory,
  getFabricSettingsSchema,
  previewFabricSettings,
  rollbackFabricSettings,
  updateFabricSettings
} from './api.js';
import { el, formatTime, toast } from './render.js';

// Presentation metadata only. Every value-bearing contract comes from the
// server schema; this table decides labels and in-view anchors.
const MODULE_PRESENTATION = {
  overview: { label: 'Overview', anchors: [{ label: 'Overview', target: 'overviewHeading' }] },
  protection: { label: 'Control', anchors: [{ label: 'Control', target: 'protectionHeading' }, { label: 'Readiness', target: 'protectionReadiness' }] },
  l7: { label: 'Live', anchors: [{ label: 'Live', target: 'l7Heading' }, { label: 'Findings', target: 'l7Findings' }] },
  xdr: { label: 'Incidents', anchors: [{ label: 'Incidents', target: 'xdrHeading' }, { label: 'Behavior', target: 'xdrBehavior' }] },
  kinetic: { label: 'Live', anchors: [{ label: 'Live', target: 'kineticHeading' }, { label: 'Sources', target: 'kineticSources' }, { label: 'Stream', target: 'kineticStream' }] },
  threat_intel: { label: 'Feeds', page: 'threat-intel', anchors: [{ label: 'Feeds', target: 'threatIntelHeading' }, { label: 'Sync Truth', target: 'threatIntelSyncState' }] },
  network: { label: 'CIDR Policies', anchors: [{ label: 'CIDR Policies', target: 'networkHeading' }, { label: 'Block Rules', target: 'networkRules' }] },
  hardening: { label: 'Posture', anchors: [{ label: 'Posture', target: 'hardeningCenterHeading' }, { label: 'Controls', target: 'hardeningInventory' }, { label: 'Transactions', target: 'hardeningTransactions' }] },
  integrity: { label: 'FIM', anchors: [{ label: 'FIM', target: 'integrityHeading' }, { label: 'Evidence', target: 'evidenceRecords' }, { label: 'Packages', target: 'packageIntegrityHealth' }] },
  boot_trust: { label: 'Attestation', page: 'boot', anchors: [{ label: 'Attestation', target: 'bootHeading' }, { label: 'Evidence', target: 'bootEvidence' }] },
  policy_trust: { label: 'Policy', page: 'policy', anchors: [{ label: 'Policy', target: 'policyHeading' }, { label: 'Trust Chain', target: 'policyTrustChain' }] },
  forensics: { label: 'Cases', anchors: [{ label: 'Cases', target: 'forensicsHeading' }, { label: 'Quarantine', target: 'quarantineHeading' }, { label: 'Register', target: 'forensicsRegister' }] },
  release: { label: 'Gates', anchors: [{ label: 'Gates', target: 'releaseHeading' }, { label: 'Promotion', target: 'releasePromotion' }, { label: 'Fail-Safe', target: 'releaseEmergencySection' }] },
  settings: { label: 'Node', anchors: [{ label: 'Node', target: 'settingsHeading' }, { label: 'Allowlist', target: 'settingsAllowlist' }] },
  system: { label: 'Diagnostics', anchors: [{ label: 'Diagnostics', target: 'systemHeading' }, { label: 'Cells', target: 'cellsHeading' }] }
};

// Modules whose Settings tab is served by the Fabric module API.
const FABRIC_MODULES = new Set(['kinetic', 'network', 'protection', 'xdr', 'l7', 'threat_intel', 'hardening', 'integrity', 'boot_trust', 'policy_trust', 'forensics', 'system']);

const FEED_ACTIONS = ['BLOCK', 'CORRELATE_ONLY', 'ANNOTATE_ONLY'];
const FEED_FORMATS = ['lines', 'json', 'ipsum'];
const CANARY_TYPES = ['SSH_KEY', 'CLOUD_CRED', 'SHADOW_BAK', 'DOTENV'];
const FEED_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

const RISK_LABEL = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' };
const RISK_TONE = { low: 'good', medium: 'warn', high: 'danger', critical: 'danger' };

const deepClone = value => JSON.parse(JSON.stringify(value));
const stable = value => JSON.stringify(value);

// Motion is a state explanation, not decoration: honour the operator's platform
// preference for reduced motion when scrolling between settings domains.
const scrollBehavior = () => {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
  } catch (_) {
    return 'auto';
  }
};

function groupNode(tag, className, textContent) {
  return el(tag, className, textContent);
}

function getPath(root, path) {
  return path.split('.').reduce((value, key) => (value == null ? undefined : value[key]), root);
}

function setPath(root, path, value) {
  const keys = path.split('.');
  let target = root;
  for (let index = 0; index < keys.length - 1; index++) {
    if (!target[keys[index]] || typeof target[keys[index]] !== 'object') target[keys[index]] = {};
    target = target[keys[index]];
  }
  target[keys[keys.length - 1]] = value;
}

function formatScalar(value) {
  if (value === null || value === undefined) return '—';
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
  if (typeof value === 'boolean') return value ? 'enabled' : 'disabled';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function moduleTitle(module) {
  const presentation = MODULE_PRESENTATION[module];
  const label = presentation ? presentation.label : module;
  return `${label} / Settings`;
}

class SettingField {
  constructor(controller, meta, path) {
    this.controller = controller;
    this.meta = meta;
    this.path = path;
  }

  describe() {
    const meta = this.meta;
    if (meta.description) return meta.description;
    return `${meta.label} (${meta.type})`;
  }
}

class FabricSettingsController {
  constructor(view, module, schemaByModule) {
    this.view = view;
    this.module = module;
    this.schema = schemaByModule;
    this.mainChildren = [...view.children];
    this.revision = 0;
    this.initial = null;
    this.draft = null;
    this.effective = null;
    this.details = {};
    this.fields = [];
    this.inputs = new Map();
    this.dirty = false;
    this.activeGroup = null;
    this.searchTerm = '';
    this.loaded = false;
    this.buildShell();
  }

  // ---------------------------------------------------------------- structure

  buildShell() {
    const presentation = MODULE_PRESENTATION[this.module] || { label: this.module, anchors: [] };
    this.tabs = groupNode('div', 'fabric-subnav');
    this.tabs.setAttribute('role', 'tablist');
    this.tabButtons = [];
    for (const anchor of presentation.anchors || []) {
      const button = groupNode('button', 'fabric-subtab', anchor.label);
      button.type = 'button';
      button.dataset.fabricTab = anchor.target;
      button.addEventListener('click', () => this.activateAnchor(anchor.target));
      this.tabs.append(button);
      this.tabButtons.push(button);
    }
    this.settingsTab = groupNode('button', 'fabric-subtab', 'Settings');
    this.settingsTab.type = 'button';
    this.settingsTab.dataset.fabricTab = 'settings';
    this.settingsTab.addEventListener('click', () => this.activateSettings());
    this.tabs.append(this.settingsTab);
    if (!(presentation.anchors || []).length) this.tabs.classList.add('fabric-subnav-solo');
    this.view.prepend(this.tabs);

    this.area = groupNode('section', 'settings-workbench');
    this.area.hidden = true;
    this.area.setAttribute('aria-label', moduleTitle(this.module));

    this.area.append(this.buildHead());
    this.area.append(this.buildBody());
    this.area.append(this.buildActions());
    this.view.append(this.area);
    this.selectTab(this.firstTabName());
  }

  firstTabName() {
    const first = this.tabs.querySelector('[data-fabric-tab]');
    return first && first.dataset.fabricTab !== 'settings' ? first.dataset.fabricTab : 'settings';
  }

  buildHead() {
    const head = groupNode('header', 'settings-head');
    const main = groupNode('div', 'settings-head-main');
    main.append(groupNode('p', 'eyebrow', 'SECURITY FABRIC CONTROL'));
    main.append(groupNode('h3', 'settings-head-title', moduleTitle(this.module)));
    this.headNote = groupNode('p', 'settings-head-note', 'Effective values are served by the running component, not by the browser.');
    main.append(this.headNote);
    head.append(main);

    this.meta = groupNode('dl', 'settings-head-meta');
    this.metaState = this.metaCell('STATUS');
    this.metaRevision = this.metaCell('REVISION');
    this.metaChange = this.metaCell('LAST CHANGE');
    this.metaProfile = this.metaCell('APPLY');
    head.append(this.meta);
    return head;
  }

  metaCell(label) {
    const wrap = groupNode('div', 'settings-meta-cell');
    wrap.append(groupNode('dt', '', label));
    const value = groupNode('dd', 'font-mono', '—');
    wrap.append(value);
    return value;
  }

  buildBody() {
    const body = groupNode('div', 'settings-body');
    this.body = body;

    const rail = groupNode('nav', 'settings-rail');
    rail.setAttribute('aria-label', 'Settings domains');
    this.searchInput = document.createElement('input');
    this.searchInput.type = 'search';
    this.searchInput.className = 'settings-search';
    this.searchInput.placeholder = 'Search settings';
    this.searchInput.setAttribute('aria-label', 'Search settings');
    this.searchInput.addEventListener('input', () => {
      this.searchTerm = this.searchInput.value.trim().toLowerCase();
      this.renderFields();
    });
    rail.append(this.searchInput);
    this.railList = groupNode('ul', 'settings-rail-list');
    rail.append(this.railList);
    this.rail = rail;

    const editor = groupNode('div', 'settings-editor');
    this.editorStatus = groupNode('p', 'settings-editor-status', 'Loading effective settings…');
    editor.append(this.editorStatus);
    this.form = groupNode('form', 'settings-form');
    this.form.addEventListener('submit', event => event.preventDefault());
    editor.append(this.form);

    this.preview = groupNode('aside', 'settings-preview');
    this.preview.hidden = true;
    this.preview.setAttribute('aria-label', 'Change preview');
    body.append(rail, editor, this.preview);
    return body;
  }

  buildActions() {
    const actions = groupNode('footer', 'settings-actions');
    this.dirtyFlag = groupNode('span', 'settings-dirty', 'NO UNSAVED CHANGES');
    actions.append(this.dirtyFlag);

    const buttons = groupNode('div', 'settings-action-buttons');
    this.discardButton = groupNode('button', 'button button-quiet', 'Discard');
    this.discardButton.type = 'button';
    this.discardButton.disabled = true;
    this.discardButton.addEventListener('click', () => this.discard());

    this.previewButton = groupNode('button', 'button button-primary', 'Preview changes');
    this.previewButton.type = 'button';
    this.previewButton.disabled = true;
    this.previewButton.addEventListener('click', () => this.runPreview());

    this.historyButton = groupNode('button', 'button button-quiet', 'Revision history');
    this.historyButton.type = 'button';
    this.historyButton.addEventListener('click', () => this.toggleHistory());
    this.historyPanel = groupNode('div', 'settings-history');
    this.historyPanel.hidden = true;
    this.historyButton.setAttribute('aria-expanded', 'false');

    buttons.append(this.discardButton, this.previewButton, this.historyButton);
    actions.append(buttons);
    const wrap = groupNode('div', 'settings-actions-wrap');
    wrap.append(actions, this.historyPanel);
    return wrap;
  }

  // syncPreviewLayout keeps the docked preview in the layout without relying on
  // the :has() selector, which is still unavailable on some operator browsers.
  syncPreviewLayout() {
    this.body.classList.toggle('has-preview', !this.preview.hidden);
  }

  // ------------------------------------------------------------------ tabbing

  selectTab(name) {
    const settingsMode = name === 'settings';
    for (const child of this.mainChildren) child.hidden = settingsMode;
    this.area.hidden = !settingsMode;
    for (const button of this.tabs.querySelectorAll('[data-fabric-tab]')) {
      const active = button.dataset.fabricTab === name;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', String(active));
    }
    if (!settingsMode && this.dirty) this.warnUnsaved();
  }

  activateAnchor(target) {
    this.selectTab(target);
    const element = document.getElementById(target);
    if (element) element.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
  }

  activateSettings() {
    if (!FABRIC_MODULES.has(this.module)) {
      toast('This module has no administrative surface in this build.', 'warning');
      return;
    }
    this.selectTab('settings');
    if (!this.loaded) this.load().catch(error => toast(error.message, 'danger', error.errorID));
  }

  warnUnsaved() {
    toast('Unsaved settings changes were kept. Use Discard or Apply in Settings.', 'warning');
  }

  // -------------------------------------------------------------------- data

  async load() {
    this.editorStatus.textContent = 'Loading effective settings…';
    const response = await getFabricSettings(this.module);
    this.revision = Number(response.revision || 0);
    this.initial = deepClone(response.settings || {});
    this.draft = deepClone(this.initial);
    this.details = response.details || {};
    this.effective = this.details.active ? deepClone(this.details.active) : deepClone(this.initial);
    this.applyState = String(response.apply_state || 'unknown');
    this.updatedAt = response.updated_at || null;
    this.loaded = true;
    this.headNote.textContent = `Source: ${response.source || 'encrypted-runtime-settings'} · Updated ${formatTime(response.updated_at)}`;
    this.renderMeta();
    this.renderFields();
    this.renderRail();
    this.updateDirtyState();
  }

  renderMeta() {
    const tone = this.applyState === 'applied' ? 'good' : this.applyState === 'restart_required' ? 'warn' : 'muted';
    this.metaState.replaceChildren(groupNode('span', `status-pill ${tone}`, this.applyState.replace(/_/g, ' ').toUpperCase()));
    this.metaRevision.textContent = String(this.revision);
    this.metaChange.textContent = this.updatedAt ? formatTime(this.updatedAt) : '—';
    const restartKeys = this.schema.filter(meta => meta.apply_class === 'RESTART');
    this.metaProfile.textContent = restartKeys.length ? `${restartKeys.length} restart-class` : 'all hot';
  }

  // ------------------------------------------------------------------ schema

  registeredGroups() {
    const order = [];
    const byGroup = new Map();
    for (const meta of this.schema) {
      if (!byGroup.has(meta.group)) {
        byGroup.set(meta.group, []);
        order.push(meta.group);
      }
      byGroup.get(meta.group).push(meta);
    }
    return order.map(group => ({ group, entries: byGroup.get(group) }));
  }

  matchesSearch(meta) {
    if (!this.searchTerm) return true;
    const haystack = `${meta.key} ${meta.label} ${meta.group} ${meta.description || ''}`.toLowerCase();
    return haystack.includes(this.searchTerm);
  }

  renderRail() {
    this.railList.replaceChildren();
    let totalShown = 0;
    for (const { group, entries } of this.registeredGroups()) {
      const visible = entries.filter(meta => this.matchesSearch(meta));
      if (!visible.length) continue;
      totalShown += visible.length;
      const item = groupNode('li', 'settings-rail-item');
      const button = groupNode('button', 'settings-rail-button', group);
      button.type = 'button';
      if (this.searchTerm) button.classList.add('active');
      button.addEventListener('click', () => {
        const section = this.form.querySelector(`[data-group="${CSS.escape(group)}"]`);
        if (section) section.scrollIntoView({ block: 'start', behavior: scrollBehavior() });
      });
      const count = groupNode('span', 'settings-rail-count', String(visible.length));
      button.append(count);
      item.append(button);
      this.railList.append(item);
    }
    if (!totalShown) {
      const empty = groupNode('li', 'settings-rail-empty', `No setting matches “${this.searchTerm}”.`);
      this.railList.append(empty);
    }
  }

  renderFields() {
    this.inputs.clear();
    this.form.replaceChildren();
    if (!this.schema.length) {
      this.editorStatus.textContent = 'No administrative schema is published for this module.';
      return;
    }
    this.editorStatus.textContent = this.searchTerm
      ? `Filtered view · matching “${this.searchTerm}”`
      : 'Changes are validated and applied server-side. Nothing is written from the browser directly.';

    const groups = this.registeredGroups();
    let rendered = 0;
    for (const { group, entries } of groups) {
      const visible = entries.filter(meta => this.matchesSearch(meta));
      if (!visible.length) continue;
      rendered += visible.length;
      const section = groupNode('section', 'settings-group');
      section.dataset.group = group;
      const head = groupNode('div', 'settings-group-head');
      head.append(groupNode('h4', 'settings-group-title', group));
      const risk = visible.reduce((worst, meta) => {
        const rank = { low: 0, medium: 1, high: 2, critical: 3 };
        return rank[meta.risk] > rank[worst] ? meta.risk : worst;
      }, 'low');
      head.append(groupNode('span', `status-pill ${RISK_TONE[risk] || 'muted'}`, `${RISK_LABEL[risk] || 'LOW'} RISK`));
      section.append(head);
      for (const meta of visible) section.append(this.renderRow(meta));
      this.form.append(section);
    }
    if (!rendered) {
      const empty = groupNode('p', 'settings-empty', `No setting matches “${this.searchTerm}”.`);
      this.form.append(empty);
    }
  }

  renderRow(meta) {
    const row = groupNode('div', 'settings-row');
    row.dataset.key = meta.key;
    // A key that is registered in the schema but absent from the served snapshot
    // is a contract violation. Surface it instead of rendering an empty control.
    if (getPath(this.draft, meta.key) === undefined) row.classList.add('is-missing');

    const labelCell = groupNode('div', 'settings-row-label');
    const title = groupNode('label', 'settings-row-title', meta.label);
    title.setAttribute('for', `fabric-${this.module}-${meta.key}`);
    labelCell.append(title);
    if (meta.description) labelCell.append(groupNode('p', 'settings-row-help', meta.description));
    const key = groupNode('code', 'settings-row-key', meta.key);
    labelCell.append(key);

    const controlCell = groupNode('div', 'settings-row-control');
    controlCell.append(this.buildControl(meta));
    controlCell.append(this.buildRowMeta(meta));

    row.append(labelCell, controlCell);
    return row;
  }

  buildRowMeta(meta) {
    const wrap = groupNode('div', 'settings-row-meta');
    wrap.append(groupNode('span', `status-pill ${meta.apply_class === 'HOT' ? 'muted' : 'warn'}`, meta.apply_class));
    wrap.append(groupNode('span', `risk-dot risk-${meta.risk}`, RISK_LABEL[meta.risk] || 'LOW'));
    const bounds = [];
    if (meta.minimum !== undefined && meta.minimum !== null) bounds.push(`min ${meta.minimum}`);
    if (meta.maximum !== undefined && meta.maximum !== null) bounds.push(`max ${meta.maximum}`);
    if (meta.unit) bounds.push(meta.unit);
    if (bounds.length) wrap.append(groupNode('span', 'settings-row-bounds', bounds.join(' · ')));
    const effectiveValue = this.effective ? getPath(this.effective, meta.key) : undefined;
    if (effectiveValue !== undefined) {
      const effective = groupNode('span', 'settings-row-effective', `effective ${formatScalar(effectiveValue)}`);
      wrap.append(effective);
    }
    return wrap;
  }

  buildControl(meta) {
    const id = `fabric-${this.module}-${meta.key}`;
    const current = getPath(this.draft, meta.key);
    let input;

    if (meta.key === 'rules') return this.buildRuleMatrix(meta);
    if (meta.key === 'feeds') return this.buildFeedMatrix(meta);
    if (meta.key === 'deception.canaries') return this.buildCanaryMatrix(meta);
    if (meta.key === 'sysctl.profiles') return this.buildSysctlProfiles(meta);

    if (meta.type === 'boolean') {
      const wrap = groupNode('div', 'settings-switch');
      input = document.createElement('input');
      input.type = 'checkbox';
      input.id = id;
      input.checked = Boolean(current);
      const track = groupNode('span', 'settings-switch-track');
      const state = groupNode('span', 'settings-switch-state', input.checked ? 'enabled' : 'disabled');
      input.addEventListener('change', () => {
        state.textContent = input.checked ? 'enabled' : 'disabled';
      });
      wrap.append(input, track, state);
      this.bindInput(meta, input);
      return wrap;
    }

    if (meta.type === 'enum') {
      input = document.createElement('select');
      input.id = id;
      for (const option of meta.enum || []) {
        const node = document.createElement('option');
        node.value = option;
        node.textContent = option;
        input.append(node);
      }
      input.value = String(current ?? (meta.default ?? ''));
      this.bindInput(meta, input);
      return input;
    }

    if (meta.type === 'list') {
      input = document.createElement('textarea');
      input.id = id;
      input.className = 'mono';
      input.rows = 6;
      input.spellcheck = false;
      input.value = Array.isArray(current) ? current.join('\n') : '';
      this.bindInput(meta, input);
      return input;
    }

    if (meta.type === 'ports' || meta.type === 'json') {
      input = document.createElement('textarea');
      input.id = id;
      input.className = 'mono';
      input.rows = meta.type === 'json' ? 10 : 3;
      input.spellcheck = false;
      input.value = Array.isArray(current) ? current.join(', ') : JSON.stringify(current ?? null, null, 2);
      this.bindInput(meta, input);
      return input;
    }

    input = document.createElement('input');
    input.id = id;
    input.type = meta.type === 'integer' ? 'number' : 'text';
    if (meta.type === 'integer') {
      if (meta.minimum !== undefined && meta.minimum !== null) input.min = String(meta.minimum);
      if (meta.maximum !== undefined && meta.maximum !== null) input.max = String(meta.maximum);
      input.step = '1';
      input.inputMode = 'numeric';
    }
    input.spellcheck = false;
    input.value = current === undefined || current === null ? '' : String(current);
    this.bindInput(meta, input);
    return input;
  }

  buildRuleMatrix(meta) {
    const wrap = groupNode('div', 'settings-rules');
    const catalog = Array.isArray(this.details.rule_registry) ? this.details.rule_registry : [];
    const overrides = new Map();
    for (const entry of Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []) {
      overrides.set(entry.id, entry);
    }
    const table = document.createElement('table');
    table.className = 'table-compact settings-rule-table';
    const head = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const label of ['Rule', 'Category', 'Score', 'Confidence', 'Block eligible', 'Overridden']) {
      const cell = document.createElement('th');
      cell.textContent = label;
      headRow.append(cell);
    }
    head.append(headRow);
    table.append(head);

    const body = document.createElement('tbody');
    const ids = catalog.length ? catalog.map(entry => entry.id) : [...overrides.keys()].sort();
    for (const id of ids) {
      const base = catalog.find(entry => entry.id === id) || { id, score: 0, confidence: 0, category: '—', summary: '' };
      const override = overrides.get(id);
      const row = document.createElement('tr');
      if (override) row.classList.add('is-overridden');

      const nameCell = document.createElement('th');
      nameCell.scope = 'row';
      nameCell.append(groupNode('code', 'font-mono fs-xs', id));
      if (base.summary) nameCell.append(groupNode('span', 'settings-rule-summary', base.summary));
      row.append(nameCell);

      const categoryCell = document.createElement('td');
      categoryCell.append(groupNode('span', 'text-muted fs-xs', base.category || '—'));
      row.append(categoryCell);

      const enabled = override ? override.enabled : true;
      const scoreInput = document.createElement('input');
      scoreInput.type = 'number';
      scoreInput.min = '1';
      scoreInput.max = '250';
      scoreInput.className = 'settings-rule-number';
      scoreInput.value = String(override ? override.score : base.score);
      scoreInput.setAttribute('aria-label', `Score for ${id}`);

      const confidenceInput = document.createElement('input');
      confidenceInput.type = 'number';
      confidenceInput.min = '1';
      confidenceInput.max = '100';
      confidenceInput.className = 'settings-rule-number';
      confidenceInput.value = String(override ? override.confidence : (base.confidence || 50));
      confidenceInput.setAttribute('aria-label', `Confidence for ${id}`);

      const alertOnly = document.createElement('input');
      alertOnly.type = 'checkbox';
      alertOnly.checked = Boolean(override && override.alert_only);
      alertOnly.setAttribute('aria-label', `Keep ${id} out of block decisions`);

      const toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.checked = enabled;
      toggle.setAttribute('aria-label', `Enable ${id}`);

      const scoreCell = document.createElement('td');
      scoreCell.append(scoreInput);
      const confidenceCell = document.createElement('td');
      confidenceCell.append(confidenceInput);
      const blockCell = document.createElement('td');
      blockCell.className = 'text-center';
      blockCell.append(alertOnly);
      const toggleCell = document.createElement('td');
      toggleCell.className = 'text-center';
      toggleCell.append(toggle);
      row.append(scoreCell, confidenceCell, blockCell, toggleCell);
      body.append(row);

      const commit = () => {
        const list = Array.isArray(getPath(this.draft, meta.key)) ? [...getPath(this.draft, meta.key)] : [];
        const index = list.findIndex(entry => entry.id === id);
        const atDefault = toggle.checked && Number(scoreInput.value) === (base.score || 0) && Number(confidenceInput.value) === (base.confidence || 0) && !alertOnly.checked;
        if (atDefault) {
          if (index >= 0) list.splice(index, 1);
        } else {
          const entry = {
            id,
            enabled: toggle.checked,
            score: Number(scoreInput.value),
            confidence: Number(confidenceInput.value),
            alert_only: alertOnly.checked
          };
          if (index >= 0) list[index] = entry;
          else list.push(entry);
        }
        list.sort((a, b) => (a.id < b.id ? -1 : 1));
        setPath(this.draft, meta.key, list);
        row.classList.toggle('is-overridden', list.some(entry => entry.id === id));
        this.updateDirtyState();
      };
      for (const control of [scoreInput, confidenceInput, alertOnly, toggle]) {
        control.addEventListener('change', commit);
      }
    }
    table.append(body);
    wrap.append(table);
    wrap.append(groupNode('p', 'settings-row-help', `${ids.length} built-in signatures. Patterns are read-only; enablement, score, confidence and block eligibility are administrable.`));
    return wrap;
  }

  // buildFeedMatrix renders the structured feed source model. Each row is one
  // administrable source with its live generation state beside it, so the
  // operator configures and observes in the same place instead of reading a raw
  // JSON payload.
  buildFeedMatrix(meta) {
    const wrap = groupNode('div', 'settings-feeds');
    const current = Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : [];
    const runtime = (this.details.runtime && Array.isArray(this.details.runtime.feeds)) ? this.details.runtime.feeds : [];
    const stateByID = new Map(runtime.map(entry => [entry.id, entry]));

    const table = document.createElement('table');
    table.className = 'table-compact settings-feed-table';
    const head = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const label of ['On', 'Source', 'Destination', 'Format', 'Action', 'Priority', 'Trust', 'Bounds', 'Generation', '']) {
      const cell = document.createElement('th');
      cell.textContent = label;
      headRow.append(cell);
    }
    head.append(headRow);
    table.append(head);

    const body = document.createElement('tbody');
    const commit = list => {
      setPath(this.draft, meta.key, list);
      this.updateDirtyState();
    };

    current.forEach((feed, index) => {
      const row = document.createElement('tr');
      const controls = [];
      const update = (field, parse) => {
        const list = (Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).map(entry => ({ ...entry }));
        if (!list[index]) return;
        list[index][field] = parse();
        commit(list);
      };

      const enabled = document.createElement('input');
      enabled.type = 'checkbox';
      enabled.checked = Boolean(feed.enabled);
      enabled.setAttribute('aria-label', `Enable feed ${feed.id}`);
      enabled.addEventListener('change', () => update('enabled', () => enabled.checked));
      const enabledCell = document.createElement('td');
      enabledCell.className = 'text-center';
      enabledCell.append(enabled);
      controls.push(enabled);

      const name = document.createElement('input');
      name.type = 'text';
      name.className = 'settings-feed-name';
      name.maxLength = 96;
      name.value = feed.name || '';
      name.setAttribute('aria-label', `Name for feed ${feed.id}`);
      name.addEventListener('change', () => update('name', () => name.value.trim()));
      const id = groupNode('code', 'font-mono fs-xs settings-feed-id', feed.id);
      const sourceCell = document.createElement('td');
      sourceCell.append(name, id);
      controls.push(name);

      const url = document.createElement('input');
      url.type = 'text';
      url.className = 'settings-feed-url mono';
      url.spellcheck = false;
      url.value = feed.url || '';
      url.setAttribute('aria-label', `URL for feed ${feed.id}`);
      url.addEventListener('change', () => update('url', () => url.value.trim()));
      const destinationCell = document.createElement('td');
      destinationCell.append(url);
      controls.push(url);

      const selectFor = (values, value, label, field) => {
        const select = document.createElement('select');
        select.className = 'settings-feed-select';
        select.setAttribute('aria-label', `${label} for feed ${feed.id}`);
        for (const option of values) {
          const node = document.createElement('option');
          node.value = option;
          node.textContent = option;
          select.append(node);
        }
        select.value = value;
        select.addEventListener('change', () => update(field, () => select.value));
        controls.push(select);
        return select;
      };
      const formatCell = document.createElement('td');
      formatCell.append(selectFor(FEED_FORMATS, feed.format || 'lines', 'Format', 'format'));
      const actionCell = document.createElement('td');
      actionCell.append(selectFor(FEED_ACTIONS, feed.action || 'CORRELATE_ONLY', 'Action', 'action'));

      const numberFor = (value, label, field, min, max) => {
        const input = document.createElement('input');
        input.type = 'number';
        input.className = 'settings-feed-number';
        input.min = String(min);
        input.max = String(max);
        input.value = String(value ?? 0);
        input.setAttribute('aria-label', `${label} for feed ${feed.id}`);
        input.addEventListener('change', () => update(field, () => Number(input.value)));
        controls.push(input);
        return input;
      };
      const priorityCell = document.createElement('td');
      priorityCell.append(numberFor(feed.priority, 'Priority', 'priority', 0, 1000000));
      const trustCell = document.createElement('td');
      trustCell.append(numberFor(feed.trust_weight ?? 100, 'Trust weight', 'trust_weight', 1, 1000));

      const boundsCell = document.createElement('td');
      const bounds = groupNode('div', 'settings-feed-bounds');
      const override = (label, value, field, min, max) => {
        const field_ = groupNode('label', 'settings-feed-override');
        field_.append(groupNode('span', '', label));
        field_.append(numberFor(value, label, field, min, max));
        return field_;
      };
      bounds.append(override('refresh', feed.refresh_minutes, 'refresh_minutes', 0, 1440));
      bounds.append(override('entries', feed.max_entries, 'max_entries', 0, 5000000));
      bounds.append(override('bytes', feed.max_download_bytes, 'max_download_bytes', 0, 67108864));
      boundsCell.append(bounds);

      const live = stateByID.get(feed.id);
      const generationCell = document.createElement('td');
      generationCell.className = 'settings-feed-state';
      if (live) {
        const tone = live.status === 'OK' ? 'good' : live.status === 'ERROR' || live.status === 'CRITICAL' ? 'danger' : 'warn';
        generationCell.append(groupNode('span', `status-pill ${tone}`, String(live.status || 'UNKNOWN')));
        generationCell.append(groupNode('span', 'font-mono fs-xs', `${live.last_good_count || 0} · gen ${live.last_good_gen || 0}`));
        if (live.last_error) generationCell.append(groupNode('span', 'settings-feed-error', String(live.last_error)));
      } else {
        generationCell.append(groupNode('span', 'status-pill muted', 'NOT SYNCED'));
      }

      const removeCell = document.createElement('td');
      removeCell.className = 'text-center';
      const remove = groupNode('button', 'button button-quiet fs-xs', 'Remove');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove feed ${feed.id}`);
      remove.addEventListener('click', () => {
        const list = (Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).filter((_, position) => position !== index);
        commit(list);
        this.renderFields();
      });
      removeCell.append(remove);

      row.append(enabledCell, sourceCell, destinationCell, formatCell, actionCell, priorityCell, trustCell, boundsCell, generationCell, removeCell);
      body.append(row);
    });

    table.append(body);
    wrap.append(table);
    wrap.append(groupNode('p', 'settings-row-help',
      `${current.length} of 256 sources. Priority decides evaluation order; trust weight breaks ties. Bounds set to 0 inherit the global value. HTTPS, port 443, public-host and anti-poisoning checks are enforced unconditionally.`));

    const add = groupNode('button', 'button button-quiet mt-sm', 'Add feed source');
    add.type = 'button';
    add.addEventListener('click', () => {
      const list = (Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).map(entry => ({ ...entry }));
      if (list.length >= 256) {
        toast('The feed limit of 256 sources is reached.', 'warning');
        return;
      }
      let suffix = list.length + 1;
      let candidate = `feed-${suffix}`;
      const existing = new Set(list.map(entry => entry.id));
      while (existing.has(candidate)) {
        suffix += 1;
        candidate = `feed-${suffix}`;
      }
      list.push({
        id: candidate, name: `Feed ${suffix}`, enabled: false, url: 'https://',
        format: 'lines', action: 'CORRELATE_ONLY', priority: (list.length + 1) * 10,
        trust_weight: 100, refresh_minutes: 0, max_entries: 0, max_download_bytes: 0
      });
      commit(list);
      this.renderFields();
    });
    wrap.append(add);

    this.runtimeFeedState = stateByID;
    return wrap;
  }

  // buildCanaryMatrix renders the decoy grid as a matrix. A canary path that is
  // silently wrong disables a decoy without any visible failure, so the enrolled
  // state reported by the engine sits next to every row.
  buildCanaryMatrix(meta) {
    const wrap = groupNode('div', 'settings-feeds');
    const current = Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : [];
    const enrolled = new Map(
      (Array.isArray(this.details.canaries) ? this.details.canaries : []).map(entry => [entry.path, entry])
    );

    const table = document.createElement('table');
    table.className = 'table-compact settings-feed-table';
    const head = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const label of ['On', 'Decoy path', 'Type', 'Owner UID', 'Mode', 'Enrolled', '']) {
      const cell = document.createElement('th');
      cell.textContent = label;
      headRow.append(cell);
    }
    head.append(headRow);
    table.append(head);

    const body = document.createElement('tbody');
    const commit = list => {
      setPath(this.draft, meta.key, list);
      this.updateDirtyState();
    };

    current.forEach((canary, index) => {
      const row = document.createElement('tr');
      const update = (field, parse) => {
        const list = (Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).map(entry => ({ ...entry }));
        if (!list[index]) return;
        list[index][field] = parse();
        commit(list);
      };

      const enabled = document.createElement('input');
      enabled.type = 'checkbox';
      enabled.checked = Boolean(canary.enabled);
      enabled.setAttribute('aria-label', `Enable canary ${canary.path}`);
      enabled.addEventListener('change', () => update('enabled', () => enabled.checked));
      const enabledCell = document.createElement('td');
      enabledCell.className = 'text-center';
      enabledCell.append(enabled);

      const path = document.createElement('input');
      path.type = 'text';
      path.className = 'settings-feed-url mono';
      path.spellcheck = false;
      path.value = canary.path || '';
      path.setAttribute('aria-label', `Path of canary ${index + 1}`);
      path.addEventListener('change', () => update('path', () => path.value.trim()));
      const pathCell = document.createElement('td');
      pathCell.append(path);

      const typeSelect = document.createElement('select');
      typeSelect.className = 'settings-feed-select';
      typeSelect.setAttribute('aria-label', `Type of canary ${canary.path}`);
      for (const option of CANARY_TYPES) {
        const node = document.createElement('option');
        node.value = option;
        node.textContent = option;
        typeSelect.append(node);
      }
      typeSelect.value = canary.type || 'CLOUD_CRED';
      typeSelect.addEventListener('change', () => update('type', () => typeSelect.value));
      const typeCell = document.createElement('td');
      typeCell.append(typeSelect);

      const numberFor = (value, label, field, min, max) => {
        const input = document.createElement('input');
        input.type = 'number';
        input.className = 'settings-feed-number';
        input.min = String(min);
        input.max = String(max);
        input.value = String(value ?? 0);
        input.setAttribute('aria-label', `${label} for canary ${canary.path}`);
        input.addEventListener('change', () => update(field, () => Number(input.value)));
        return input;
      };
      const uidCell = document.createElement('td');
      uidCell.append(numberFor(canary.owner_uid, 'Owner UID', 'owner_uid', 0, 4294967295));
      const modeCell = document.createElement('td');
      const modeInput = numberFor(canary.file_mode ?? 384, 'Mode', 'file_mode', 1, 511);
      modeCell.append(modeInput);

      const live = enrolled.get(canary.path);
      const enrolledCell = document.createElement('td');
      enrolledCell.className = 'settings-feed-state';
      if (live) {
        enrolledCell.append(groupNode('span', 'status-pill good', 'ENROLLED'));
        enrolledCell.append(groupNode('span', 'font-mono fs-xs', String(live.token_id || '').slice(0, 12)));
      } else {
        enrolledCell.append(groupNode('span', 'status-pill warn', canary.enabled ? 'PENDING APPLY' : 'DISABLED'));
      }

      const removeCell = document.createElement('td');
      removeCell.className = 'text-center';
      const remove = groupNode('button', 'button button-quiet fs-xs', 'Remove');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove canary ${canary.path}`);
      remove.addEventListener('click', () => {
        commit((Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).filter((_, position) => position !== index));
        this.renderFields();
      });
      removeCell.append(remove);

      row.append(enabledCell, pathCell, typeCell, uidCell, modeCell, enrolledCell, removeCell);
      body.append(row);
    });

    table.append(body);
    wrap.append(table);
    wrap.append(groupNode('p', 'settings-row-help',
      `${current.length} of 128 decoys. Every path must live under an allowed root; the backend rejects the revision otherwise. Mode is an octal permission mask written as a decimal integer (for example 384 is 0600).`));

    const add = groupNode('button', 'button button-quiet mt-sm', 'Add decoy');
    add.type = 'button';
    add.addEventListener('click', () => {
      const list = (Array.isArray(getPath(this.draft, meta.key)) ? getPath(this.draft, meta.key) : []).map(entry => ({ ...entry }));
      if (list.length >= 128) {
        toast('The decoy limit of 128 canaries is reached.', 'warning');
        return;
      }
      list.push({ path: '/tmp/.decoy_credential', type: 'CLOUD_CRED', enabled: false, owner_uid: 1000, file_mode: 384 });
      commit(list);
      this.renderFields();
    });
    wrap.append(add);
    return wrap;
  }

  // buildSysctlProfiles renders the profile editor together with the closed
  // control vocabulary the backend actually accepts, so a profile can never
  // reference a control the engine will refuse.
  buildSysctlProfiles(meta) {
    const wrap = groupNode('div', 'settings-rules');
    const catalog = Array.isArray(this.details.sysctl_controls) ? this.details.sysctl_controls : [];
    if (catalog.length) {
      const chips = groupNode('div', 'settings-control-catalog');
      chips.append(groupNode('p', 'settings-row-help', 'Allowed controls (the kernel keys and values are fixed by the backend):'));
      const list = groupNode('div', 'settings-chip-row');
      for (const entry of catalog) {
        const chip = groupNode('span', 'settings-chip', String(entry.id));
        chip.title = Array.isArray(entry.keys) ? entry.keys.join('\n') : '';
        list.append(chip);
      }
      chips.append(list);
      wrap.append(chips);
    }
    const input = document.createElement('textarea');
    input.id = `fabric-${this.module}-${meta.key}`;
    input.className = 'mono';
    input.rows = 10;
    input.spellcheck = false;
    input.value = JSON.stringify(getPath(this.draft, meta.key) ?? null, null, 2);
    this.bindInput(meta, input);
    wrap.append(input);
    return wrap;
  }

  bindInput(meta, input) {
    const commit = () => {
      const value = this.readControl(meta, input);
      if (value instanceof Error) {
        input.setCustomValidity(value.message);
        this.editorStatus.textContent = `${meta.label}: ${value.message}`;
        return;
      }
      input.setCustomValidity('');
      setPath(this.draft, meta.key, value);
      this.updateDirtyState();
    };
    input.addEventListener('input', commit);
    input.addEventListener('change', commit);
    this.inputs.set(meta.key, { meta, input });
  }

  readControl(meta, input) {
    try {
      if (meta.type === 'boolean') return Boolean(input.checked);
      if (meta.type === 'integer') {
        const raw = String(input.value).trim();
        if (raw === '') return new Error('a value is required');
        const value = Number(raw);
        if (!Number.isFinite(value) || !Number.isInteger(value)) return new Error('an integer is required');
        if (meta.minimum !== undefined && meta.minimum !== null && value < meta.minimum) return new Error(`must be at least ${meta.minimum}`);
        if (meta.maximum !== undefined && meta.maximum !== null && value > meta.maximum) return new Error(`must be at most ${meta.maximum}`);
        return value;
      }
      if (meta.type === 'list') {
        return String(input.value || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      }
      if (meta.type === 'ports') {
        const ports = String(input.value || '').split(/[,\s]+/).map(part => part.trim()).filter(Boolean).map(Number);
        if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return new Error('ports must be integers between 1 and 65535');
        return ports;
      }
      if (meta.type === 'json') return JSON.parse(String(input.value || 'null'));
      return String(input.value ?? '');
    } catch (error) {
      return new Error(error.message);
    }
  }

  // ------------------------------------------------------------- dirty state

  updateDirtyState() {
    this.dirty = this.initial !== null && stable(this.initial) !== stable(this.draft);
    this.discardButton.disabled = !this.dirty;
    this.previewButton.disabled = !this.dirty;
    this.dirtyFlag.textContent = this.dirty ? 'UNSAVED CHANGES' : 'NO UNSAVED CHANGES';
    this.dirtyFlag.classList.toggle('is-dirty', this.dirty);
    this.area.classList.toggle('has-unsaved', this.dirty);
    if (!this.dirty) this.preview.hidden = true;
    this.syncPreviewLayout();
  }

  discard() {
    this.draft = deepClone(this.initial);
    this.preview.hidden = true;
    this.renderFields();
    this.updateDirtyState();
    this.editorStatus.textContent = `Revision ${this.revision} restored locally.`;
  }

  // ---------------------------------------------------------------- preview

  async runPreview() {
    try {
      const preview = await previewFabricSettings(this.module, this.revision, this.draft);
      this.renderPreview(preview);
    } catch (error) {
      this.editorStatus.textContent = `Preview rejected: ${error.message}`;
      toast(error.message, 'danger', error.errorID);
    }
  }

  renderPreview(preview) {
    this.preview.replaceChildren();
    this.preview.hidden = false;
    this.syncPreviewLayout();

    const head = groupNode('div', 'settings-preview-head');
    const title = groupNode('div', 'settings-preview-title');
    title.append(groupNode('p', 'eyebrow m-0', 'EFFECTIVE DIFF'));
    title.append(groupNode('h4', 'm-0', `${preview.diff ? preview.diff.length : 0} change(s)`));
    head.append(title);
    head.append(groupNode('span', `status-pill ${RISK_TONE[preview.highest_risk] || 'muted'}`, `${RISK_LABEL[preview.highest_risk] || 'LOW'} RISK`));
    const close = groupNode('button', 'button button-quiet', '✕');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close preview');
    close.addEventListener('click', () => {
      this.preview.hidden = true;
      this.syncPreviewLayout();
    });
    head.append(close);
    this.preview.append(head);

    const list = groupNode('div', 'settings-diff');
    for (const diff of preview.diff || []) {
      const row = groupNode('div', 'settings-diff-row');
      row.append(groupNode('code', 'settings-diff-key', diff.key));
      const values = groupNode('div', 'settings-diff-values');
      values.append(groupNode('span', 'settings-diff-old', formatScalar(diff.old_value)));
      values.append(groupNode('span', 'settings-diff-arrow', '→'));
      values.append(groupNode('span', 'settings-diff-new', formatScalar(diff.new_value)));
      row.append(values);
      row.append(groupNode('span', `status-pill ${RISK_TONE[diff.risk] || 'muted'}`, `${diff.apply_class}`));
      list.append(row);
    }
    if (!(preview.diff || []).length) list.append(groupNode('p', 'settings-empty', 'No effective change.'));
    this.preview.append(list);

    const facts = groupNode('dl', 'settings-preview-facts');
    const fact = (label, value) => {
      const wrap = groupNode('div', 'settings-meta-cell');
      wrap.append(groupNode('dt', '', label));
      wrap.append(groupNode('dd', '', value));
      facts.append(wrap);
    };
    fact('RESTART', preview.requires_restart ? 'Required' : 'Not required');
    fact('OPERATOR STATE', 'Preserved');
    fact('REVISION', `${preview.current_revision} → ${preview.current_revision + 1}`);
    this.preview.append(facts);

    if (preview.requires_restart) {
      this.preview.append(groupNode('p', 'settings-warning', 'Part of this revision is restart-class: the persisted values activate when the component next starts, and the module will report restart-required until then.'));
    }

    const apply = groupNode('button', 'button button-primary', 'Apply revision');
    apply.type = 'button';
    apply.disabled = !(preview.diff || []).length;
    apply.addEventListener('click', () => this.apply());
    this.preview.append(apply);
  }

  async apply() {
    try {
      const response = await updateFabricSettings(this.module, this.revision, this.draft);
      this.preview.hidden = true;
      this.syncPreviewLayout();
      toast(`${moduleTitle(this.module)} revision ${response.revision} applied`, 'good');
      await this.load();
      document.dispatchEvent(new CustomEvent('gedefense:reload', { detail: { module: this.module } }));
    } catch (error) {
      this.editorStatus.textContent = `Apply rejected: ${error.message}`;
      toast(error.message, 'danger', error.errorID);
    }
  }

  // ---------------------------------------------------------------- history

  toggleHistory() {
    this.historyPanel.hidden = !this.historyPanel.hidden;
    this.historyButton.setAttribute('aria-expanded', String(!this.historyPanel.hidden));
    if (!this.historyPanel.hidden) this.loadHistory().catch(error => toast(error.message, 'danger', error.errorID));
  }

  async loadHistory() {
    const result = await getFabricSettingsHistory();
    const current = Number(result.current_revision || 0);
    this.historyPanel.replaceChildren();
    const head = groupNode('div', 'settings-history-head');
    head.append(groupNode('p', 'eyebrow m-0', 'CONFIG HISTORY'));
    head.append(groupNode('span', 'text-muted fs-xs', `current revision ${current}`));
    this.historyPanel.append(head);
    const list = groupNode('ul', 'settings-history-list');
    for (const entry of result.history || []) {
      const item = groupNode('li', 'settings-history-item');
      item.append(groupNode('span', 'font-mono fs-xs', `REV ${entry.revision}`));
      item.append(groupNode('span', 'text-muted fs-xs', formatTime(entry.updated_at)));
      const restore = groupNode('button', 'button button-quiet fs-xs', 'Restore');
      restore.type = 'button';
      restore.disabled = Number(entry.revision) === current;
      restore.addEventListener('click', () => this.rollback(Number(entry.revision)));
      item.append(restore);
      list.append(item);
    }
    if (!(result.history || []).length) list.append(groupNode('li', 'settings-history-item', 'No earlier revision is retained.'));
    this.historyPanel.append(list);
  }

  async rollback(revision) {
    try {
      const result = await rollbackFabricSettings(revision);
      toast(`Revision ${revision} restored as revision ${result.revision}`, 'good');
      await this.load();
      await this.loadHistory();
      document.dispatchEvent(new CustomEvent('gedefense:reload', { detail: { module: this.module } }));
    } catch (error) {
      toast(error.message, 'danger', error.errorID);
    }
  }
}

const controllers = new Map();
let schemaCache = null;
let schemaPromise = null;

async function loadSchema() {
  if (schemaCache) return schemaCache;
  if (!schemaPromise) {
    schemaPromise = getFabricSettingsSchema()
      .then(payload => {
        schemaCache = payload;
        return payload;
      })
      .catch(() => ({ modules: [], settings: [] }));
  }
  return schemaPromise;
}

// initFabricSettingsTabs mounts the internal sub-navigation and the Settings
// workbench into every main module view. The settings schema is fetched once
// and shared by all controllers.
export async function initFabricSettingsTabs() {
  const schema = await loadSchema();
  const byModule = new Map();
  for (const meta of schema.settings || []) {
    if (!byModule.has(meta.module)) byModule.set(meta.module, []);
    byModule.get(meta.module).push(meta);
  }
  // FABRIC_MODULES is the authority for which views expose a Settings tab. It
  // previously iterated every presentation entry, which mounted an empty Settings
  // tab on the five views that have no administrable namespace at all.
  for (const module of FABRIC_MODULES) {
    const presentation = MODULE_PRESENTATION[module];
    if (!presentation) continue;
    const page = presentation.page || module;
    const view = document.querySelector(`.view[data-page="${page}"]`);
    if (!view || controllers.has(module)) continue;
    const moduleSchema = byModule.get(module) || [];
    if (!moduleSchema.length) continue;
    controllers.set(module, new FabricSettingsController(view, module, moduleSchema));
  }
}

// refreshFabricModule re-reads one module after a stream event announced a
// settings revision change.
export function refreshFabricModule(module) {
  const controller = controllers.get(module);
  if (!controller || !controller.loaded) return;
  controller.load().catch(() => undefined);
}

window.addEventListener('beforeunload', event => {
  for (const controller of controllers.values()) {
    if (controller.dirty && !controller.area.hidden) {
      event.preventDefault();
      event.returnValue = '';
      return '';
    }
  }
  return undefined;
});
