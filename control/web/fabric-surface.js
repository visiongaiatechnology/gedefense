'use strict';

// STATUS: DIAMANT VGT SUPREME
//
// Global Fabric control-plane surface: search across every administrable key,
// configuration drift, signed export and the two-stage import.
//
// Plan reference sections 36 to 39. The import is deliberately two-stage: a
// bundle is verified, parsed and diffed before it can be applied, and the apply
// carries the token the preview issued. There is no import-to-apply shortcut, and
// the module never fabricates a result it did not observe.

import {
  applyFabricImport,
  exportFabricSettings,
  getFabricDrift,
  getFabricSettingsHistory,
  previewFabricImport,
  searchFabricSettings
} from './api.js';
import { t } from './i18n.js';

const SEARCH_DEBOUNCE_MS = 220;
const SEARCH_MIN_CHARS = 2;

let pending = null;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function byId(id) {
  return document.getElementById(id);
}

function setStatus(element, kind, message) {
  if (!element) return;
  element.className = `fabric-surface-status ${kind}`;
  element.textContent = message;
}

// formatValue renders a telemetry value without ever printing "[object Object]".
function formatValue(value) {
  if (value === undefined || value === null) return '---';
  if (Array.isArray(value)) return `${value.length}`;
  if (typeof value === 'object') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? t('fabric.valueOn') : t('fabric.valueOff');
  return String(value);
}

// ---------------------------------------------------------------- search

function renderSearchResults(payload) {
  const body = byId('fabricSearchResults');
  if (!body) return;
  const hits = Array.isArray(payload?.hits) ? payload.hits : [];
  if (!hits.length) {
    body.replaceChildren(node('p', 'empty-note', t('fabric.searchEmpty')));
    return;
  }
  const rows = hits.map(hit => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'fabric-search-hit';
    // The trail is what tells the operator this jumps into the module's own
    // Settings tab, where the value can actually be changed.
    row.append(node('span', 'fabric-hit-path', `${hit.module} › ${hit.group}`));
    row.append(node('span', 'fabric-hit-label', hit.label));
    row.append(node('span', 'fabric-hit-value font-mono', formatValue(hit.value)));
    const tags = node('span', 'fabric-hit-tags');
    if (hit.apply_class === 'restart') {
      tags.append(node('span', 'status-pill warn', t('fabric.tagRestart')));
    }
    if (hit.risk === 'critical' || hit.risk === 'high') {
      tags.append(node('span', 'status-pill muted', t('fabric.tagRisk', { level: String(hit.risk).toUpperCase() })));
    }
    tags.append(node('span', 'fabric-hit-why', t(`fabric.match.${hit.highlight}`)));
    row.append(tags);
    row.addEventListener('click', () => openModuleSettings(hit));
    return row;
  });
  body.replaceChildren(...rows);
}

function openModuleSettings(hit) {
  const target = document.querySelector(`.view[data-page="${hit.module}"]`);
  if (!target) return;
  document.querySelectorAll('.view').forEach(view => {
    view.hidden = view !== target;
    view.classList.toggle('active', view === target);
  });
  const tab = target.querySelector('.fabric-subtab[data-fabric-tab="settings"]');
  if (tab) tab.click();
  const field = byId(`fabric-${hit.module}-${hit.key}`);
  if (field) {
    field.scrollIntoView({ block: 'center', behavior: 'smooth' });
    field.focus({ preventScroll: true });
  }
}

// ---------------------------------------------------------------- drift

function renderDrift(payload) {
  const pill = byId('fabricDriftPill');
  const list = byId('fabricDriftFindings');
  if (!pill || !list) return;
  const status = String(payload?.status || 'UNKNOWN');
  const findings = Array.isArray(payload?.findings) ? payload.findings : [];
  pill.textContent = status === 'SYSTEM_NOMINAL' ? t('fabric.driftNominal') : t('fabric.driftDetected');
  pill.className = `status-pill ${status === 'SYSTEM_NOMINAL' ? 'good' : 'warn'}`;
  if (!findings.length) {
    list.replaceChildren(node('p', 'empty-note', t('fabric.driftClear')));
    return;
  }
  list.replaceChildren(...findings.map(finding => {
    const row = node('div', 'fabric-drift-row');
    row.append(node('span', 'fabric-drift-module font-mono', finding.module));
    row.append(node('span', 'status-pill warn', finding.apply_state));
    row.append(node('span', 'fabric-drift-detail', finding.detail));
    return row;
  }));
}

// ---------------------------------------------------------------- import

function renderImportPreview(payload) {
  const target = byId('fabricImportPreview');
  if (!target) return;
  const diff = Array.isArray(payload?.diff) ? payload.diff : [];
  const rows = diff.map(change => {
    const row = node('tr', 'fabric-diff-row');
    row.append(node('td', 'font-mono fs-xs', change.key));
    row.append(node('td', 'font-mono fs-xs', formatValue(change.old_value)));
    row.append(node('td', 'font-mono fs-xs', formatValue(change.new_value)));
    return row;
  });
  const head = node('div', 'fabric-import-head');
  head.append(node('span', 'status-pill good', t('fabric.importVerified')));
  head.append(node('span', 'font-mono fs-xs', t('fabric.importSource', {
    node: payload.source_node || '---', revision: String(payload.source_revision ?? '---')
  })));
  head.append(node('span', 'font-mono fs-xs', t('fabric.importSigner', { signer: payload.signer || '---' })));
  head.append(node('span', 'font-mono fs-xs', t('fabric.importCount', { count: String(diff.length) })));

  const table = node('table', 'table-compact fabric-diff-table');
  const thead = node('thead');
  const headRow = node('tr');
  for (const label of [t('fabric.diffKey'), t('fabric.diffCurrent'), t('fabric.diffIncoming')]) {
    headRow.append(node('th', '', label));
  }
  thead.append(headRow);
  table.append(thead);
  const tbody = node('tbody');
  tbody.append(...rows);
  table.append(tbody);

  const apply = node('button', 'button button-primary mt-sm', t('fabric.importApply'));
  apply.type = 'button';
  apply.addEventListener('click', async () => {
    apply.disabled = true;
    try {
      const result = await applyFabricImport(payload.token, payload.current_revision);
      setStatus(byId('fabricImportStatus'), 'good', t('fabric.importApplied', { revision: String(result?.revision ?? '---') }));
      target.replaceChildren();
      pending = null;
      await refreshDrift();
      await refreshHistory();
    } catch (error) {
      setStatus(byId('fabricImportStatus'), 'danger', error?.message || t('fabric.importFailed'));
    } finally {
      apply.disabled = false;
    }
  });

  target.replaceChildren(head, table, apply);
}

async function handleImportFile(event) {
  const input = event.target;
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) {
    setStatus(byId('fabricImportStatus'), 'danger', t('fabric.importTooLarge'));
    input.value = '';
    return;
  }
  setStatus(byId('fabricImportStatus'), 'muted', t('fabric.importVerifying'));
  try {
    const text = await file.text();
    const bundle = JSON.parse(text);
    const preview = await previewFabricImport(bundle);
    pending = preview;
    setStatus(byId('fabricImportStatus'), 'good', t('fabric.importPreviewReady'));
    renderImportPreview(preview);
  } catch (error) {
    pending = null;
    const target = byId('fabricImportPreview');
    if (target) target.replaceChildren();
    setStatus(byId('fabricImportStatus'), 'danger', error?.message || t('fabric.importRejected'));
  } finally {
    input.value = '';
  }
}

// ---------------------------------------------------------------- history

async function refreshHistory() {
  const body = byId('fabricSurfaceHistory');
  if (!body) return;
  try {
    const payload = await getFabricSettingsHistory();
    const revisions = Array.isArray(payload?.history) ? payload.history : [];
    if (!revisions.length) {
      body.replaceChildren(node('p', 'empty-note', t('fabric.historyEmpty')));
      return;
    }
    body.replaceChildren(...revisions.slice(0, 12).map(entry => {
      const row = node('div', 'fabric-history-row');
      row.append(node('span', 'font-mono fs-xs', `#${entry.revision}`));
      row.append(node('span', 'fs-xs', entry.updated_at || '---'));
      return row;
    }));
  } catch {
    body.replaceChildren(node('p', 'empty-note', t('fabric.historyUnavailable')));
  }
}


async function refreshDrift() {
  try {
    renderDrift(await getFabricDrift());
  } catch {
    setStatus(byId('fabricImportStatus'), 'danger', t('fabric.driftUnavailable'));
  }
}

// ---------------------------------------------------------------- wiring

export function initFabricSurface() {
  const search = byId('fabricSearchInput');
  if (search) {
    let timer = 0;
    search.addEventListener('input', () => {
      globalThis.clearTimeout(timer);
      const query = search.value.trim();
      const body = byId('fabricSearchResults');
      if (query.length < SEARCH_MIN_CHARS) {
        if (body) body.replaceChildren(node('p', 'empty-note', t('fabric.searchHint')));
        return;
      }
      timer = globalThis.setTimeout(async () => {
        try {
          renderSearchResults(await searchFabricSettings(query));
        } catch {
          if (body) body.replaceChildren(node('p', 'empty-note', t('fabric.searchUnavailable')));
        }
      }, SEARCH_DEBOUNCE_MS);
    });
  }

  const exportButton = byId('fabricExportBtn');
  if (exportButton) {
    exportButton.addEventListener('click', async () => {
      exportButton.disabled = true;
      try {
        const bundle = await exportFabricSettings();
        const encoded = JSON.stringify(bundle, null, 2);
        const blob = new Blob([encoded], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `gedefense-fabric-settings-r${bundle.revision}.json`;
        link.click();
        URL.revokeObjectURL(url);
        setStatus(byId('fabricImportStatus'), 'good', t('fabric.exportDone', { revision: String(bundle.revision) }));
      } catch (error) {
        setStatus(byId('fabricImportStatus'), 'danger', error?.message || t('fabric.exportFailed'));
      } finally {
        exportButton.disabled = false;
      }
    });
  }

  const importInput = byId('fabricImportInput');
  if (importInput) importInput.addEventListener('change', handleImportFile);

  const refresh = byId('fabricDriftRefresh');
  if (refresh) refresh.addEventListener('click', () => { refreshDrift(); refreshHistory(); });

  refreshDrift();
  refreshHistory();
}
