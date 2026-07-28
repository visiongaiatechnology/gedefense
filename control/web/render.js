'use strict';

import { locale, t } from './i18n.js';

export const byID = id => document.getElementById(id);
export const text = (id, value) => {
  const node = byID(id);
  if (node) node.textContent = String(value ?? '');
};

export function badge(id, label, kind = '') {
  const node = byID(id);
  if (!node) return;
  node.textContent = label;
  node.className = `badge${kind ? ` badge-${kind}` : ''}`;
}

export function formatBytes(value) {
  let number = Number(value);
  if (!Number.isFinite(number) || number < 0) number = 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (number >= 1024 && unit < units.length - 1) {
    number /= 1024;
    unit++;
  }
  return `${number.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export const formatRate = value => `${formatBytes(value)}/s`;

export function formatUptime(seconds) {
  let remaining = Math.max(0, Math.floor(Number(seconds) || 0));
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const parts = [Math.floor(remaining / 3600), Math.floor((remaining % 3600) / 60), remaining % 60]
    .map(value => String(value).padStart(2, '0'));
  return `${days ? `${days}d ` : ''}${parts.join(':')}`;
}

export function formatTime(value) {
  if (!value) return '---';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '---' : date.toLocaleString(locale());
}

function emptyRow(columns, message) {
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = columns;
  cell.className = 'empty-cell';
  cell.textContent = message;
  row.append(cell);
  return row;
}

function cell(value, className = '') {
  const node = document.createElement('td');
  node.textContent = String(value ?? '');
  if (className) node.className = className;
  return node;
}

export function renderEvents(events = []) {
  const root = byID('events');
  if (!root) return;
  if (!events.length) {
    const item = document.createElement('li');
    item.className = 'empty-state';
    item.textContent = t('dynamic.noEvents');
    root.replaceChildren(item);
    return;
  }
  const nodes = events.slice(0, 30).map(event => {
    const item = document.createElement('li');
    item.className = `severity-${event.severity || 'info'}`;
    const dot = document.createElement('span');
    dot.className = 'event-dot';
    const body = document.createElement('div');
    const title = document.createElement('b');
    title.textContent = event.kind || 'event';
    const description = document.createElement('p');
    description.textContent = `${event.message || ''}${event.target ? ` · ${event.target}` : ''}`;
    body.append(title, description);
    const when = document.createElement('time');
    when.textContent = formatTime(event.time);
    item.append(dot, body, when);
    return item;
  });
  root.replaceChildren(...nodes);
}

export function renderRules(blocks = [], onDelete) {
  const root = byID('rules');
  if (!root) return;
  if (!blocks.length) {
    root.replaceChildren(emptyRow(6, t('dynamic.noRules')));
    return;
  }
  const rows = blocks.map(block => {
    const row = document.createElement('tr');
    row.append(
      cell(block.target, 'mono accent'),
      cell(block.source || 'manual'),
      cell(block.reason || ''),
      cell(formatTime(block.expires_at)),
      cell(block.enforced ? t('dynamic.kernel') : t('dynamic.observe'), block.enforced ? 'state-good' : 'state-warn')
    );
    const action = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'icon-button danger';
    button.textContent = t('dynamic.remove');
    button.addEventListener('click', () => onDelete(block.id));
    action.append(button);
    row.append(action);
    return row;
  });
  root.replaceChildren(...rows);
}

export function renderIncidents(items = [], onAck) {
  const roots = [byID('incidents'), byID('forensicIncidents')];
  const main = roots[0];
  const forensic = roots[1];
  if (main) {
    if (!items.length) main.replaceChildren(emptyRow(7, t('dynamic.noIncidents')));
    else {
      const rows = items.slice(0, 80).map(incident => {
        const row = document.createElement('tr');
        row.className = `severity-${incident.severity || 'info'}`;
        row.append(
          cell(formatTime(incident.time)),
          cell(incident.score || 0, 'score-cell'),
          cell(`${incident.process || 'unknown'} (${incident.pid || '?'})`),
          cell((incident.rule_ids || []).join(', '), 'signal-cell'),
          cell(incident.decision || 'alert'),
          cell(incident.outcome || 'observed')
        );
        const action = document.createElement('td');
        if (!incident.acknowledged) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'icon-button';
          button.textContent = t('dynamic.acknowledge');
          button.addEventListener('click', () => onAck(incident.id));
          action.append(button);
        } else {
          action.textContent = 'ACK';
          action.className = 'state-good';
        }
        row.append(action);
        return row;
      });
      main.replaceChildren(...rows);
    }
  }
  if (forensic) {
    if (!items.length) forensic.replaceChildren(emptyRow(7, t('dynamic.noForensics')));
    else {
      const rows = items.slice(0, 120).map(incident => {
        const row = document.createElement('tr');
        row.append(
          cell(formatTime(incident.time)),
          cell(incident.id || '', 'mono'),
          cell(incident.severity || 'info'),
          cell(incident.score || 0, 'score-cell'),
          cell(incident.summary || ''),
          cell(incident.action || 'none'),
          cell(incident.acknowledged ? 'ACK' : 'OPEN', incident.acknowledged ? 'state-good' : 'state-warn')
        );
        return row;
      });
      forensic.replaceChildren(...rows);
    }
  }
}

export function renderProfiles(profiles = []) {
  const root = byID('profiles');
  if (!root) return;
  if (!profiles.length) {
    root.replaceChildren(emptyRow(6, t('dynamic.noProfiles')));
    return;
  }
  const rows = profiles.map(profile => {
    const ports = profile.remote_ports ? Object.keys(profile.remote_ports).length : 0;
    const samples = profile.connection_count?.samples || 0;
    const meanConnections = Number(profile.connection_count?.mean || 0).toFixed(2);
    const meanRemotes = Number(profile.unique_remotes?.mean || 0).toFixed(2);
    const row = document.createElement('tr');
    row.append(
      cell(profile.executable || 'unknown', 'mono'),
      cell(samples),
      cell(meanConnections),
      cell(meanRemotes),
      cell(ports),
      cell(formatTime(profile.last_seen))
    );
    return row;
  });
  root.replaceChildren(...rows);
}

export function toast(message, kind = 'info') {
  const region = byID('toastRegion');
  if (!region) return;
  const node = document.createElement('div');
  node.className = `toast toast-${kind}`;
  node.textContent = message;
  region.append(node);
  setTimeout(() => node.remove(), 5000);
}

export function renderReleaseBlockers(blockers = []) {
  const root = byID('releaseBlockers');
  if (!root) return;
  if (!blockers.length) {
    const item = document.createElement('li');
    item.className = 'state-good';
    item.textContent = t('dynamic.allGates');
    root.replaceChildren(item);
    return;
  }
  const items = blockers.map(value => {
    const item = document.createElement('li');
    item.className = 'state-warn';
    item.textContent = String(value);
    return item;
  });
  root.replaceChildren(...items);
}
