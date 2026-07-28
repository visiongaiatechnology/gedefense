'use strict';

// Direct loopback operation may use a bearer token, but it remains only in
// this module's volatile memory. Public gateway sessions never expose the
// backend token to the browser, and a reload intentionally clears manual keys.
let volatileToken = '';

export function getToken() {
  return volatileToken;
}

export function setToken(value) {
  volatileToken = String(value || '').trim();
}

function requestID() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

export class APIError extends Error {
  constructor(message, status, errorID = '') {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.errorID = errorID;
  }
}

export async function api(path, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (method !== 'GET' && method !== 'HEAD') headers.set('X-VGT-Request-ID', requestID());
  let body;
  if (Object.prototype.hasOwnProperty.call(options, 'json')) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(options.json);
  }
  const response = await fetch(path, {
    method,
    headers,
    body,
    credentials: 'same-origin',
    cache: 'no-store',
    signal: options.signal
  });
  const contentType = response.headers.get('content-type') || '';
  let payload = null;
  if (contentType.includes('application/json')) {
    payload = await response.json();
  } else {
    payload = await response.text();
  }
  if (!response.ok) {
    const message = payload && typeof payload === 'object' ? payload.error : String(payload || `HTTP ${response.status}`);
    const errorID = payload && typeof payload === 'object' ? payload.error_id || '' : '';
    throw new APIError(message, response.status, errorID);
  }
  return payload;
}


export async function streamSnapshots({ onSnapshot, onEvent, signal }) {
  const headers = new Headers({ Accept: 'text/event-stream' });
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch('/api/v1/stream', {
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    signal
  });
  if (!response.ok || !response.body) {
    throw new APIError(response.status === 401 ? 'authorization required' : 'event stream unavailable', response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let eventName = 'message';
  let dataLines = [];
  const dispatch = () => {
    if (!dataLines.length) return;
    const raw = dataLines.join('\n');
    dataLines = [];
    try {
      const payload = JSON.parse(raw);
      if (eventName === 'snapshot') onSnapshot(payload);
      else if (eventName === 'event') onEvent(payload);
    } finally {
      eventName = 'message';
    }
  };
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).replace(/\r$/, '');
      buffer = buffer.slice(newline + 1);
      if (line === '') dispatch();
      else if (line.startsWith('event:')) eventName = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
    }
  }
  dispatch();
}
export const getStatus = signal => api('/api/v1/status', { signal });
export const getPolicy = () => api('/api/v1/policy');
export const getProfiles = () => api('/api/v1/xdr/profiles');
export const exportForensics = () => api('/api/v1/forensics/export');
export const addBlock = input => api('/api/v1/blocks', { method: 'POST', json: input });
export const deleteBlock = id => api(`/api/v1/blocks/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const syncFeeds = () => api('/api/v1/feeds/sync', { method: 'POST', json: {} });
export const acknowledgeIncident = id => api(`/api/v1/xdr/incidents/${encodeURIComponent(id)}/ack`, { method: 'POST', json: {} });

export const getRelease = () => api('/api/v1/release');
export const transitionRelease = input => api('/api/v1/release/transition', { method: 'POST', json: input });
export const emergencyStop = reason => api('/api/v1/release/emergency-stop', { method: 'POST', json: { reason } });
export const getSettings = () => api('/api/v1/settings');
export const updateSettings = input => api('/api/v1/settings', { method: 'PUT', json: input });
export const addAllowlist = target => api('/api/v1/allowlist', { method: 'POST', json: { target } });
export const removeAllowlist = target => api('/api/v1/allowlist/remove', { method: 'POST', json: { target } });
export const clearEmergencyStop = (confirmation, reason) => api('/api/v1/release/emergency-stop/clear', { method: 'POST', json: { confirmation, reason } });
export const getTransactions = () => api('/api/v1/transactions?limit=100');
export const previewTransaction = input => api('/api/v1/transactions/preview', { method: 'POST', json: input });
export const applyTransaction = (id, confirmation) => api(`/api/v1/transactions/${encodeURIComponent(id)}/apply`, { method: 'POST', json: { confirmation } });
export const reverseTransaction = (id, confirmation) => api(`/api/v1/transactions/${encodeURIComponent(id)}/reverse`, { method: 'POST', json: { confirmation } });
export const getQuarantine = () => api('/api/v1/quarantine');
export const previewQuarantine = input => api('/api/v1/quarantine/preview', { method: 'POST', json: input });
export const getCases = () => api('/api/v1/cases?limit=100');
export const setCaseStatus = (id, status, resolution) => api(`/api/v1/cases/${encodeURIComponent(id)}/status`, { method: 'POST', json: { status, resolution } });
export const getCells = () => api('/api/v1/cells');
export const previewCellAction = input => api('/api/v1/cells/preview', { method: 'POST', json: input });
