// STATUS: PLATIN
// Bounded transport normalization shared by the overview map and its telemetry table.
export const LIMITS = Object.freeze({ sources: 500, markers: 240, arcs: 40, events: 300 });

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const countryLimit = 60;
const text = (value, max = 240) => typeof value === 'string' ? value.slice(0, max) : '';
const count = value => typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.min(1e12, Math.trunc(value))) : 0;
const areas = new Set(['kinetic', 'l7', 'xdr', 'host']);
const area = value => areas.has(value) ? value : 'xdr';

export function positionOf(latitude, longitude) {
  if (typeof latitude !== 'number' || typeof longitude !== 'number') return null;
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
  if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180 || (latitude === 0 && longitude === 0)) return null;
  return [latitude, longitude];
}

export function stateFor(item) {
  if (item.blocked) return 'blocked';
  return ['critical', 'high', 'medium'].includes(item.severity) ? 'suspicious' : 'tracked';
}

export function remoteIP(remote) {
  const value = text(remote, 80);
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracket) return bracket[1];
  return /^\d+\.\d+\.\d+\.\d+:\d+$/.test(value) ? value.split(':')[0] : value;
}

function strings(value) {
  return Array.isArray(value) ? value.slice(0, 16).map(item => text(item, 120)).filter(Boolean) : [];
}

// The per-country roll-up the server already computed. Bounded like every other collection in this
// module, so a malformed or oversized frame can never turn into an unbounded DOM list.
function normalizeCountries(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, countryLimit).filter(record).map(item => ({
    country: text(item.country, 100) || text(item.country_code, 2).toUpperCase(),
    countryCode: text(item.country_code, 2).toUpperCase(),
    total: count(item.total), kinetic: count(item.kinetic), l7: count(item.l7), xdr: count(item.xdr),
    blocked: count(item.blocked), severity: text(item.severity, 16)
  })).filter(item => item.country && item.total > 0);
}

export function normalizePayload(payload) {
  if (!record(payload) || !Array.isArray(payload.sources) || !Array.isArray(payload.recent)) {
    throw new TypeError('Invalid overview telemetry response');
  }
  const sources = payload.sources.slice(0, LIMITS.sources).filter(record).map(source => ({
    ip: text(source.ip, 80), area: area(source.area), areas: strings(source.areas).filter(value => areas.has(value)),
    country: text(source.country, 100), countryCode: text(source.country_code, 2).toUpperCase(),
    asn: text(source.asn, 32), asName: text(source.as_name, 160),
    position: positionOf(source.latitude, source.longitude), blocked: source.blocked === true,
    severity: text(source.severity, 16), summary: text(source.summary, 500), rules: strings(source.rules),
    hits: count(source.hits), lastSeen: text(source.last_seen, 48), service: text(source.service, 100)
  })).filter(source => source.ip);
  const byIP = new Map(sources.map(source => [source.ip, source]));
  const recent = payload.recent.slice(0, LIMITS.events).filter(record).map(event => {
    const ip = remoteIP(event.remote);
    const source = byIP.get(ip);
    return {
      id: text(event.id, 120), ip, area: area(event.area), time: text(event.time, 48),
      country: text(event.country, 100) || source?.country || '',
      countryCode: text(event.country_code, 2).toUpperCase() || source?.countryCode || '',
      asn: source?.asn || '', asName: source?.asName || '', position: source?.position || null,
      severity: text(event.severity, 16), blocked: event.blocked === true,
      summary: text(event.summary, 500), rules: strings(event.rules), decision: text(event.decision, 100),
      path: text(event.path, 500), method: text(event.method, 16), process: text(event.process, 240),
      host: text(event.host, 240)
    };
  });
  const originData = record(payload.origin) ? payload.origin : {};
  const originPosition = positionOf(originData.lat, originData.lon);
  const origin = {
    known: originData.known === true && originPosition !== null, position: originPosition,
    ip: text(originData.ip, 80), country: text(originData.country, 100),
    asn: text(originData.asn, 32), asName: text(originData.as_name, 160)
  };
  const totals = {};
  for (const key of ['sources', 'placed', 'blocked', 'countries', 'kinetic', 'l7', 'xdr']) {
    totals[key] = count(record(payload.totals) ? payload.totals[key] : 0);
  }
  return {
    sources, recent, origin, totals, countries24h: normalizeCountries(payload.countries_24h),
    generated: text(payload.generated, 48),
    geo: { loaded: record(payload.geo) && payload.geo.loaded === true, entries: count(payload.geo?.entries) }
  };
}

// Keep packet sources visible even when there is no corresponding incident in the bounded ledger slice.
export function telemetryRows(payload) {
  const seen = new Set(payload.recent.map(event => event.ip));
  const rows = [...payload.recent];
  for (const source of payload.sources) {
    if (rows.length >= LIMITS.events) break;
    if (seen.has(source.ip)) continue;
    rows.push({ ...source, time: source.lastSeen, path: '', method: '', process: '', host: '', decision: '' });
  }
  return rows.sort((a, b) => (Date.parse(b.time) || 0) - (Date.parse(a.time) || 0));
}
