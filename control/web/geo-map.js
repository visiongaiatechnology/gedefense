'use strict';

// STATUS: DIAMANT VGT SUPREME
//
// Kinetic live geography layer.
//
// Renders the vendored jsVectorMap SVG world map from data the control plane
// already produces locally. The GeoIP/ASN database stays on the host: this module
// issues no network request, requests no tile and references no external origin.
// The map geometry is a module import, not a fetch.
//
// Trusted Types
// -------------
// The vendored tree contains exactly two inner-HTML assignments, and both sit
// behind the `html = true` argument of `createElement`. The only caller that passes
// it is `setupZoomButtons`, and that caller has two branches:
//
//   const zoomIn = zoomInOption ? getZoomButton(zoomInOption) : createElement(..., true)
//
// Supplying `zoomInButton` and `zoomOutButton` therefore selects the branch that
// uses our own `<button>` elements, and the inner-HTML line is never executed. The
// policy stays at `require-trusted-types-for 'script'` with no exception, the zoom
// controls are real native buttons with keyboard support, and nothing about the map
// had to be given up. A contract test asserts that both options are passed, so a
// future edit that drops one fails the build instead of throwing in the browser.
//
// Bounds
// ------
// Every layer is truncated before anything reaches the DOM, so a hostile feed
// cannot grow the map. The caps are exported so the dashboard can display the same
// numbers it enforces.

import jsVectorMap from './vendor/jsvectormap/js/index.js';
import worldMercatorMap from './vendor/jsvectormap/maps/world-merc.js';
import { t } from './i18n.js';

const MAP_NAME = 'gedefense-world';
const MARKERS_GROUP_ID = 'jvm-markers-group';
const ZOOM_IN_SELECTOR = '#kineticGeoZoomIn';
const ZOOM_OUT_SELECTOR = '#kineticGeoZoomOut';

// Layer caps. `tracked` matches the source matrix limit so the map and the rail
// never disagree about how many sources are being shown.
export const GEO_MAP_LIMITS = Object.freeze({
  tracked: 96,
  blocked: 48,
  pulsing: 24,
  countries: 192
});

// The heat ramp is defined here rather than taken from the library's two-colour
// interpolation, because that ramp always paints the minimum observed value at full
// strength. A country with a single hit would then look as alarming as a country
// under sustained attack, and a country with no traffic at all would be
// indistinguishable from one with a little.
const HEAT_COLD = [18, 52, 78];
const HEAT_HOT = [255, 96, 124];
const REGION_BASE_FILL = '#0d2537';
const REGION_STROKE = 'rgba(82, 199, 255, .18)';

const TRACKED_FILL = '#5bd4ff';
const SUSPICIOUS_FILL = '#f4c76a';
const BLOCKED_FILL = '#ff6482';
// The origin marker is deliberately a different shape and colour from a source: it is
// not a threat, it is where the threats are arriving. Drawing it as one of them would
// put this host on its own map of attackers.
const ORIGIN_NAME = 'gedefense-origin';
const ORIGIN_FILL = '#7ef7c8';
const ORIGIN_RING = 'rgba(126, 247, 200, .28)';

let registered = false;
let instance = null;
let pulsingNodes = [];
let lastSignature = '';
// The normalised payload is kept beside the map so the tooltip callbacks can answer
// without reaching back into the caller.
let lastCountries = new Map();
let lastMarkers = new Map();
let lastOrigin = null;

function byId(id) {
  return document.getElementById(id);
}

// prefersReducedMotion reports the operator's motion preference. The pulse is the
// only animation this layer adds and it is suppressed entirely when requested.
function prefersReducedMotion() {
  const match = globalThis.matchMedia;
  return typeof match === 'function' && match('(prefers-reduced-motion: reduce)').matches;
}

// finiteNumber converts a value to a finite number, or returns null.
//
// The null and empty-string guards are load-bearing: Number(null) is 0 and
// Number('') is 0, both of which are finite. Without them a source that carries no
// coordinates is plotted at 0,0 - a cluster of imaginary markers in the Gulf of
// Guinea, which is precisely the fabricated picture this layer must never draw.
function finiteNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

// positionOf returns [lat, lng] for a source, or null. A source without a usable
// position is skipped rather than plotted at 0,0: the Gulf of Guinea is not a threat
// origin, and a cluster of imaginary markers there would be a fabricated picture.
function positionOf(source) {
  const lat = finiteNumber(source?.latitude);
  const lng = finiteNumber(source?.longitude);
  if (lat === null || lng === null) return null;
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  return [lat, lng];
}

function isBlocked(source) {
  if (source?.blocked) return true;
  return String(source?.state || '').toUpperCase() === 'BLOCKED';
}

function isSuspicious(source) {
  if (Number(source?.score || 0) >= 40) return true;
  return ['SUSPICIOUS', 'THREAT', 'SCAN', 'BURST'].includes(String(source?.state || '').toUpperCase());
}

function markerFill(source) {
  if (isBlocked(source)) return BLOCKED_FILL;
  if (isSuspicious(source)) return SUSPICIOUS_FILL;
  return TRACKED_FILL;
}

// heatColour maps an event rate onto the ramp. A zero rate returns the neutral base
// fill, so an idle country is never presented as hot.
function heatColour(hits, maxHits) {
  if (!(hits > 0) || !(maxHits > 0)) return REGION_BASE_FILL;
  const ratio = Math.max(0, Math.min(1, hits / maxHits));
  const channel = index => Math.round(HEAT_COLD[index] + (HEAT_HOT[index] - HEAT_COLD[index]) * ratio);
  return `rgb(${channel(0)}, ${channel(1)}, ${channel(2)})`;
}

// countryCode normalises an ISO-3166 alpha-2 code. Anything else is rejected rather
// than handed to the region lookup, where it would silently do nothing.
function countryCode(value) {
  const code = String(value || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : '';
}

function ensureMapRegistered() {
  if (registered) return;
  jsVectorMap.addMap(MAP_NAME, worldMercatorMap);
  registered = true;
}

// ensureInstance creates the map once. It returns null while the container is not in
// the document, which is the normal state for a view that has not been opened; the
// caller simply tries again on the next snapshot.
function ensureInstance() {
  if (instance) return instance;
  if (!byId('kineticGeoMap')) return null;
  // The zoom controls must exist before the map is built, because the library wires
  // them during construction and falls back to its own raw HTML element otherwise.
  if (!byId('kineticGeoZoomIn') || !byId('kineticGeoZoomOut')) return null;

  ensureMapRegistered();
  instance = new jsVectorMap({
    selector: '#kineticGeoMap',
    map: MAP_NAME,
    backgroundColor: 'transparent',
    draggable: true,
    // The wheel belongs to the page. A dashboard that captures scroll over a map
    // traps the operator mid-page, so zoom is offered through the buttons instead.
    zoomOnScroll: false,
    zoomButtons: true,
    zoomInButton: ZOOM_IN_SELECTOR,
    zoomOutButton: ZOOM_OUT_SELECTOR,
    zoomAnimate: !prefersReducedMotion(),
    showTooltip: true,
    regionsSelectable: false,
    markersSelectable: false,
    // An empty marker list is load-bearing, not decoration. The library creates the
    // marker group during construction only when `options.markers` is truthy, and
    // `addMarkers` appends into that group. Constructing without it leaves the group
    // undefined, so every later addMarkers call has nowhere to draw and the live
    // source layer stays permanently empty while reporting a non-zero count.
    markers: [],
    // Arcs are drawn from each source to this host. The line style is the arc shape;
    // the dash animation is applied to the created paths after the fact, because the
    // library never sets the attribute its own stylesheet animates on.
    lines: [],
    lineStyle: { curvature: 0.42, stroke: 'rgba(255, 100, 130, .5)', strokeWidth: 1.1, strokeLinecap: 'round' },
    regionStyle: {
      initial: { fill: REGION_BASE_FILL, fillOpacity: 1, stroke: REGION_STROKE, strokeWidth: 0.4 },
      hover: { fillOpacity: 0.82, cursor: 'pointer' }
    },
    markerStyle: {
      initial: { r: 4, fill: TRACKED_FILL, fillOpacity: 0.92, stroke: '#03121f', strokeWidth: 1, strokeOpacity: 0.8 },
      hover: { r: 5.5, fill: '#ffffff', cursor: 'pointer' }
    },
    onRegionTooltipShow(event, tooltip, code) {
      const row = lastCountries.get(code);
      if (!row) {
        tooltip.text(`${code} · ${t('kinetic.geoNoTraffic')}`);
        return;
      }
      tooltip.text(`${row.name || code} · ${row.hits} ${t('kinetic.geoHits')} · ${row.blocked} ${t('kinetic.geoBlocked')}`);
    },
    onMarkerTooltipShow(event, tooltip, index) {
      const source = lastMarkers.get(String(index));
      if (!source) return;
      const label = String(source.ip || source.source || '---');
      const state = isBlocked(source) ? t('kinetic.geoBlocked') : t('kinetic.geoTracked');
      tooltip.text(`${label} · ${state} · ${t('kinetic.geoScore')} ${Number(source.score || 0)}`);
    }
  });
  return instance;
}

// applyCountryHeat paints the choropleth and returns how many regions carried data.
// Every region the map knows is written on each pass, so a country that stops
// reporting is reset instead of keeping its previous colour.
function applyCountryHeat(map, countries) {
  const rows = [];
  for (const row of countries) {
    const code = countryCode(row?.code);
    if (!code) continue;
    rows.push({
      code,
      name: String(row?.name || ''),
      hits: Math.max(0, Number(row?.hits || 0)),
      blocked: Math.max(0, Number(row?.blocked || 0))
    });
    if (rows.length >= GEO_MAP_LIMITS.countries) break;
  }

  const maxHits = rows.reduce((max, row) => Math.max(max, row.hits), 0);
  const next = new Map(rows.map(row => [row.code, row]));

  for (const code of Object.keys(map.regions || {})) {
    const row = next.get(code);
    map.regions[code].element.setStyle('fill', row ? heatColour(row.hits, maxHits) : REGION_BASE_FILL);
  }

  lastCountries = next;
  return rows.length;
}

// applyMarkers rebuilds the marker layer within its caps. Blocked sources are kept in
// their own bucket, so the two populations are always separately visible and the
// blocked layer cannot be crowded out by ordinary tracked traffic.
function applyMarkers(map, sources) {
  const tracked = [];
  const blocked = [];

  for (const source of sources) {
    const coords = positionOf(source);
    if (!coords) continue;
    if (isBlocked(source)) {
      if (blocked.length < GEO_MAP_LIMITS.blocked) blocked.push({ source, coords });
      continue;
    }
    if (tracked.length < GEO_MAP_LIMITS.tracked) tracked.push({ source, coords });
  }

  const ordered = tracked.concat(blocked);
  map.removeMarkers();
  lastMarkers = new Map();
  if (!ordered.length) {
    clearPulsing();
    return { tracked: 0, blocked: 0 };
  }

  map.addMarkers(ordered.map((entry, index) => {
    lastMarkers.set(String(index), entry.source);
    const blockedSource = isBlocked(entry.source);
    return {
      name: String(entry.source.ip || entry.source.source || '---'),
      coords: entry.coords,
      // A per-marker style is merged over the map default by the library, which is how
      // a blocked source is separated visually without a second map instance.
      style: {
        initial: {
          r: blockedSource ? 5 : 4,
          fill: markerFill(entry.source),
          fillOpacity: blockedSource ? 1 : 0.92
        }
      }
    };
  }));

  markPulsing(ordered.map(entry => entry.source));
  applyOriginLines(map, ordered);

  return { tracked: tracked.length, blocked: blocked.length };
}

// applyOriginLines draws the arcs from every placed source to this host.
//
// The library connects lines by marker NAME, not by coordinate, so the source markers
// carry their address as their name and the origin marker carries a reserved one. When
// the host position could not be resolved there is nothing to draw to, and the map
// says so through the layer note rather than inventing a destination.
function applyOriginLines(map, ordered) {
  if (map.removeLines) map.removeLines();
  if (!lastOrigin || !lastOrigin.known) return;
  if (!ordered.length) return;

  const originCoords = [Number(lastOrigin.lat), Number(lastOrigin.lon)];
  if (!Number.isFinite(originCoords[0]) || !Number.isFinite(originCoords[1])) return;

  // The origin is its own marker so it has a position for the lines to terminate at.
  map.addMarkers([{
    name: ORIGIN_NAME,
    coords: originCoords,
    style: { initial: { r: 6, fill: ORIGIN_FILL, fillOpacity: 1, stroke: ORIGIN_RING, strokeWidth: 9, strokeOpacity: 0.5 } }
  }]);

  const arcs = [];
  for (const entry of ordered) {
    const name = String(entry.source.ip || entry.source.source || '');
    if (!name) continue;
    arcs.push({
      from: name,
      to: ORIGIN_NAME,
      style: {
        stroke: isBlocked(entry.source) ? 'rgba(255, 100, 130, .55)' : 'rgba(91, 212, 255, .38)',
        strokeWidth: isBlocked(entry.source) ? 1.3 : 1
      }
    });
  }
  if (arcs.length) map.addLines(arcs);
  animateArcs();
}

// animateArcs tags the created paths so the stylesheet's dash animation applies.
// The library emits `jvm-line` paths but never sets the `animation` attribute its own
// stylesheet keys on, so without this step the arcs are static.
function animateArcs() {
  // The paths are queried under the map container rather than through the library's
  // own group id. That id is an implementation detail the vendored code owns and could
  // rename; the container is ours and the line class is part of the library's public
  // stylesheet contract.
  const container = byId('kineticGeoMap');
  if (!container) return;
  const paths = container.querySelectorAll('.jvm-line');
  if (!paths.length) return;
  const reduced = prefersReducedMotion();
  for (const node of paths) {
    if (reduced) {
      node.removeAttribute('animation');
      node.style.strokeDasharray = '';
      continue;
    }
    node.setAttribute('animation', 'true');
    node.style.strokeDasharray = '7 5';
  }
}

function clearPulsing() {
  for (const node of pulsingNodes) node.classList.remove('geo-pulse');
  pulsingNodes = [];
}

// markPulsing tags the newest sources so CSS can animate them. Only the newest few
// pulse: on a map where everything moves, movement stops carrying information.
function markPulsing(sources) {
  clearPulsing();
  if (prefersReducedMotion()) return;

  const group = byId(MARKERS_GROUP_ID);
  if (!group) return;
  const nodes = group.children;
  const budget = Math.min(GEO_MAP_LIMITS.pulsing, sources.length);
  for (let index = 0; index < budget; index += 1) {
    const node = nodes[index];
    if (!node) break;
    node.classList.add('geo-pulse');
    pulsingNodes.push(node);
  }
}

// signatureOf identifies a snapshot cheaply. It is computed over the bounded prefix
// the map would actually draw, so the cost does not grow with a feed that reports
// thousands of sources the map will never show.
function signatureOf(countries, sources) {
  return `${countries.length}|${sources.length}|` + sources
    .slice(0, GEO_MAP_LIMITS.tracked + GEO_MAP_LIMITS.blocked)
    .map(source => `${source?.ip || source?.source || ''}:${source?.state || ''}:${source?.blocked ? 1 : 0}`)
    .join(',');
}

// updateKineticGeoMap renders one snapshot. It is idempotent: an unchanged signature
// is skipped, so a polling dashboard does not rebuild the SVG on every tick.
export function updateKineticGeoMap(payload) {
  const map = ensureInstance();
  if (!map) return null;

  const countries = Array.isArray(payload?.countries) ? payload.countries : [];
  const sources = Array.isArray(payload?.sources) ? payload.sources : [];
  // The origin travels with every snapshot. A missing origin is not an error: it means
  // this host's position could not be resolved, and the arcs are simply not drawn.
  lastOrigin = payload?.origin && payload.origin.known ? payload.origin : null;
  const originNote = String(payload?.origin_note || '');
  const signature = signatureOf(countries, sources) + `|${lastOrigin ? lastOrigin.lat + "," + lastOrigin.lon : "no-origin"}`;
  if (signature === lastSignature) return null;

  const placedCountries = applyCountryHeat(map, countries);
  const placed = applyMarkers(map, sources);
  lastSignature = signature;

  return {
    countries: placedCountries,
    tracked: placed.tracked,
    blocked: placed.blocked,
    originKnown: Boolean(lastOrigin),
    originNote,
    limits: GEO_MAP_LIMITS
  };
}

// clearKineticGeoMap empties the layers without destroying the map, for the case
// where the view is open but the selected window holds no data at all.
export function clearKineticGeoMap() {
  if (!instance) return;
  instance.removeMarkers();
  if (instance.removeLines) instance.removeLines();
  for (const code of Object.keys(instance.regions || {})) {
    instance.regions[code].element.setStyle('fill', REGION_BASE_FILL);
  }
  clearPulsing();
  lastCountries = new Map();
  lastMarkers = new Map();
  lastSignature = '';
}

// destroyKineticGeoMap releases the instance. The map holds SVG nodes, delegated
// listeners and a tooltip element attached to the body; none of that should survive
// the view being torn down.
export function destroyKineticGeoMap() {
  if (!instance) return;
  clearPulsing();
  instance.destroy();
  instance = null;
  lastCountries = new Map();
  lastMarkers = new Map();
  lastSignature = '';
}

// geoMapLimits exposes the caps for the dashboard, so the interface can state the
// bound it enforces instead of leaving the operator to guess it.
export function geoMapLimits() {
  return GEO_MAP_LIMITS;
}
