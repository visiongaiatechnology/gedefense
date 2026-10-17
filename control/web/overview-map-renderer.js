// STATUS: PLATIN
// WP overview geometry and motion, using the existing local MIT world-map data.
import world from './vendor/jsvectormap/maps/world-merc.js';
import { LIMITS, stateFor } from './overview-map-data.js';

const NS = 'http://www.w3.org/2000/svg';
const COLORS = Object.freeze({ blocked: '#ff3366', suspicious: '#ffaa00', tracked: '#00f3ff' });
const WIDTH = 900;
const HEIGHT = 583.0802520919394;

function svgNode(name, attributes = {}, label = '') {
  const node = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  if (label) node.textContent = label;
  return node;
}

export function project([lat, lon]) {
  const inset = world.insets[0];
  const latitude = Math.max(-84, Math.min(84, lat));
  const x = 6381372 * lon * Math.PI / 180;
  const y = -6381372 * Math.log(Math.tan(Math.PI / 4 + latitude * Math.PI / 360));
  return [
    (x - inset.bbox[0].x) / (inset.bbox[1].x - inset.bbox[0].x) * WIDTH,
    (y - inset.bbox[0].y) / (inset.bbox[1].y - inset.bbox[0].y) * HEIGHT
  ];
}

export class OverviewMapRenderer {
  constructor(container, onSelect, hostLabel) {
    this.container = container;
    this.onSelect = onSelect;
    this.hostLabel = hostLabel;
    this.zoom = 1;
    this.pan = [0, 0];
    this.drag = null;
    this.data = null;
    this.signature = '';
    this.focused = '';
    this.motion = false;
    this.events = new AbortController();
    const options = { signal: this.events.signal };
    this.svg = svgNode('svg', { viewBox: `0 0 ${WIDTH} ${HEIGHT}`, class: 'overview-world-map',
      role: 'group', tabindex: '0', 'aria-label': container.getAttribute('aria-label') });
    const defs = svgNode('defs');
    for (const [kind, color] of Object.entries(COLORS)) {
      const gradient = svgNode('linearGradient', { id: `overview-gradient-${kind}`, x1: '0%', y1: '0%', x2: '100%', y2: '0%' });
      gradient.append(svgNode('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': '.85' }),
        svgNode('stop', { offset: '100%', 'stop-color': '#00f3ff', 'stop-opacity': '.4' }));
      defs.append(gradient);
    }
    const glow = svgNode('radialGradient', { id: 'overview-origin-glow' });
    glow.append(svgNode('stop', { offset: '0%', 'stop-color': '#00f3ff', 'stop-opacity': '.8' }),
      svgNode('stop', { offset: '100%', 'stop-color': '#00f3ff', 'stop-opacity': '0' }));
    defs.append(glow);
    this.viewport = svgNode('g');
    const countries = svgNode('g', { class: 'overview-world-countries' });
    for (const [code, region] of Object.entries(world.paths)) {
      const path = svgNode('path', { d: region.path, class: 'overview-world-country', 'data-country': code });
      path.append(svgNode('title', {}, region.name));
      countries.append(path);
    }
    this.arcs = svgNode('g', { class: 'overview-map-arcs', 'aria-hidden': 'true' });
    this.markers = svgNode('g', { class: 'overview-map-markers' });
    this.hub = svgNode('g', { class: 'overview-origin-marker', 'aria-hidden': 'true' });
    this.viewport.append(countries, this.arcs, this.markers, this.hub);
    this.svg.append(defs, this.viewport);
    container.replaceChildren(this.svg);
    this.svg.addEventListener('click', event => {
      const marker = event.target.closest('[data-source]');
      if (marker) this.select(marker.dataset.source);
    }, options);
    this.svg.addEventListener('keydown', event => {
      const marker = event.target.closest('[data-source]');
      if (marker && ['Enter', ' '].includes(event.key)) {
        event.preventDefault();
        this.select(marker.dataset.source);
      } else if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', '+', '-', 'Home'].includes(event.key)) {
        event.preventDefault();
        if (event.key === '+') this.setZoom(this.zoom + .35);
        else if (event.key === '-') this.setZoom(this.zoom - .35);
        else if (event.key === 'Home') this.reset();
        else {
          this.pan[0] += event.key === 'ArrowLeft' ? 24 : event.key === 'ArrowRight' ? -24 : 0;
          this.pan[1] += event.key === 'ArrowUp' ? 24 : event.key === 'ArrowDown' ? -24 : 0;
          this.transform();
        }
      }
    }, options);
    this.svg.addEventListener('pointerdown', event => {
      if (event.button !== 0 || this.zoom <= 1 || event.target.closest('[data-source]')) return;
      const matrix = this.svg.getScreenCTM();
      if (!matrix) return;
      const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
      this.drag = { id: event.pointerId, point, pan: [...this.pan] };
      this.svg.setPointerCapture(event.pointerId);
    }, options);
    this.svg.addEventListener('pointermove', event => {
      if (!this.drag || this.drag.id !== event.pointerId) return;
      const matrix = this.svg.getScreenCTM();
      if (!matrix) return;
      const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
      this.pan = [this.drag.pan[0] + point.x - this.drag.point.x, this.drag.pan[1] + point.y - this.drag.point.y];
      this.transform();
    }, options);
    const endDrag = () => { this.drag = null; };
    for (const name of ['pointerup', 'pointercancel', 'lostpointercapture']) this.svg.addEventListener(name, endDrag, options);
    this.transform();
  }

  select(ip) {
    const source = this.data?.sources.find(item => item.ip === ip);
    if (!source) return;
    const key = source.position ? project(source.position).map(n => n.toFixed(1)).join('_') : '';
    const cluster = this.data.sources.filter(item => item.position && project(item.position).map(n => n.toFixed(1)).join('_') === key);
    this.onSelect(source, cluster);
  }

  setZoom(zoom) { this.zoom = Math.max(1, Math.min(3.8, zoom)); this.transform(); }
  reset() { this.zoom = 1; this.pan = [0, 0]; this.transform(); }
  transform() {
    this.pan = this.pan.map((value, index) => Math.max(-(this.zoom - 1) * (index ? HEIGHT : WIDTH) / 2,
      Math.min((this.zoom - 1) * (index ? HEIGHT : WIDTH) / 2, value)));
    this.viewport.setAttribute('transform', `translate(${WIDTH / 2 + this.pan[0]} ${HEIGHT / 2 + this.pan[1]}) scale(${this.zoom}) translate(${-WIDTH / 2} ${-HEIGHT / 2})`);
    this.svg.classList.toggle('is-zoomed', this.zoom > 1);
    const zoomIn = document.getElementById('overviewMapZoomIn');
    const zoomOut = document.getElementById('overviewMapZoomOut');
    if (zoomIn) zoomIn.disabled = this.zoom >= 3.8;
    if (zoomOut) zoomOut.disabled = this.zoom <= 1;
  }

  render(data) {
    this.data = data;
    const signature = JSON.stringify([data.sources, data.origin, this.hostLabel]);
    if (signature === this.signature) return;
    this.signature = signature;
    this.arcs.replaceChildren();
    this.markers.replaceChildren();
    this.hub.replaceChildren();
    const origin = data.origin.known ? project(data.origin.position) : null;
    const placed = data.sources.filter(item => item.position).slice(0, LIMITS.markers);
    const clusters = new Map();
    placed.forEach((source, index) => {
      const point = project(source.position);
      const key = point.map(n => n.toFixed(1)).join('_');
      const cluster = clusters.get(key) || { point, entries: [] };
      cluster.entries.push(source);
      clusters.set(key, cluster);
      if (!origin || index >= LIMITS.arcs) return;
      const dx = origin[0] - point[0], dy = origin[1] - point[1];
      const distance = Math.hypot(dx, dy);
      if (distance < 1) return;
      const bow = Math.min(75, Math.max(25, distance * .16));
      const direction = dx > 0 ? -1 : 1;
      const cx = (point[0] + origin[0]) / 2 - dy / distance * bow * direction;
      const cy = (point[1] + origin[1]) / 2 + dx / distance * bow * direction - 10;
      const path = `M ${point[0]},${point[1]} Q ${cx},${cy} ${origin[0]},${origin[1]}`;
      const kind = stateFor(source);
      const group = svgNode('g', { class: `overview-arc-item is-${kind}`, 'data-ip': source.ip });
      group.append(svgNode('path', { class: 'overview-threat-arc', d: path, stroke: `url(#overview-gradient-${kind})` }));
      const photon = svgNode('circle', { class: 'overview-threat-projectile', r: '2.2', fill: COLORS[kind] });
      photon.append(svgNode('animateMotion', { path, dur: `${Math.max(1.8, Math.min(3.8, 1.4 + distance / 220)).toFixed(2)}s`,
        begin: `${(index * .28 % 2.5).toFixed(2)}s`, repeatCount: 'indefinite' }));
      group.append(photon);
      this.arcs.append(group);
    });
    for (const { point, entries } of clusters.values()) {
      const source = entries.find(item => item.blocked) || entries.find(item => stateFor(item) === 'suspicious') || entries[0];
      const color = COLORS[stateFor(source)];
      const group = svgNode('g', { class: `overview-threat-marker is-${stateFor(source)}`, transform: `translate(${point.join(' ')})`,
        'data-source': source.ip, 'data-ips': entries.map(item => item.ip).join(','), tabindex: '0', role: 'button',
        'aria-label': `${source.ip} · ${source.country || source.countryCode} · ${entries.length}` });
      group.append(svgNode('circle', { class: 'overview-sonar-pulse', r: entries.length > 1 ? 13 : 9, fill: color }),
        svgNode('circle', { r: entries.length > 1 ? 8.5 : 5, fill: '#060e1a', stroke: color, 'stroke-width': '1.2' }),
        svgNode('circle', { r: entries.length > 1 ? 4.2 : 3.2, fill: color, class: 'overview-marker-core' }));
      if (entries.length > 1) group.append(svgNode('text', { y: '2.8', 'text-anchor': 'middle', class: 'overview-cluster-count' }, String(entries.length)));
      this.markers.append(group);
    }
    if (origin) {
      this.hub.setAttribute('transform', `translate(${origin.join(' ')})`);
      this.hub.append(svgNode('circle', { r: 28, fill: 'url(#overview-origin-glow)' }),
        svgNode('circle', { r: 14, class: 'overview-origin-ping', fill: 'none', stroke: '#00f3ff', 'stroke-width': '1.2' }),
        svgNode('circle', { r: 8, fill: '#00f3ff26', stroke: '#00ffaa', 'stroke-width': '1.5' }),
        svgNode('circle', { r: 4.5, fill: '#00ffaa' }),
        svgNode('text', { y: -18, 'text-anchor': 'middle', class: 'overview-origin-label' }, this.hostLabel));
    }
    this.focus(this.focused);
    this.setMotion(this.motion);
  }

  focus(ip) {
    this.focused = ip;
    for (const node of this.svg.querySelectorAll('[data-ip], [data-ips]')) {
      node.classList.toggle('is-focused', Boolean(ip) && (node.dataset.ip === ip || (node.dataset.ips || '').split(',').includes(ip)));
    }
  }

  setMotion(enabled) {
    this.motion = enabled;
    this.container.classList.toggle('is-motion-paused', !enabled);
    if (enabled) this.svg.unpauseAnimations();
    else this.svg.pauseAnimations();
  }

  destroy() { this.events.abort(); this.svg.remove(); this.data = null; }
}
