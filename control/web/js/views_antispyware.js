// STATUS: DIAMANT VGT SUPREME
'use strict';

import { getAntispywareStatus } from '../api.js';
import { t } from '../i18n.js';
import { byID, el, text } from '../render.js';
import { handleActionError, number } from './navigation.js';

function stateMeta(rawState, extraActive = false) {
  const s = String(rawState || 'unavailable').toLowerCase();
  if (extraActive || s === 'active' || s === 'applied' || s === 'enforcing' || s === 'enforced' || s === 'healthy') {
    return { label: t('antispyware.state.active'), cls: 'status-pill good' };
  }
  if (s === 'observe' || s === 'inactive' || s === 'idle') {
    return { label: t('antispyware.state.observe'), cls: 'status-pill warn' };
  }
  if (s === 'degraded' || s === 'capability-missing' || s === 'pending' || s === 'failed') {
    return { label: t('antispyware.state.degraded'), cls: 'status-pill danger' };
  }
  if (s === 'disarmed' || s === 'disabled') {
    return { label: t('antispyware.state.disarmed'), cls: 'status-pill muted' };
  }
  return { label: t('antispyware.state.unavailable'), cls: 'status-pill muted' };
}

function setPill(id, rawState, customLabel = '', extraActive = false) {
  const node = byID(id);
  if (!node) return;
  const meta = stateMeta(rawState, extraActive);
  node.className = meta.cls;
  node.textContent = customLabel || meta.label;
}

function buildMatrixRows(data) {
  const selfGuard = data?.self_guard || {};
  const execInode = data?.exec_inode || {};
  const bpfGuard = data?.bpf_guard || {};
  const crossView = data?.cross_view || {};
  const kernelHooks = data?.kernel_hooks || {};
  const persistence = data?.persistence || {};
  const dns = data?.dns || {};
  const styx = data?.styx || {};
  const styxP2 = data?.styx_phase2 || {};
  const cred = data?.credential_guard || {};
  const ransom = data?.ransom || {};
  const secCrit = data?.sec_crit || {};
  const titan = data?.titan_exec || {};
  const chameleon = data?.chameleon || {};
  const summary = data?.summary || {};

  const fanotifyOn = Boolean(summary.fanotify_active);

  const layers = [
    {
      id: 'ap0',
      title: t('antispyware.ap0.title'),
      co: t('antispyware.ap0.co'),
      triggers: t('antispyware.ap0.trigger'),
      action: t('antispyware.ap0.action'),
      detail: t('antispyware.ap0.detail'),
      state: selfGuard.state,
      stats: `bpffs=${Boolean(selfGuard.bpffs_ok)} · pins=${Boolean(selfGuard.pins_ok)} · canary=${Boolean(selfGuard.canary_ok)} · events=${number(selfGuard.events)}`
    },
    {
      id: 'ap1',
      title: t('antispyware.ap1.title'),
      co: t('antispyware.ap1.co'),
      triggers: t('antispyware.ap1.trigger'),
      action: t('antispyware.ap1.action'),
      detail: t('antispyware.ap1.detail'),
      state: execInode.state,
      stats: `offsets=${Boolean(execInode.offsets_ok)} · trusted=${number(execInode.trusted)} · denied=${number(execInode.denied)} · credguard_denied=${number(cred.denied ?? cred.Denied ?? 0)}`
    },
    {
      id: 'ap2',
      title: t('antispyware.ap2.title'),
      co: t('antispyware.ap2.co'),
      triggers: t('antispyware.ap2.trigger'),
      action: t('antispyware.ap2.action'),
      detail: t('antispyware.ap2.detail'),
      state: bpfGuard.state,
      stats: `lsm=${Boolean(bpfGuard.lsm)} · tp=${Boolean(bpfGuard.tp)} · kprobe=${Boolean(bpfGuard.kprobe)} · loads=${number(bpfGuard.loads)} · helper_risk=${number(bpfGuard.helper_risk)}`
    },
    {
      id: 'ap3',
      title: t('antispyware.ap3.title'),
      co: t('antispyware.ap3.co'),
      triggers: t('antispyware.ap3.trigger'),
      action: t('antispyware.ap3.action'),
      detail: t('antispyware.ap3.detail'),
      state: crossView.state,
      stats: `domains=${number(crossView.domains)} · scans=${number(crossView.scans)} · contradictions=${number(crossView.contradictions)} · pkgdb=${String(crossView.pkgdb || '---')}`
    },
    {
      id: 'ap4',
      title: t('antispyware.ap4.title'),
      co: t('antispyware.ap4.co'),
      triggers: t('antispyware.ap4.trigger'),
      action: t('antispyware.ap4.action'),
      detail: t('antispyware.ap4.detail'),
      state: kernelHooks.state,
      stats: `io_uring=${Boolean(kernelHooks.io_uring)} · module_trace=${Boolean(kernelHooks.module_trace)} · loads=${number(kernelHooks.loads)} · rings=${number(kernelHooks.ring_creates)}`
    },
    {
      id: 'ap5',
      title: t('antispyware.ap5.title'),
      co: t('antispyware.ap5.co'),
      triggers: t('antispyware.ap5.trigger'),
      action: t('antispyware.ap5.action'),
      detail: t('antispyware.ap5.detail'),
      state: persistence.state,
      stats: `file_open=${Boolean(persistence.hook_file_open)} · mmap=${Boolean(persistence.hook_mmap)} · ptrace=${Boolean(persistence.hook_ptrace)} · secrets=${number(persistence.secrets)} · drifted=${number(persistence.drifted)}`
    },
    {
      id: 'ap6',
      title: t('antispyware.ap6.title'),
      co: t('antispyware.ap6.co'),
      triggers: t('antispyware.ap6.trigger'),
      action: t('antispyware.ap6.action'),
      detail: t('antispyware.ap6.detail'),
      state: dns.state || styx.sensor_state,
      stats: `styx_rx=${String(styxP2.rx_observation || '---')} · pcr_inc=${number(styxP2.pcr_incidents)} · dns_inc=${number(dns.incidents ?? dns.Incidents ?? 0)} · sbc=${String(data?.sbc_fusion?.state || '---')}`
    },
    {
      id: 'ap7',
      title: t('antispyware.ap7.title'),
      co: t('antispyware.ap7.co'),
      triggers: t('antispyware.ap7.trigger'),
      action: t('antispyware.ap7.action'),
      detail: t('antispyware.ap7.detail'),
      state: fanotifyOn ? 'active' : (summary.xdr_enabled ? 'observe' : 'disarmed'),
      stats: `fanotify=${fanotifyOn} · titan=${String(titan.state || '---')} · ransom=${String(ransom.state || ransom.State || '---')}`
    },
    {
      id: 'ap8',
      title: t('antispyware.ap8.title'),
      co: t('antispyware.ap8.co'),
      triggers: t('antispyware.ap8.trigger'),
      action: t('antispyware.ap8.action'),
      detail: t('antispyware.ap8.detail'),
      state: chameleon.active ? 'active' : 'observe',
      stats: `mode=${String(chameleon.mode || 'standard')} · pin_root=${String(chameleon.bpf_pin_root || '/sys/fs/bpf/gedefense')}`
    },
    {
      id: 'ap9',
      title: t('antispyware.ap9.title'),
      co: t('antispyware.ap9.co'),
      triggers: t('antispyware.ap9.trigger'),
      action: t('antispyware.ap9.action'),
      detail: t('antispyware.ap9.detail'),
      state: secCrit.state || 'observe',
      stats: `sec_crit=${String(secCrit.state || '---')} · reserve=${number(secCrit.quotas?.quarantine_reserve_bytes ?? 0)} B · rbac=step-up`
    }
  ];

  return layers;
}

function renderMatrixTable(layers) {
  const body = byID('antispywareMatrixBody');
  if (!body) return;
  const rows = layers.map(layer => {
    const tr = el('tr');
    const meta = stateMeta(layer.state);

    const tdTitle = el('td');
    tdTitle.append(el('strong', 'd-block', layer.title), el('small', 'text-muted font-mono', layer.stats));

    const tdCo = el('td', '', layer.co);
    const tdTrig = el('td', '', layer.triggers);
    const tdAct = el('td', '', layer.action);

    const tdState = el('td');
    tdState.append(el('span', meta.cls, meta.label));

    tr.append(tdTitle, tdCo, tdTrig, tdAct, tdState);
    return tr;
  });
  body.replaceChildren(...rows);
}

function renderArchitectureCards(layers) {
  const root = byID('antispywareCardsRoot');
  if (!root) return;
  const cards = layers.map(layer => {
    const card = el('article', 'glass-panel panel-padded v61-panel');
    const head = el('div', 'v61-panel-head');
    const headCopy = document.createElement('div');
    headCopy.append(el('h3', '', layer.title), el('p', 'fs-xs text-muted mt-xs', layer.detail));
    const meta = stateMeta(layer.state);
    head.append(headCopy, el('span', meta.cls, meta.label));

    const kv = el('dl', 'v61-kv-grid');
    for (const [label, value, isMono] of [
      [t('antispyware.guide.coLabel'), layer.co, false],
      [t('antispyware.guide.triggerLabel'), layer.triggers, false],
      [t('antispyware.guide.actionLabel'), layer.action, false],
      [t('antispyware.guide.roleLabel'), layer.stats, true]
    ]) {
      const cell = document.createElement('div');
      cell.className = 'v61-kv';
      cell.append(el('dt', '', label), el('dd', isMono ? 'v61-mono' : '', value));
      kv.append(cell);
    }
    card.append(head, kv);
    return card;
  });
  root.replaceChildren(...cards);
}

function renderAntispywareStatus(data) {
  const summary = data?.summary || {};
  const selfGuard = data?.self_guard || {};
  const execInode = data?.exec_inode || {};
  const cred = data?.credential_guard || {};
  const secCrit = data?.sec_crit || {};

  const active = Number(summary.active_planes || 0);
  const total = Number(summary.total_planes || 12);
  text('antispywarePlanesKpi', `${number(active)} / ${number(total)}`);
  text('antispywareSensorKpi', `${String(summary.xdr_mode || 'observe').toUpperCase()} · ${summary.fanotify_active ? 'fanotify-exec' : (summary.sensor || '---')}`);
  text('antispywareSelfGuardKpi', `${String(selfGuard.state || '---').toUpperCase()} · bpffs=${Boolean(selfGuard.bpffs_ok)} · canary=${Boolean(selfGuard.canary_ok)}`);
  text('antispywareExecInodeKpi', `${String(execInode.state || '---').toUpperCase()} · offsets=${Boolean(execInode.offsets_ok)}`);
  text('antispywareCredGuardKpi', `${String(cred.state || cred.State || '---').toUpperCase()} · denied=${number(cred.denied ?? cred.Denied ?? 0)}`);
  text('antispywareSecCritKpi', `${String(secCrit.state || '---').toUpperCase()} · drop=${number(secCrit.drops ?? 0)}`);

  const overallGood = Boolean(summary.core_connected) && active > 0;
  setPill('antispywarePill', overallGood ? 'active' : 'observe', `${number(active)}/${number(total)} ACTIVE`, overallGood);

  const layers = buildMatrixRows(data || {});
  renderMatrixTable(layers);
  renderArchitectureCards(layers);
}

export async function loadAntispywareView() {
  const data = await getAntispywareStatus();
  renderAntispywareStatus(data);
  return data;
}

export function initAntispywareModule() {
  byID('antispywareRefreshBtn')?.addEventListener('click', () => {
    loadAntispywareView().catch(handleActionError);
  });
  byID('antispywareOpenXdrBtn')?.addEventListener('click', () => {
    document.querySelector('[data-view="xdr"]')?.click();
  });
}
