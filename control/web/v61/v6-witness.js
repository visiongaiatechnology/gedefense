// STATUS: DIAMANT VGT SUPREME
'use strict';

// V6 panel — out-of-band witness.
//
// Checkpoint creation is recoverable and only records intent; pushing a signed
// checkpoint off the host is the destructive direction and therefore requires
// the typed phrase "PUSH WITNESS". The panel shows the local checkpoint, the
// last witness acknowledgement, the outbox pressure and every degraded reason
// the engine reports — an unwired or disabled witness never looks healthy here.

import { t } from '../i18n.js';
import { toast } from '../render.js';
import {
  asBool,
  asObject,
  bindAction,
  confirmAction,
  formatSize,
  formatCount,
  formatStamp,
  getJSON,
  initV61Shared,
  refusalText,
  sendJSON,
  setNotice,
  setText,
  setTone
} from './v6.js';

const STATUS_PATH = '/api/v1/witness/status';

export function initWitnessModule() {
  initV61Shared();
  bindAction('witnessRefreshBtn', () => loadWitnessView());
  bindAction('witnessCheckpointBtn', checkpointWitness);
  bindAction('witnessPushBtn', pushWitness);
}

export async function loadWitnessView() {
  try {
    renderStatus(asObject(await getJSON(STATUS_PATH)));
  } catch (error) {
    setNotice('witnessReason', refusalText(error, 'v61.v6.witness.unavailable'), 'bad');
    setTone('witnessPill', t('v61.v6.common.unavailable'), 'danger');
  }
}

async function checkpointWitness() {
  const confirmed = await confirmAction({
    titleKey: 'v61.v6.witness.checkpointTitle',
    bodyKey: 'v61.v6.witness.checkpointBody',
    submitKey: 'v61.v6.witness.checkpointSubmit',
    danger: false,
    requireReason: false,
    detail: t('v61.v6.witness.checkpointDetail')
  });
  if (!confirmed) return;
  await mutate('/api/v1/witness/checkpoint', {}, 'v61.v6.witness.checkpointDone');
}

async function pushWitness() {
  const confirmed = await confirmAction({
    titleKey: 'v61.v6.witness.pushTitle',
    bodyKey: 'v61.v6.witness.pushBody',
    submitKey: 'v61.v6.witness.pushSubmit',
    phrase: 'PUSH WITNESS',
    requireReason: false,
    detail: t('v61.v6.witness.pushDetail')
  });
  if (!confirmed) return;
  // The push route accepts exactly one field; sending an extra reason would be a
  // malformed body. The typed phrase is the intent proof for this direction.
  await mutate('/api/v1/witness/push', { confirmation: 'PUSH WITNESS' }, 'v61.v6.witness.pushDone');
}

async function mutate(path, body, doneKey) {
  setNotice('witnessActionResult', '');
  try {
    const result = asObject(await sendJSON(path, 'POST', body));
    const status = asObject(result.status);
    const message = t(doneKey);
    setNotice('witnessActionResult', message, 'good');
    toast(message, 'good');
    if (Object.keys(status).length) renderStatus(status);
    else await loadWitnessView();
  } catch (error) {
    setNotice('witnessActionResult', refusalText(error, 'v61.v6.witness.actionFailed'), 'bad');
    toast(refusalText(error), 'danger', error?.errorID || '');
  }
}

function renderStatus(status) {
  const checkpoint = asObject(status.checkpoint);
  const ack = asObject(status.last_ack);
  const outbox = asObject(status.outbox);
  const enabled = asBool(status.enabled);
  const wired = asBool(status.wired);
  const degraded = asBool(status.degraded);
  const healthy = asBool(status.healthy);
  const state = !enabled ? 'disabled' : degraded ? 'degraded' : healthy ? 'healthy' : 'degraded';

  setTone('witnessPill', stateLabel(state), stateTone(state));
  setTone('witnessEnabledKpi', t(enabled ? 'v61.v6.common.enabled' : 'v61.v6.common.disabled'), enabled ? 'good' : 'muted');
  setText('witnessModeKpi', status.mode || '—');
  setTone('witnessWiredKpi', t(wired ? 'v61.v6.common.yes' : 'v61.v6.common.no'), wired ? 'good' : 'warn');
  setTone('witnessHealthyKpi', t(healthy ? 'v61.v6.common.yes' : 'v61.v6.common.no'), healthy ? 'good' : 'danger');
  setTone('witnessDegradedKpi', t(degraded ? 'v61.v6.common.yes' : 'v61.v6.common.no'), degraded ? 'danger' : 'good');
  setTone('witnessChallengeKpi', t(asBool(status.challenge_pending) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), asBool(status.challenge_pending) ? 'warn' : 'muted');
  setTone('witnessEquivocationKpi', t(asBool(status.equivocation) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), asBool(status.equivocation) ? 'danger' : 'good');
  setText('witnessQuoteKpi', status.quote_kind || '—');
  setText('witnessKeyBindingKpi', status.key_binding || '—');
  setText('witnessOutboxDepthKpi', formatCount(outbox.depth));
  setText('witnessOutboxBytesKpi', formatSize(Number(outbox.bytes) || 0));
  setTone('witnessOutboxFullKpi', t(asBool(outbox.full) ? 'v61.v6.common.yes' : 'v61.v6.common.no'), asBool(outbox.full) ? 'danger' : 'good');
  setText('witnessOutboxOldest', outbox.oldest_at ? formatStamp(outbox.oldest_at) : t('v61.v6.common.none'));

  setText('witnessCheckpointId', checkpoint.id || '—');
  setText('witnessCheckpointEpoch', checkpoint.epoch === undefined ? '—' : formatCount(checkpoint.epoch));
  setText('witnessCheckpointSeq', checkpoint.sequence === undefined ? '—' : formatCount(checkpoint.sequence));
  setText('witnessCheckpointHash', checkpoint.head_hash || '—');
  setText('witnessCheckpointAt', checkpoint.created_at ? formatStamp(checkpoint.created_at) : t('v61.v6.common.none'));
  setText('witnessAckSeq', ack.witness_seq === undefined ? '—' : formatCount(ack.witness_seq));
  setText('witnessAckId', ack.checkpoint_id || '—');
  setText('witnessAckAt', ack.at ? formatStamp(ack.at) : t('v61.v6.common.none'));
  setText('witnessEquivocationDetail', asBool(status.equivocation)
    ? t('v61.v6.witness.equivocationDetail', { kind: status.equivocation_kind || '—', at: formatStamp(status.equivocation_at) })
    : t('v61.v6.witness.equivocationClear'));

  const reasons = [String(status.degraded_reason || '').trim(), String(status.last_error || '').trim()].filter(Boolean);
  setNotice('witnessReason', reasons.join(' · '), healthy ? 'good' : 'warn');
}

function stateLabel(state) {
  switch (state) {
    case 'healthy':
      return t('v61.v6.state.healthy');
    case 'degraded':
      return t('v61.v6.state.degraded');
    case 'disabled':
      return t('v61.v6.common.disabled');
    default:
      return t('v61.v6.common.unknown');
  }
}

function stateTone(state) {
  switch (state) {
    case 'healthy':
      return 'good';
    case 'degraded':
      return 'danger';
    case 'disabled':
      return 'muted';
    default:
      return 'warn';
  }
}
