'use strict';

const history = { rx: [], tx: [], max: 90 };

export function appendTraffic(rx, tx) {
  history.rx.push(Number.isFinite(rx) ? Math.max(0, rx) : 0);
  history.tx.push(Number.isFinite(tx) ? Math.max(0, tx) : 0);
  if (history.rx.length > history.max) history.rx.shift();
  if (history.tx.length > history.max) history.tx.shift();
}

function line(ctx, values, width, height, maximum, color) {
  if (values.length < 2) return;
  ctx.beginPath();
  values.forEach((value, index) => {
    const x = (index / (history.max - 1)) * width;
    const y = height - (value / maximum) * (height - 24) - 12;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.shadowColor = color;
  ctx.shadowBlur = 10;
  ctx.stroke();
  ctx.shadowBlur = 0;
}

export function drawTraffic(canvas) {
  if (!(canvas instanceof HTMLCanvasElement)) return;
  const ratio = Math.max(1, globalThis.devicePixelRatio || 1);
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(320, Math.floor(rect.width));
  const height = Math.max(220, Math.floor(rect.height));
  if (canvas.width !== width * ratio || canvas.height !== height * ratio) {
    canvas.width = width * ratio;
    canvas.height = height * ratio;
  }
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.strokeStyle = 'rgba(105, 220, 255, .08)';
  ctx.lineWidth = 1;
  for (let y = 12; y < height; y += Math.max(34, height / 6)) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
  const maximum = Math.max(1, ...history.rx, ...history.tx);
  const fill = ctx.createLinearGradient(0, 0, 0, height);
  fill.addColorStop(0, 'rgba(71, 225, 255, .12)');
  fill.addColorStop(1, 'rgba(71, 225, 255, 0)');
  if (history.rx.length > 1) {
    ctx.beginPath();
    history.rx.forEach((value, index) => {
      const x = (index / (history.max - 1)) * width;
      const y = height - (value / maximum) * (height - 24) - 12;
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(((history.rx.length - 1) / (history.max - 1)) * width, height);
    ctx.lineTo(0, height);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
  }
  line(ctx, history.rx, width, height, maximum, '#47e1ff');
  line(ctx, history.tx, width, height, maximum, '#9a7cff');
}
