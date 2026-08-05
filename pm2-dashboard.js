#!/usr/bin/env node
'use strict';

try { require('dotenv').config(); } catch (_) { /* dotenv optional */ }

const pm2 = require('pm2');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch (_) { /* email optional */ }

// ────────────────────────────────────────────────
// Config (from .env or defaults)
// ────────────────────────────────────────────────
const cfg = {
  port: parseInt(process.env.PORT || '3099', 10),
  checkInterval: parseInt(process.env.CHECK_INTERVAL_MS || '10000', 10),
  historyMax: parseInt(process.env.HISTORY_MAX || '300', 10),
  metricsBuffer: parseInt(process.env.METRICS_BUFFER || '60', 10),
  memoryAlertMb: parseInt(process.env.MEMORY_ALERT_MB || '5500', 10),
  cpuSustainedPct: parseInt(process.env.CPU_SUSTAINED_PCT || '85', 10),
  cpuSustainedPolls: parseInt(process.env.CPU_SUSTAINED_POLLS || '4', 10),
  webhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  throttleMs: parseInt(process.env.ALERT_THROTTLE_MS || '300000', 10),
  escalationMin: parseInt(process.env.ESCALATION_MINUTES || '10', 10),
  accessToken: process.env.ACCESS_TOKEN || '',
  ignore: new Set((process.env.IGNORE_PROCESSES || 'pm2-dashboard').split(',').map(s => s.trim()).filter(Boolean)),
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    to: process.env.ALERT_EMAIL_TO || ''
  }
};

const HISTORY_FILE = path.join(__dirname, 'pm2-downtime-history.json');
const LOG_FILE = path.join(__dirname, 'pm2-monitor.log');
const MAX_LOG_BYTES = 5 * 1024 * 1024;
const MONITOR_STARTED_AT = Date.now();

// ────────────────────────────────────────────────
// State
// ────────────────────────────────────────────────
let processes = [];
let history = [];
let metrics = {};               // name -> [{ts, cpu, mem}]
let lastAlert = {};
let lastPollAt = null;
let historyDirty = false;
let busConnected = false;
let pm2ConnectionReady = false;

try {
  if (fs.existsSync(HISTORY_FILE)) {
    history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
  }
} catch (e) {
  console.error('Could not load history:', e.message);
}

// ────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────
function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  try {
    if (fs.existsSync(LOG_FILE) && fs.statSync(LOG_FILE).size > MAX_LOG_BYTES) {
      fs.renameSync(LOG_FILE, LOG_FILE.replace(/\.log$/, `.${Date.now()}.log`));
    }
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch (_) { /* non-fatal */ }
}

function persistHistory() {
  if (!historyDirty) return;
  try {
    if (history.length > cfg.historyMax) history = history.slice(0, cfg.historyMax);
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
    historyDirty = false;
  } catch (e) {
    log('Failed to persist history: ' + e.message);
  }
}

function formatDuration(ms) {
  if (ms == null) return '-';
  if (ms < 1000) return ms + ' ms';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + ' s';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function uptimePercent(name, days = 7) {
  const cutoff = Date.now() - days * 86400000;
  const events = history.filter(h => h.name === name && new Date(h.downAt).getTime() >= cutoff);
  let downMs = 0;
  for (const e of events) {
    const start = Math.max(new Date(e.downAt).getTime(), cutoff);
    const end = e.upAt ? new Date(e.upAt).getTime() : Date.now();
    downMs += Math.max(0, end - start);
  }
  const total = days * 86400000;
  return Math.max(0, Math.min(100, ((total - downMs) / total) * 100)).toFixed(2);
}

function escapeHtml(str) {
  return String(str == null ? '' : str).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// ────────────────────────────────────────────────
// Alerting (throttle + escalation)
// ────────────────────────────────────────────────
function shouldAlert(name, kind) {
  const key = `${name}:${kind}`;
  const now = Date.now();
  const prev = lastAlert[key];
  if (!prev || now - prev.ts > cfg.throttleMs) {
    lastAlert[key] = { ts: now, count: 1 };
    return true;
  }
  prev.count++;
  return false;
}

function sendAlert(text, name = '', kind = 'generic') {
  if (name && cfg.ignore.has(name)) return;
  if (name && !shouldAlert(name, kind)) {
    log(`Throttled alert -> ${name} (${kind})`);
    return;
  }

  log(`ALERT: ${text}`);

  if (cfg.webhookUrl) {
    try {
      const payload = JSON.stringify({ text, content: text });
      const url = new URL(cfg.webhookUrl);
      const lib = url.protocol === 'http:' ? http : https;
      const req = lib.request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      });
      req.on('error', e => log('Webhook error: ' + e.message));
      req.write(payload);
      req.end();
    } catch (e) {
      log('Webhook failed: ' + e.message);
    }
  }

  if (nodemailer && cfg.smtp.host && cfg.smtp.to) {
    try {
      const transporter = nodemailer.createTransport({
        host: cfg.smtp.host,
        port: cfg.smtp.port,
        secure: cfg.smtp.port === 465,
        auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.pass } : undefined
      });
      transporter.sendMail({
        from: cfg.smtp.user || 'pm2-monitor@localhost',
        to: cfg.smtp.to,
        subject: `[PM2] ${text.slice(0, 80)}`,
        text
      }).catch(e => log('Email error: ' + e.message));
    } catch (e) {
      log('Email setup failed: ' + e.message);
    }
  }
}

// ────────────────────────────────────────────────
// Event recording
// ────────────────────────────────────────────────
function recordDown(name, reason = 'status') {
  if (cfg.ignore.has(name)) return;
  const open = history.find(h => h.name === name && !h.upAt);
  if (open) return;
  history.unshift({ name, downAt: new Date().toISOString(), upAt: null, durationMs: null, reason });
  historyDirty = true;
  log(`DOWN -> ${name} (${reason})`);
  sendAlert(`\u{1F534} ${name} went DOWN (${reason})`, name, 'down');
}

function recordUp(name) {
  const open = history.find(h => h.name === name && !h.upAt);
  if (!open) return;
  open.upAt = new Date().toISOString();
  open.durationMs = Date.now() - new Date(open.downAt).getTime();
  historyDirty = true;
  log(`UP -> ${name} (down ${formatDuration(open.durationMs)})`);
  sendAlert(`\u{1F7E2} ${name} is back UP (was down ${formatDuration(open.durationMs)})`, name, 'up');
}

// Intentional removal (pm2 delete): close any open outage silently, no alert.
function recordDeleted(name) {
  const open = history.find(h => h.name === name && !h.upAt);
  if (open) {
    open.upAt = new Date().toISOString();
    open.durationMs = 0;
    open.reason = (open.reason || 'status') + ' (process deleted)';
    historyDirty = true;
    log(`INFO -> ${name} removed from PM2, closing open outage record without alert`);
  }
}

// ────────────────────────────────────────────────
// PM2 Event Bus (real-time) — reuses the single persistent connection
// ────────────────────────────────────────────────
function startBus() {
  pm2.launchBus((err, bus) => {
    if (err) {
      log('Bus error: ' + err.message);
      setTimeout(startBus, 5000);
      return;
    }
    busConnected = true;
    log('PM2 event bus connected');

    bus.on('process:event', (packet) => {
      const name = packet.process && packet.process.name;
      if (!name || cfg.ignore.has(name)) return;
      const event = packet.event;

      if (event === 'exit' || event === 'stop') {
        recordDown(name, event);
      } else if (event === 'delete') {
        recordDeleted(name);
      } else if (event === 'online' || event === 'start') {
        recordUp(name);
      } else if (event === 'restart') {
        recordUp(name); // close any window that was open
        history.unshift({
          name,
          downAt: new Date().toISOString(),
          upAt: new Date().toISOString(),
          durationMs: 0,
          reason: 'restart event'
        });
        historyDirty = true;
        sendAlert(`\u26A0\uFE0F ${name} restarted (crash-loop or manual restart)`, name, 'restart');
      }
    });

    bus.on('error', () => {
      busConnected = false;
      log('Bus disconnected - retrying...');
      setTimeout(startBus, 5000);
    });
  });
}

// ────────────────────────────────────────────────
// Metrics polling — uses the already-open pm2 connection, never disconnects mid-run
// ────────────────────────────────────────────────
function pollMetrics() {
  if (!pm2ConnectionReady) return;

  pm2.list((err, list) => {
    if (err) {
      log('PM2 list error: ' + err.message);
      return;
    }

    lastPollAt = Date.now();
    const seenNames = new Set();

    processes = list.map(p => {
      const memMb = Math.round(((p.monit && p.monit.memory) || 0) / 1024 / 1024);
      const cpu = (p.monit && p.monit.cpu) || 0;
      const name = p.name;
      seenNames.add(name);

      if (!metrics[name]) metrics[name] = [];
      metrics[name].push({ ts: Date.now(), cpu, mem: memMb });
      if (metrics[name].length > cfg.metricsBuffer) metrics[name].shift();

      if (!cfg.ignore.has(name)) {
        if (memMb >= cfg.memoryAlertMb) {
          sendAlert(`\u{1F7E0} ${name} memory high: ${memMb} MB (threshold ${cfg.memoryAlertMb} MB)`, name, 'memory');
        }

        const recent = metrics[name].slice(-cfg.cpuSustainedPolls);
        if (recent.length >= cfg.cpuSustainedPolls &&
            recent.every(s => s.cpu >= cfg.cpuSustainedPct)) {
          sendAlert(`\u{1F7E0} ${name} CPU sustained >= ${cfg.cpuSustainedPct}%`, name, 'cpu');
        }

        const open = history.find(h => h.name === name && !h.upAt);
        if (open) {
          const downMin = (Date.now() - new Date(open.downAt).getTime()) / 60000;
          if (downMin >= cfg.escalationMin) {
            sendAlert(`\u{1F6A8} ESCALATION: ${name} still DOWN for ${Math.round(downMin)} min`, name, 'escalation');
          }
        }
      }

      return {
        id: p.pm_id,
        name,
        status: p.pm2_env.status,
        uptime: p.pm2_env.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : 0,
        restarts: p.pm2_env.restart_time || 0,
        cpu,
        memory: memMb,
        pid: p.pid,
        outLog: p.pm2_env.pm_out_log_path || null,
        errLog: p.pm2_env.pm_err_log_path || null
      };
    });

    // Any name that has an open outage but no longer appears in `pm2 list` at all
    // (deleted outside of a clean 'delete' bus event, e.g. daemon restart) — close it quietly.
    history.filter(h => !h.upAt && !seenNames.has(h.name)).forEach(h => {
      h.upAt = new Date().toISOString();
      h.durationMs = 0;
      h.reason = (h.reason || 'status') + ' (process no longer present)';
      historyDirty = true;
    });

    persistHistory();
  });
}

// ────────────────────────────────────────────────
// HTTP helpers
// ────────────────────────────────────────────────
function isAuthorized(req) {
  if (!cfg.accessToken) return true;
  const url = new URL(req.url, `http://${req.headers.host}`);
  return url.searchParams.get('token') === cfg.accessToken ||
         req.headers['x-access-token'] === cfg.accessToken;
}

function send(res, status, body, type = 'text/html') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}

function tailLog(name, lines = 300) {
  const proc = processes.find(p => p.name === name);
  const base = path.join(os.homedir(), '.pm2', 'logs');
  const outPath = (proc && proc.outLog) || path.join(base, `${name}-out.log`);
  const errPath = (proc && proc.errLog) || path.join(base, `${name}-error.log`);

  let content = '';
  for (const f of [errPath, outPath]) {
    try {
      if (f && fs.existsSync(f)) {
        const data = fs.readFileSync(f, 'utf8').split('\n');
        content += `\n===== ${path.basename(f)} (last ${lines} lines) =====\n`;
        content += data.slice(-lines).join('\n');
      }
    } catch (_) { /* skip unreadable log */ }
  }
  return content || 'No logs found for this process.';
}

// ────────────────────────────────────────────────
// Dashboard UI
// ────────────────────────────────────────────────
function statusDotClass(status) {
  return status === 'online' ? 'dot-online' : 'dot-offline';
}

function renderDashboard(tokenQ = '') {
  const onlineCount = processes.filter(p => p.status === 'online').length;
  const offlineCount = processes.length - onlineCount;
  const totalRestarts = processes.reduce((s, p) => s + p.restarts, 0);
  const maxMem = Math.max(...processes.map(p => p.memory), 0);
  const avgSla = processes.length
    ? (processes.reduce((s, p) => s + parseFloat(uptimePercent(p.name)), 0) / processes.length).toFixed(2)
    : '100.00';

  const stale = lastPollAt && (Date.now() - lastPollAt) > cfg.checkInterval * 3;

  const kpiCards = `
    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-icon icon-online">&#9679;</div>
        <div>
          <div class="kpi-value">${onlineCount}<span class="kpi-value-muted">/${processes.length}</span></div>
          <div class="kpi-label">Processes Online</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-offline">&#9679;</div>
        <div>
          <div class="kpi-value">${offlineCount}</div>
          <div class="kpi-label">Processes Down</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-restart">&#8635;</div>
        <div>
          <div class="kpi-value">${totalRestarts}</div>
          <div class="kpi-label">Total Restarts</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-mem">&#9612;</div>
        <div>
          <div class="kpi-value">${maxMem}<span class="kpi-value-muted">MB</span></div>
          <div class="kpi-label">Peak Memory</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-sla">&#10003;</div>
        <div>
          <div class="kpi-value">${avgSla}<span class="kpi-value-muted">%</span></div>
          <div class="kpi-label">Avg 7-day SLA</div>
        </div>
      </div>
    </div>`;

  const rows = [...processes]
    .sort((a, b) => (a.status === 'online' ? 1 : 0) - (b.status === 'online' ? 1 : 0) || a.name.localeCompare(b.name))
    .map(p => {
      const cls = p.status === 'online' ? 'online' : 'offline';
      const ignored = cfg.ignore.has(p.name) ? ' <span class="tag-ignored">ignored</span>' : '';
      return `
        <tr class="${cls}" data-name="${escapeHtml(p.name.toLowerCase())}">
          <td class="mono">${p.id}</td>
          <td><span class="dot ${statusDotClass(p.status)}"></span><strong>${escapeHtml(p.name)}</strong>${ignored}</td>
          <td><span class="badge ${cls}">${escapeHtml(p.status)}</span></td>
          <td class="mono">${formatDuration(p.uptime)}</td>
          <td class="mono">${uptimePercent(p.name)}%</td>
          <td class="mono">${p.restarts}</td>
          <td class="mono">${p.cpu}%</td>
          <td class="mono">${p.memory} MB</td>
          <td class="mono">${p.pid || '-'}</td>
          <td><a class="btn" href="/logs/${encodeURIComponent(p.name)}${tokenQ}">Logs</a></td>
        </tr>`;
    }).join('');

  const histRows = history.slice(0, 30).map(h => `
    <tr>
      <td><strong>${escapeHtml(h.name)}</strong></td>
      <td class="mono">${new Date(h.downAt).toLocaleString()}</td>
      <td class="mono">${h.upAt ? new Date(h.upAt).toLocaleString() : '<span class="still-down">still down</span>'}</td>
      <td class="mono">${h.durationMs != null ? formatDuration(h.durationMs) : '-'}</td>
      <td>${escapeHtml(h.reason || 'status')}</td>
    </tr>`).join('');

  const lastPoll = lastPollAt ? formatDuration(Date.now() - lastPollAt) + ' ago' : 'never';
  const busStatus = busConnected ? 'Live' : 'Reconnecting';
  const monitorUptime = formatDuration(Date.now() - MONITOR_STARTED_AT);
  const hostname = escapeHtml(os.hostname());

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PM2 Production Monitor${stale ? ' — stale' : ''}</title>
  <meta http-equiv="refresh" content="20${tokenQ}">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22><circle cx=%2216%22 cy=%2216%22 r=%2214%22 fill=%22%2322c55e%22/></svg>">
  <style>
    :root {
      --bg: #f3f4f8;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e5e7eb;
      --accent: #4f46e5;
      --green: #16a34a;
      --red: #dc2626;
      --orange: #d97706;
      --radius: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      -webkit-font-smoothing: antialiased;
    }
    .topbar {
      background: #0b1120;
      color: #f8fafc;
      padding: 16px 32px;
      display: flex;
      align-items: center;
      gap: 16px;
      position: sticky;
      top: 0;
      z-index: 20;
      box-shadow: 0 2px 12px rgb(0 0 0 / 0.15);
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; }
    .brand-mark {
      width: 26px; height: 26px; border-radius: 8px;
      background: linear-gradient(135deg, var(--accent), #22c55e);
      display: inline-block;
    }
    .topbar-meta { display: flex; gap: 10px; margin-left: auto; align-items: center; flex-wrap: wrap; }
    .pill {
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.12);
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 0.78rem;
      color: #cbd5e1;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pill.live::before {
      content: '';
      width: 7px; height: 7px; border-radius: 50%;
      background: ${busConnected ? 'var(--green)' : 'var(--orange)'};
      ${busConnected ? 'box-shadow: 0 0 0 rgba(34,197,94,0.5); animation: pulse 1.8s infinite;' : ''}
    }
    @keyframes pulse {
      0%   { box-shadow: 0 0 0 0 rgba(34,197,94,0.5); }
      70%  { box-shadow: 0 0 0 6px rgba(34,197,94,0); }
      100% { box-shadow: 0 0 0 0 rgba(34,197,94,0); }
    }
    .btn-refresh {
      background: var(--accent);
      color: white;
      border: none;
      padding: 7px 16px;
      border-radius: 8px;
      font-size: 0.82rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    .btn-refresh:hover { filter: brightness(1.1); }

    .wrap { max-width: 1320px; margin: 0 auto; padding: 28px 32px 60px; }
    .stale-banner {
      background: #fef3c7; color: #92400e; border: 1px solid #fde68a;
      padding: 10px 16px; border-radius: 10px; font-size: 0.85rem; margin-bottom: 20px;
      display: ${stale ? 'block' : 'none'};
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .kpi {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 20px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: 0 1px 2px rgb(0 0 0 / 0.03);
    }
    .kpi-icon {
      width: 38px; height: 38px; border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1rem; flex-shrink: 0;
    }
    .icon-online  { background: #dcfce7; color: var(--green); }
    .icon-offline { background: #fee2e2; color: var(--red); }
    .icon-restart { background: #ede9fe; color: var(--accent); }
    .icon-mem     { background: #ffedd5; color: var(--orange); }
    .icon-sla     { background: #dbeafe; color: #2563eb; }
    .kpi-value { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.1; }
    .kpi-value-muted { font-size: 0.85rem; color: var(--muted); font-weight: 500; margin-left: 2px; }
    .kpi-label { font-size: 0.78rem; color: var(--muted); margin-top: 3px; }

    .card {
      background: var(--card);
      border-radius: var(--radius);
      border: 1px solid var(--border);
      box-shadow: 0 1px 2px rgb(0 0 0 / 0.03);
      overflow: hidden;
    }
    .card-header {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      font-weight: 600;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .card-header .sub { color: var(--muted); font-weight: 400; font-size: 0.78rem; }
    .card-body { padding: 16px 18px; }

    .section-title {
      font-size: 1rem; font-weight: 700; margin: 30px 0 12px;
      display: flex; align-items: center; gap: 10px;
    }
    .filter-input {
      margin-left: auto;
      border: 1px solid var(--border);
      background: var(--card);
      padding: 7px 12px;
      border-radius: 8px;
      font-size: 0.82rem;
      width: 220px;
    }
    .filter-input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }

    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 11px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.83rem; }
    th {
      background: #f8fafc; color: var(--muted); font-weight: 600;
      text-transform: uppercase; font-size: 0.68rem; letter-spacing: 0.05em;
    }
    tbody tr:hover td { background: #f8fafc; }
    tr.offline td { background: #fef2f2; }
    tr.offline:hover td { background: #fde8e8; }
    .mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, 'SF Mono', Menlo, monospace; }
    .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 8px; }
    .dot-online { background: var(--green); }
    .dot-offline { background: var(--red); }
    .badge { padding: 3px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }
    .badge.online  { background: #dcfce7; color: #166534; }
    .badge.offline { background: #fee2e2; color: #991b1b; }
    .tag-ignored {
      font-size: 0.68rem; color: var(--muted); background: #f1f5f9;
      padding: 1px 7px; border-radius: 999px; margin-left: 6px; font-weight: 500;
    }
    .still-down { color: var(--red); font-style: italic; }
    .btn {
      display: inline-block; padding: 5px 13px; background: var(--accent); color: white;
      border-radius: 7px; text-decoration: none; font-size: 0.78rem; font-weight: 600;
    }
    .btn:hover { filter: brightness(1.08); }
    .empty { text-align: center; color: var(--muted); padding: 44px; font-size: 0.88rem; }
    footer { text-align: center; color: var(--muted); font-size: 0.75rem; padding: 30px 0 10px; }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand"><span class="brand-mark"></span> PM2 Production Monitor</div>
    <div class="topbar-meta">
      <span class="pill">${hostname}</span>
      <span class="pill">Monitor up ${monitorUptime}</span>
      <span class="pill">Last poll ${lastPoll}</span>
      <span class="pill live">Event bus: ${busStatus}</span>
      <a href="/${tokenQ}" class="btn-refresh">Refresh</a>
    </div>
  </div>

  <div class="wrap">
    <div class="stale-banner">&#9888; No successful poll in a while — the monitor process itself may be stalled or PM2 is unreachable.</div>

    ${kpiCards}

    <div class="section-title">
      Processes
      <input class="filter-input" id="filterInput" type="text" placeholder="Filter by name...">
    </div>
    <div class="card">
      <table id="procTable">
        <thead>
          <tr>
            <th>ID</th><th>Name</th><th>Status</th><th>Uptime</th>
            <th>7d SLA</th><th>Restarts</th><th>CPU</th><th>Memory</th><th>PID</th><th></th>
          </tr>
        </thead>
        <tbody>
          ${rows || '<tr><td colspan="10" class="empty">No processes found</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="section-title">Recent Downtime &amp; Restarts</div>
    <div class="card">
      <table>
        <thead>
          <tr><th>Process</th><th>Down at</th><th>Up at</th><th>Duration</th><th>Reason</th></tr>
        </thead>
        <tbody>
          ${histRows || '<tr><td colspan="5" class="empty">No events recorded yet</td></tr>'}
        </tbody>
      </table>
    </div>

    <footer>PM2 Production Monitor &middot; <a href="/health${tokenQ}" style="color:inherit">health</a> &middot; <a href="/api/status${tokenQ}" style="color:inherit">raw json</a></footer>
  </div>

  <script>
    document.getElementById('filterInput').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#procTable tbody tr').forEach(row => {
        const name = row.dataset.name || '';
        row.style.display = name.includes(q) ? '' : 'none';
      });
    });
  </script>
</body>
</html>`;
}

function renderLogsPage(name, content, tokenQ) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Logs - ${escapeHtml(name)}</title>
  <style>
    body { margin: 0; font-family: ui-monospace, 'SF Mono', Menlo, monospace; background: #0b1120; color: #e2e8f0; }
    header {
      background: #111827; padding: 14px 24px; display: flex; align-items: center; gap: 16px;
      border-bottom: 1px solid #1f2937; position: sticky; top: 0; z-index: 10;
      font-family: -apple-system, system-ui, sans-serif;
    }
    h1 { font-size: 1rem; margin: 0; font-weight: 600; }
    a.back { color: #818cf8; text-decoration: none; font-size: 0.85rem; }
    pre { margin: 0; padding: 22px 24px; font-size: 12.5px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
  <header>
    <a class="back" href="/${tokenQ}">&larr; Back to Dashboard</a>
    <h1>Logs: ${escapeHtml(name)}</h1>
  </header>
  <pre>${escapeHtml(content)}</pre>
</body>
</html>`;
}

// ────────────────────────────────────────────────
// HTTP Server
// ────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  if (!isAuthorized(req)) {
    return send(res, 401, 'Unauthorized');
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const tokenQ = cfg.accessToken ? `?token=${cfg.accessToken}` : '';

  if (url.pathname === '/' || url.pathname === '/index.html') {
    return send(res, 200, renderDashboard(tokenQ));
  }

  if (url.pathname === '/api/status') {
    return send(res, 200, JSON.stringify({
      processes, history: history.slice(0, 50), lastPollAt, busConnected
    }, null, 2), 'application/json');
  }

  if (url.pathname === '/health') {
    const stale = lastPollAt && (Date.now() - lastPollAt) > cfg.checkInterval * 3;
    const hasPolled = lastPollAt !== null;
    const allOnline = hasPolled && !stale &&
      processes.every(p => p.status === 'online' || cfg.ignore.has(p.name));
    const body = {
      status: allOnline ? 'ok' : 'degraded',
      polled: hasPolled,
      stale: !!stale,
      busConnected,
      downProcesses: processes.filter(p => p.status !== 'online' && !cfg.ignore.has(p.name)).map(p => p.name)
    };
    return send(res, allOnline ? 200 : 503, JSON.stringify(body, null, 2), 'application/json');
  }

  if (url.pathname.startsWith('/logs/')) {
    const name = decodeURIComponent(url.pathname.slice(6).split('?')[0]);
    const content = tailLog(name, 300);
    return send(res, 200, renderLogsPage(name, content, tokenQ));
  }

  send(res, 404, 'Not found');
});

// ────────────────────────────────────────────────
// Graceful shutdown
// ────────────────────────────────────────────────
function shutdown(sig) {
  log(`Received ${sig}, saving state and exiting...`);
  historyDirty = true;
  persistHistory();
  server.close(() => {
    try { pm2.disconnect(); } catch (_) { /* already down */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// ────────────────────────────────────────────────
// Start — single persistent PM2 connection for both bus + polling
// ────────────────────────────────────────────────
server.listen(cfg.port, '0.0.0.0', () => {
  log(`Dashboard listening on http://0.0.0.0:${cfg.port}${cfg.accessToken ? ' (token required)' : ''}`);
});

pm2.connect(err => {
  if (err) {
    log('Fatal: PM2 connect error: ' + err.message);
    process.exit(1);
  }
  pm2ConnectionReady = true;
  startBus();
  pollMetrics();
  setInterval(pollMetrics, cfg.checkInterval);
});
