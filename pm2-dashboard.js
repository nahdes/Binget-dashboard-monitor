#!/usr/bin/env node
'use strict';

try { require('dotenv').config(); } catch (_) { /* dotenv optional */ }

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch (_) { /* email optional */ }

// ────────────────────────────────────────────────
// Config (from .env or defaults) — no PM2 anywhere in this file.
// ────────────────────────────────────────────────
const cfg = {
  port: parseInt(process.env.PORT || '3099', 10),
  checkIntervalMs: parseInt(process.env.CHECK_INTERVAL_MS || '10000', 10),
  checkTimeoutMs: parseInt(process.env.CHECK_TIMEOUT_MS || '3000', 10),
  historyMax: parseInt(process.env.HISTORY_MAX || '300', 10),
  webhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  throttleMs: parseInt(process.env.ALERT_THROTTLE_MS || '300000', 10),
  escalationMin: parseInt(process.env.ESCALATION_MINUTES || '10', 10),
  accessToken: process.env.ACCESS_TOKEN || '',
  ignore: new Set((process.env.IGNORE_SERVICES || '').split(',').map(s => s.trim()).filter(Boolean)),
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    to: process.env.ALERT_EMAIL_TO || ''
  },
  // SERVICES format: name:host:port[:httpPath], comma-separated.
  // No httpPath -> plain TCP connect check. With httpPath -> HTTP GET, expects 2xx/3xx.
  services: (process.env.SERVICES || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(entry => {
      const parts = entry.split(':');
      const [name, host, portStr, ...pathParts] = parts;
      return {
        name,
        host: host || '127.0.0.1',
        port: parseInt(portStr, 10),
        path: pathParts.length ? pathParts.join(':') : null
      };
    })
    .filter(s => s.name && s.port),
  // SERVICE_LOGS format: name:/absolute/path/to.log, comma-separated. Optional, powers /logs/:name.
  serviceLogs: (process.env.SERVICE_LOGS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .reduce((map, entry) => {
      const idx = entry.indexOf(':');
      if (idx > 0) map[entry.slice(0, idx)] = entry.slice(idx + 1);
      return map;
    }, {})
};

const HISTORY_FILE = path.join(__dirname, 'monitor-downtime-history.json');
const LOG_FILE = path.join(__dirname, 'monitor.log');
const MAX_LOG_BYTES = 5 * 1024 * 1024;
const MONITOR_STARTED_AT = Date.now();

// ────────────────────────────────────────────────
// State
// ────────────────────────────────────────────────
let history = [];               // { name, downAt, upAt, durationMs, reason }
let services = [];              // [{ name, host, port, path, status, latencyMs, statusCode, lastCheckedAt }]
let lastAlert = {};
let lastPollAt = null;
let historyDirty = false;

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
        from: cfg.smtp.user || 'monitor@localhost',
        to: cfg.smtp.to,
        subject: `[Monitor] ${text.slice(0, 80)}`,
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
function recordDown(name, reason = 'unreachable') {
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

function checkEscalations() {
  const now = Date.now();
  history.forEach(h => {
    if (h.upAt) return;
    const downMin = (now - new Date(h.downAt).getTime()) / 60000;
    if (downMin >= cfg.escalationMin) {
      sendAlert(`\u{1F6A8} ESCALATION: ${h.name} still DOWN for ${Math.round(downMin)} min`, h.name, 'escalation');
    }
  });
}

// ────────────────────────────────────────────────
// Watchdog — TCP / HTTP reachability checks
// ────────────────────────────────────────────────
function checkTcp(host, portNum, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    const socket = net.createConnection({ host, port: portNum, timeout: timeoutMs });
    const done = ok => { socket.destroy(); resolve({ ok, latencyMs: Date.now() - start }); };
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

function checkHttp(host, portNum, urlPath, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    const req = http.get({ host, port: portNum, path: urlPath, timeout: timeoutMs }, res => {
      const ok = res.statusCode >= 200 && res.statusCode < 400;
      res.resume();
      resolve({ ok, latencyMs: Date.now() - start, statusCode: res.statusCode });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, latencyMs: Date.now() - start }); });
    req.on('error', () => resolve({ ok: false, latencyMs: Date.now() - start }));
  });
}

async function checkServices() {
  if (!cfg.services.length) return;

  lastPollAt = Date.now();

  const results = await Promise.all(cfg.services.map(async svc => {
    const result = svc.path
      ? await checkHttp(svc.host, svc.port, svc.path, cfg.checkTimeoutMs)
      : await checkTcp(svc.host, svc.port, cfg.checkTimeoutMs);
    return { ...svc, ...result };
  }));

  services = results.map(r => ({
    name: r.name,
    host: r.host,
    port: r.port,
    path: r.path,
    status: r.ok ? 'online' : 'stopped',
    latencyMs: r.latencyMs,
    statusCode: r.statusCode || null,
    lastCheckedAt: Date.now()
  }));

  services.forEach(svc => {
    if (svc.status === 'online') recordUp(svc.name);
    else recordDown(svc.name, svc.path ? 'http-check-failed' : 'port-unreachable');
  });

  checkEscalations();
  persistHistory();
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
  const logPath = cfg.serviceLogs[name];
  if (!logPath) return `No log path configured for "${name}". Add it to SERVICE_LOGS in .env, e.g.\nSERVICE_LOGS=${name}:/var/log/${name}/out.log`;
  if (!fs.existsSync(logPath)) return `Configured log path not found on disk: ${logPath}`;
  try {
    const data = fs.readFileSync(logPath, 'utf8').split('\n');
    return data.slice(-lines).join('\n');
  } catch (e) {
    return `Error reading log: ${e.message}`;
  }
}

// ────────────────────────────────────────────────
// Dashboard UI
// ────────────────────────────────────────────────
function statusDotClass(status) {
  return status === 'online' ? 'dot-online' : 'dot-offline';
}

function renderDashboard(tokenQ = '') {
  const onlineCount = services.filter(s => s.status === 'online').length;
  const offlineCount = services.length - onlineCount;
  const avgSla = services.length
    ? (services.reduce((s, svc) => s + parseFloat(uptimePercent(svc.name)), 0) / services.length).toFixed(2)
    : '100.00';
  const avgLatency = services.length
    ? Math.round(services.reduce((s, svc) => s + (svc.latencyMs || 0), 0) / services.length)
    : 0;

  const stale = lastPollAt && (Date.now() - lastPollAt) > cfg.checkIntervalMs * 3;

  const kpiCards = `
    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-icon icon-online">&#9679;</div>
        <div>
          <div class="kpi-value">${onlineCount}<span class="kpi-value-muted">/${services.length}</span></div>
          <div class="kpi-label">Services Online</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-offline">&#9679;</div>
        <div>
          <div class="kpi-value">${offlineCount}</div>
          <div class="kpi-label">Services Down</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-sla">&#10003;</div>
        <div>
          <div class="kpi-value">${avgSla}<span class="kpi-value-muted">%</span></div>
          <div class="kpi-label">Avg 7-day SLA</div>
        </div>
      </div>
      <div class="kpi">
        <div class="kpi-icon icon-restart">&#9889;</div>
        <div>
          <div class="kpi-value">${avgLatency}<span class="kpi-value-muted">ms</span></div>
          <div class="kpi-label">Avg Latency</div>
        </div>
      </div>
    </div>`;

  const rows = [...services]
    .sort((a, b) => (a.status === 'online' ? 1 : 0) - (b.status === 'online' ? 1 : 0) || a.name.localeCompare(b.name))
    .map(s => {
      const cls = s.status === 'online' ? 'online' : 'offline';
      const target = s.path ? `${s.host}:${s.port}${s.path}` : `${s.host}:${s.port}`;
      const ignored = cfg.ignore.has(s.name) ? ' <span class="tag-ignored">ignored</span>' : '';
      return `
        <tr class="${cls}" data-name="${escapeHtml(s.name.toLowerCase())}">
          <td><span class="dot ${statusDotClass(s.status)}"></span><strong>${escapeHtml(s.name)}</strong>${ignored}</td>
          <td class="mono">${escapeHtml(target)}</td>
          <td>${s.path ? 'HTTP' : 'TCP'}</td>
          <td><span class="badge ${cls}">${escapeHtml(s.status)}</span></td>
          <td class="mono">${s.statusCode || '-'}</td>
          <td class="mono">${s.latencyMs != null ? s.latencyMs + ' ms' : '-'}</td>
          <td class="mono">${uptimePercent(s.name)}%</td>
          <td class="mono">${s.lastCheckedAt ? new Date(s.lastCheckedAt).toLocaleTimeString() : '-'}</td>
          <td><a class="btn" href="/logs/${encodeURIComponent(s.name)}${tokenQ}">Logs</a></td>
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
  const monitorUptime = formatDuration(Date.now() - MONITOR_STARTED_AT);
  const hostname = escapeHtml(os.hostname());

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Service Status Monitor${stale ? ' — stale' : ''}</title>
  <meta http-equiv="refresh" content="20${tokenQ}">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22><circle cx=%2216%22 cy=%2216%22 r=%2214%22 fill=%22%2322c55e%22/></svg>">
  <style>
    :root {
      --bg: #f3f4f8; --card: #ffffff; --text: #0f172a; --muted: #64748b;
      --border: #e5e7eb; --accent: #4f46e5; --green: #16a34a; --red: #dc2626;
      --orange: #d97706; --radius: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); -webkit-font-smoothing: antialiased; }
    .topbar { background: #0b1120; color: #f8fafc; padding: 16px 32px; display: flex; align-items: center; gap: 16px; position: sticky; top: 0; z-index: 20; box-shadow: 0 2px 12px rgb(0 0 0 / 0.15); }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; }
    .brand-mark { width: 26px; height: 26px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), #22c55e); display: inline-block; }
    .topbar-meta { display: flex; gap: 10px; margin-left: auto; align-items: center; flex-wrap: wrap; }
    .pill { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12); padding: 5px 12px; border-radius: 999px; font-size: 0.78rem; color: #cbd5e1; display: flex; align-items: center; gap: 6px; }
    .btn-refresh { background: var(--accent); color: white; border: none; padding: 7px 16px; border-radius: 8px; font-size: 0.82rem; font-weight: 600; text-decoration: none; cursor: pointer; }
    .btn-refresh:hover { filter: brightness(1.1); }
    .wrap { max-width: 1320px; margin: 0 auto; padding: 28px 32px 60px; }
    .stale-banner { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; padding: 10px 16px; border-radius: 10px; font-size: 0.85rem; margin-bottom: 20px; display: ${stale ? 'block' : 'none'}; }
    .empty-banner { display: ${cfg.services.length ? 'none' : 'block'}; background: #dbeafe; color: #1e40af; border: 1px solid #bfdbfe; padding: 10px 16px; border-radius: 10px; font-size: 0.85rem; margin-bottom: 20px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 28px; }
    .kpi { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px 20px; display: flex; align-items: center; gap: 14px; box-shadow: 0 1px 2px rgb(0 0 0 / 0.03); }
    .kpi-icon { width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1rem; flex-shrink: 0; }
    .icon-online  { background: #dcfce7; color: var(--green); }
    .icon-offline { background: #fee2e2; color: var(--red); }
    .icon-restart { background: #ede9fe; color: var(--accent); }
    .icon-sla     { background: #dbeafe; color: #2563eb; }
    .kpi-value { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.1; }
    .kpi-value-muted { font-size: 0.85rem; color: var(--muted); font-weight: 500; margin-left: 2px; }
    .kpi-label { font-size: 0.78rem; color: var(--muted); margin-top: 3px; }
    .card { background: var(--card); border-radius: var(--radius); border: 1px solid var(--border); box-shadow: 0 1px 2px rgb(0 0 0 / 0.03); overflow: hidden; }
    .section-title { font-size: 1rem; font-weight: 700; margin: 30px 0 12px; display: flex; align-items: center; gap: 10px; }
    .filter-input { margin-left: auto; border: 1px solid var(--border); background: var(--card); padding: 7px 12px; border-radius: 8px; font-size: 0.82rem; width: 220px; }
    .filter-input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 11px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.83rem; }
    th { background: #f8fafc; color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.68rem; letter-spacing: 0.05em; }
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
    .tag-ignored { font-size: 0.68rem; color: var(--muted); background: #f1f5f9; padding: 1px 7px; border-radius: 999px; margin-left: 6px; font-weight: 500; }
    .still-down { color: var(--red); font-style: italic; }
    .btn { display: inline-block; padding: 5px 13px; background: var(--accent); color: white; border-radius: 7px; text-decoration: none; font-size: 0.78rem; font-weight: 600; }
    .btn:hover { filter: brightness(1.08); }
    .empty { text-align: center; color: var(--muted); padding: 44px; font-size: 0.88rem; }
    footer { text-align: center; color: var(--muted); font-size: 0.75rem; padding: 30px 0 10px; }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand"><span class="brand-mark"></span> Service Status Monitor</div>
    <div class="topbar-meta">
      <span class="pill">${hostname}</span>
      <span class="pill">Monitor up ${monitorUptime}</span>
      <span class="pill">Last check ${lastPoll}</span>
      <a href="/${tokenQ}" class="btn-refresh">Refresh</a>
    </div>
  </div>

  <div class="wrap">
    <div class="stale-banner">&#9888; No successful check in a while — the monitor process may be stalled.</div>
    <div class="empty-banner">&#8505; <strong>SERVICES is empty in .env</strong> — nothing is being monitored yet. Add entries like <code>name:host:port</code> and restart.</div>

    ${kpiCards}

    <div class="section-title">
      Services
      <input class="filter-input" id="filterInput" type="text" placeholder="Filter by name...">
    </div>
    <div class="card">
      <table id="svcTable">
        <thead>
          <tr><th>Name</th><th>Target</th><th>Check</th><th>Status</th><th>HTTP</th><th>Latency</th><th>7d SLA</th><th>Last Checked</th><th></th></tr>
        </thead>
        <tbody>
          ${rows || '<tr><td colspan="9" class="empty">No services configured</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="section-title">Recent Downtime</div>
    <div class="card">
      <table>
        <thead>
          <tr><th>Service</th><th>Down at</th><th>Up at</th><th>Duration</th><th>Reason</th></tr>
        </thead>
        <tbody>
          ${histRows || '<tr><td colspan="5" class="empty">No events recorded yet</td></tr>'}
        </tbody>
      </table>
    </div>

    <footer>Service Status Monitor &middot; <a href="/health${tokenQ}" style="color:inherit">health</a> &middot; <a href="/api/status${tokenQ}" style="color:inherit">raw json</a></footer>
  </div>

  <script>
    document.getElementById('filterInput').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#svcTable tbody tr').forEach(row => {
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
    header { background: #111827; padding: 14px 24px; display: flex; align-items: center; gap: 16px; border-bottom: 1px solid #1f2937; position: sticky; top: 0; z-index: 10; font-family: -apple-system, system-ui, sans-serif; }
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
      services, history: history.slice(0, 50), lastPollAt
    }, null, 2), 'application/json');
  }

  if (url.pathname === '/health') {
    const stale = lastPollAt && (Date.now() - lastPollAt) > cfg.checkIntervalMs * 3;
    const hasPolled = cfg.services.length === 0 || lastPollAt !== null;
    const allOnline = hasPolled && !stale &&
      services.every(s => s.status === 'online' || cfg.ignore.has(s.name));
    const body = {
      status: allOnline ? 'ok' : 'degraded',
      configured: cfg.services.length,
      polled: hasPolled,
      stale: !!stale,
      downServices: services.filter(s => s.status !== 'online' && !cfg.ignore.has(s.name)).map(s => s.name)
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
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// ────────────────────────────────────────────────
// Start
// ────────────────────────────────────────────────
server.listen(cfg.port, '127.0.0.1', () => {
  log(`Dashboard listening on http://127.0.0.1:${cfg.port}${cfg.accessToken ? ' (token required)' : ''}`);
});

if (cfg.services.length) {
  log(`Watching: ${cfg.services.map(s => `${s.name} (${s.host}:${s.port}${s.path || ''})`).join(', ')}`);
  checkServices();
  setInterval(checkServices, cfg.checkIntervalMs);
} else {
  log('No services configured. Set SERVICES in .env, e.g. SERVICES=api:127.0.0.1:4000,web:127.0.0.1:3000:/health');
}