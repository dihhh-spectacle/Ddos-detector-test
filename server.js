const http = require('http');

const PORT = process.env.PORT || 8080;
const MIN_RPS = 50;     // flag if requests/sec reaches this
const SPIKE_X = 5;      // flag if rps is 5x the recent average (and at least 20)
const IP_LIMIT = 100;   // flag if one IP sends this many requests in 10s
const MAX_IPS = 5000;   // memory cap per second
const CALM_SECONDS = 10; // seconds of normal traffic before alert ends

const newBucket = () => ({ total: 0, ips: new Map() });
let buckets = [newBucket()];
const clients = new Set();
const alerts = [];
let attack = false;
let calm = 0;

const getIp = (req) => {
  const x = req.headers['x-forwarded-for'];
  if (x) return x.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
};

const addAlert = (type, rps, reason) => {
  alerts.unshift({ time: new Date().toISOString(), type, rps, reason });
  if (alerts.length > 20) alerts.pop();
};

setInterval(() => {
  buckets.push(newBucket());
  if (buckets.length > 61) buckets.shift();

  const done = buckets.slice(0, -1);
  const last = done[done.length - 1] || newBucket();
  const rps = last.total;

  const older = done.slice(0, -5);
  const baseline = older.length
    ? older.reduce((s, b) => s + b.total, 0) / older.length
    : 0;

  const ipTotals = new Map();
  for (const b of done.slice(-10)) {
    for (const [ip, c] of b.ips) ipTotals.set(ip, (ipTotals.get(ip) || 0) + c);
  }
  const top = [...ipTotals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);

  let reason = '';
  if (rps >= MIN_RPS) reason = `High traffic: ${rps} req/s`;
  else if (rps >= 20 && baseline > 0 && rps >= baseline * SPIKE_X)
    reason = `Spike: ${rps} req/s vs ${baseline.toFixed(1)} avg`;
  else if (top[0] && top[0][1] >= IP_LIMIT)
    reason = `Single IP flood: ${top[0][0]} sent ${top[0][1]} in 10s`;

  if (reason) {
    calm = 0;
    if (!attack) { attack = true; addAlert('START', rps, reason); }
  } else if (attack) {
    calm++;
    if (calm >= CALM_SECONDS) { attack = false; addAlert('END', rps, 'Traffic back to normal'); }
  }

  const data = JSON.stringify({
    rps,
    baseline: Math.round(baseline * 10) / 10,
    attack,
    reason,
    top,
    alerts,
    history: done.map((b) => b.total)
  });
  for (const c of clients) c.write(`data: ${data}\n\n`);
}, 1000);

const page = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DDoS Detector</title>
<style>
body{margin:0;padding:16px;background:#0f1115;color:#fff;font-family:system-ui,sans-serif}
.status{padding:16px;border-radius:12px;text-align:center;font-size:24px;font-weight:700;background:#14532d}
.status.attack{background:#991b1b}
.sub{font-size:14px;font-weight:400;opacity:.85;margin-top:4px}
.row{display:flex;gap:12px;margin:12px 0}
.card{flex:1;background:#1a1d24;border-radius:12px;padding:12px;text-align:center}
.n{font-size:32px;font-weight:700}
.l{opacity:.6;font-size:13px}
h3{margin:16px 0 6px;font-size:15px;opacity:.8}
.chart{display:flex;align-items:flex-end;gap:2px;height:100px;background:#1a1d24;border-radius:12px;padding:8px}
.bar{flex:1;background:#3b82f6;min-height:1px;border-radius:2px}
.item{background:#1a1d24;border-radius:8px;padding:8px 10px;margin-bottom:6px;font-size:13px;word-break:break-all}
.start{border-left:4px solid #ef4444}.end{border-left:4px solid #22c55e}
</style></head><body>
<div class="status" id="status">NORMAL<div class="sub" id="reason"></div></div>
<div class="row">
<div class="card"><div class="n" id="rps">0</div><div class="l">requests/sec</div></div>
<div class="card"><div class="n" id="base">0</div><div class="l">avg (older)</div></div>
</div>
<h3>Last 60 seconds</h3><div class="chart" id="chart"></div>
<h3>Top IPs (last 10s)</h3><div id="top"></div>
<h3>Alerts</h3><div id="alerts"></div>
<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
new EventSource('/events').onmessage = (e) => {
  const d = JSON.parse(e.data);
  $('status').className = 'status' + (d.attack ? ' attack' : '');
  $('status').firstChild.textContent = d.attack ? 'ATTACK DETECTED' : 'NORMAL';
  $('reason').textContent = d.reason;
  $('rps').textContent = d.rps;
  $('base').textContent = d.baseline;
  const max = Math.max(10, ...d.history);
  $('chart').innerHTML = d.history.map((v) => '<div class="bar" style="height:' + (v / max * 100) + '%"></div>').join('');
  $('top').innerHTML = d.top.length
    ? d.top.map((t) => '<div class="item">' + esc(t[0]) + ' — ' + t[1] + ' req</div>').join('')
    : '<div class="item">No traffic yet</div>';
  $('alerts').innerHTML = d.alerts.length
    ? d.alerts.map((a) => '<div class="item ' + a.type.toLowerCase() + '">' + esc(a.time) + '<br>' + a.type + ': ' + esc(a.reason) + '</div>').join('')
    : '<div class="item">No alerts</div>';
};
</script></body></html>`;

http.createServer((req, res) => {
  if (req.url === '/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }

  const b = buckets[buckets.length - 1];
  const ip = getIp(req);
  b.total++;
  if (b.ips.has(ip) || b.ips.size < MAX_IPS) b.ips.set(ip, (b.ips.get(ip) || 0) + 1);

  if (req.url === '/' || req.url.startsWith('/?')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page);
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
}).listen(PORT, '0.0.0.0', () => console.log('Running on ' + PORT));
