// Email Notifier backend: serves index.html and sends each email through Splunk's
// `sendemail` command (Splunk is already connected to the internal SMTP server).
// No npm dependencies. Run:  node server.js   (configure via .env)
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

// --- minimal .env loader ---
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m || process.env[m[1]] !== undefined) continue;
    process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}

const PORT = Number(process.env.PORT || 3000);
const API_TOKEN = process.env.API_TOKEN || '';
const SPLUNK_URL = (process.env.SPLUNK_URL || 'https://localhost:8089').replace(/\/+$/, '');
const SPLUNK_APP = process.env.SPLUNK_APP || 'search';
const MAIL_FROM = process.env.MAIL_FROM || '';            // empty = Splunk's default sender (alert_actions.conf)
const CONTENT_TYPE = process.env.MAIL_CONTENT_TYPE === 'html' ? 'html' : 'plain';
const EMAIL_RE = /^[^\s@<>(),;:"\\|]+@[^\s@<>(),;:"\\|]+\.[^\s@<>(),;:"\\|]+$/;

// Auth: a Splunk authentication token (preferred) or username/password.
function splunkAuthHeader() {
  if (process.env.SPLUNK_TOKEN) return `Bearer ${process.env.SPLUNK_TOKEN}`;
  if (process.env.SPLUNK_USER) {
    return 'Basic ' + Buffer.from(`${process.env.SPLUNK_USER}:${process.env.SPLUNK_PASS || ''}`).toString('base64');
  }
  return undefined;
}

// TLS for the management port (8089 often uses an internal CA / self-signed cert).
const agent = new https.Agent({
  ca: process.env.SPLUNK_CA_FILE ? fs.readFileSync(process.env.SPLUNK_CA_FILE) : undefined,
  rejectUnauthorized: process.env.SPLUNK_INSECURE_TLS !== 'true',
  keepAlive: true,
});

function splunkRequest(method, apiPath, form) {
  const url = new URL(SPLUNK_URL + apiPath);
  const body = form ? new URLSearchParams(form).toString() : undefined;
  const mod = url.protocol === 'http:' ? http : https;
  return new Promise((resolve, reject) => {
    const req = mod.request(url, {
      method,
      agent: url.protocol === 'https:' ? agent : undefined,
      timeout: 60_000,
      headers: {
        ...(splunkAuthHeader() ? { Authorization: splunkAuthHeader() } : {}),
        ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('Splunk request timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Quote a value for SPL: wrap in double quotes, escape backslashes and quotes.
const splQuote = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';

function buildSearch({ to, subject, message, replyTo }) {
  const args = [
    `to=${splQuote(to)}`,
    MAIL_FROM && `from=${splQuote(MAIL_FROM)}`,
    `subject=${splQuote(subject)}`,
    `message=${splQuote(message)}`,
    `content_type=${CONTENT_TYPE}`,
    'sendresults=false',
    'inline=false',
  ].filter(Boolean);
  // sendemail has no reply-to option; mention it at the end of the body instead.
  if (replyTo) args[args.findIndex((a) => a.startsWith('message='))] = `message=${splQuote(
    message + (CONTENT_TYPE === 'html' ? `<br><br>Reply-To: ${replyTo}` : `\n\nReply-To: ${replyTo}`))}`;
  return `| makeresults | sendemail ${args.join(' ')}`;
}

// Splunk reports sendemail failures as ERROR/FATAL messages in the search response.
function splunkError(r) {
  if (r.status === 401) return 'Splunk: authentication failed (check SPLUNK_TOKEN / user)';
  const msgs = (r.json && r.json.messages) || [];
  const bad = msgs.filter((m) => /^(ERROR|FATAL)$/i.test(m.type));
  if (bad.length) return 'Splunk: ' + bad.map((m) => m.text).join('; ');
  if (r.status < 200 || r.status >= 300) return `Splunk HTTP ${r.status}: ${r.text.slice(0, 300)}`;
  return null;
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const authorized = (req) => !API_TOKEN || req.headers.authorization === `Bearer ${API_TOKEN}`;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(path.join(__dirname, 'index.html')).pipe(res);
      return;
    }

    if (req.method === 'GET' && req.url === '/api/health') {
      if (!authorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
      try {
        const r = await splunkRequest('GET', '/services/server/info?output_mode=json');
        const err = splunkError(r);
        if (err) return json(res, 502, { ok: false, error: err });
        const c = r.json?.entry?.[0]?.content || {};
        return json(res, 200, { ok: true, from: MAIL_FROM || '(Splunk default sender)',
          splunk: `${c.serverName || SPLUNK_URL} — Splunk ${c.version || '?'}` });
      } catch (e) {
        return json(res, 502, { ok: false, error: `Splunk: ${e.message}` });
      }
    }

    if (req.method === 'POST' && req.url === '/api/send') {
      if (!authorized(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
      const { to, subject, text, html, replyTo } = JSON.parse(await readBody(req)) || {};
      if (typeof to !== 'string' || !EMAIL_RE.test(to)) return json(res, 400, { ok: false, error: 'invalid recipient' });
      if (!subject || (!text && !html)) return json(res, 400, { ok: false, error: 'subject and body required' });
      if (replyTo && !EMAIL_RE.test(replyTo)) return json(res, 400, { ok: false, error: 'invalid reply-to' });

      const message = CONTENT_TYPE === 'html' ? String(html || text) : String(text || '');
      // One search per recipient, so employees never see each other's addresses.
      const search = buildSearch({ to, subject: String(subject).replace(/[\r\n]+/g, ' ').slice(0, 300), message, replyTo });
      const r = await splunkRequest('POST', `/servicesNS/-/${encodeURIComponent(SPLUNK_APP)}/search/jobs`,
        { search, exec_mode: 'oneshot', output_mode: 'json' });
      const err = splunkError(r);
      if (err) return json(res, 502, { ok: false, error: err });
      return json(res, 200, { ok: true });
    }

    json(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    json(res, 500, { ok: false, error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`Email Notifier (via Splunk ${SPLUNK_URL}): http://localhost:${PORT}`);
  if (!splunkAuthHeader()) console.warn('⚠️  SPLUNK_TOKEN not set — copy .env.example to .env and configure it.');
});

module.exports = { buildSearch, splQuote };
