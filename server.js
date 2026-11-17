'use strict';
/**
 * SignGuard HTTP service — stdlib only, no dependencies.
 *   GET  /         service info
 *   GET  /health   liveness probe
 *   GET  /analyze  usage hint (so endpoint checks that GET the handler get 200)
 *   POST /analyze  { to, data?, value?, from?, expectedRecipient? } -> verdict
 * Run:  node server.js            (PORT env, default 8080; HOST env, default 127.0.0.1)
 * The service is read-only analysis: it never signs, sends, or broadcasts.
 */
const http = require('http');
const { analyze } = require('./guard');

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0'; // 0.0.0.0 so hosted platforms (Railway etc.) can route to it; set HOST=127.0.0.1 for local-only
const MAX_BODY = 64 * 1024; // 64 KiB
const VERSION = '0.1.0';

const startedAt = Date.now();

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'GET' && url.pathname === '/health') {
    return send(res, 200, { ok: true, service: 'signguard', version: VERSION, uptimeSec: Math.floor((Date.now() - startedAt) / 1000) });
  }
  if (req.method === 'GET' && url.pathname === '/') {
    return send(res, 200, {
      service: 'signguard',
      version: VERSION,
      description: 'BSC/EVM pre-signing transaction guard — deterministic policy analysis, no signing.',
      endpoints: {
        'GET /health': 'liveness probe',
        'POST /analyze': '{ to, data?, value?, from?, expectedRecipient? }',
      },
    });
  }
  if (req.method === 'GET' && url.pathname === '/analyze') {
    return send(res, 200, {
      service: 'signguard',
      version: VERSION,
      usage: 'POST /analyze with JSON body { to, data?, value?, from?, expectedRecipient? }',
      example: { to: '0x55d398326f99059fF775485246999027B3197955', data: '0x095ea7b3...', value: '0' },
      note: 'Returns ALLOW / REVIEW / BLOCK with a 0-100 risk score.',
    });
  }
  if (req.method === 'POST' && url.pathname === '/analyze') {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { res.writeHead(413, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ verdict: 'ERROR', errors: ['body too large (max 64 KiB)'] })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      let input;
      try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {
        return send(res, 400, { verdict: 'ERROR', errors: ['invalid JSON body'] });
      }
      if (input === null || typeof input !== 'object' || Array.isArray(input)) {
        return send(res, 400, { verdict: 'ERROR', errors: ['body must be a JSON object'] });
      }
      const out = analyze(input);
      return send(res, out.verdict === 'ERROR' ? 400 : 200, out);
    });
    return;
  }
  return send(res, 404, { verdict: 'ERROR', errors: ['not found'] });
});

server.listen(PORT, HOST, () => {
  console.log(`signguard ${VERSION} listening on http://${HOST}:${PORT}`);
});
