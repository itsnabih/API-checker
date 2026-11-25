/**
 * cors-bridge.mjs — Zero-Trace Local Static Server, In-Memory CORS Relay & TCP/TLS Forensics Bridge
 *
 * Usage:
 *   node cors-bridge.mjs
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT) || 8787;
const HOST = '127.0.0.1';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// Short-lived volatile cache (60s) for non-secret host DNS & TLS certificate inspection
const hostForensicsCache = new Map();

async function inspectTargetHostInfrastructure(targetUrl) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return null;
  }

  const hostname = parsed.hostname;
  const port = Number(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);
  const cacheKey = `${ parsed.protocol }//${hostname}:${port}`;

  const cached = hostForensicsCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < 60000) {
    return cached.data;
  }

  const info = {
    hostname,
    port,
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    resolvedIps: [],
    cnames: [],
    reversePtr: [],
    remoteIp: null,
    remotePort: null,
    tls: null
  };

  // 1. Native DNS Lookup (A / AAAA / CNAME / PTR)
  try {
    const [lookupAll, cnameList] = await Promise.all([
      dns.lookup(hostname, { all: true }).catch(() => []),
      dns.resolveCname(hostname).catch(() => [])
    ]);
    info.resolvedIps = lookupAll.map((entry) => ({
      address: entry.address,
      family: `IPv${entry.family}`
    }));
    info.cnames = cnameList;

    if (info.resolvedIps.length > 0) {
      info.remoteIp = info.resolvedIps[0].address;
      const ptrs = await dns.reverse(info.remoteIp).catch(() => []);
      info.reversePtr = ptrs;
    }
  } catch {
    // ignore DNS error
  }

  // 2. Native TLS Handshake & Peer Certificate Inspection
  if (parsed.protocol === 'https:') {
    await new Promise((resolve) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 2500
        },
        () => {
          try {
            if (socket.remoteAddress) info.remoteIp = socket.remoteAddress;
            if (socket.remotePort) info.remotePort = socket.remotePort;
            const proto = socket.getProtocol() || null;
            const cipher = socket.getCipher() || null;
            const cert = socket.getPeerCertificate(false) || {};

            const altNames = cert.subjectaltname
              ? cert.subjectaltname
                  .split(',')
                  .map((s) => s.trim().replace(/^DNS:/i, ''))
                  .filter(Boolean)
              : [];

            info.tls = {
              protocol: proto,
              cipherName: cipher?.name || null,
              cipherStandardName: cipher?.standardName || null,
              subjectCN: cert.subject?.CN || null,
              subjectOrg: cert.subject?.O || null,
              issuerCN: cert.issuer?.CN || null,
              issuerOrg: cert.issuer?.O || null,
              issuerCountry: cert.issuer?.C || null,
              validFrom: cert.valid_from || null,
              validTo: cert.valid_to || null,
              serialNumber: cert.serialNumber || null,
              fingerprint256: cert.fingerprint256 || null,
              altNames: altNames.slice(0, 25)
            };
          } catch {
            // ignore cert parse error
          } finally {
            socket.destroy();
            resolve();
          }
        }
      );

      socket.on('error', () => {
        socket.destroy();
        resolve();
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });
    });
  }

  hostForensicsCache.set(cacheKey, { timestamp: Date.now(), data: info });
  return info;
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    req.headers['access-control-request-headers'] ||
      'Content-Type, Authorization, x-api-key, anthropic-version, anthropic-dangerous-direct-browser-access, x-goog-api-key, x-target-url'
  );
  res.setHeader('Access-Control-Expose-Headers', '*');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
}

const server = http.createServer(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url || '/', `http://${HOST}:${PORT}`);

  if (parsedUrl.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', mode: 'zero-trace-local-bridge' }));
    return;
  }

  if (parsedUrl.pathname === '/proxy') {
    const targetUrl = req.headers['x-target-url'] || parsedUrl.searchParams.get('url');
    if (!targetUrl || typeof targetUrl !== 'string') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'Missing x-target-url header for CORS bridge.' } }));
      return;
    }

    try {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const bodyBuffer = Buffer.concat(chunks);

      const forwardHeaders = {
        accept: 'application/json, text/event-stream, */*',
        'user-agent': 'AgentAPI-Checker/1.0'
      };
      const skipHeaders = new Set([
        'host',
        'origin',
        'referer',
        'connection',
        'content-length',
        'accept-encoding',
        'accept-language',
        'x-target-url',
        'sec-fetch-mode',
        'sec-fetch-site',
        'sec-fetch-dest',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'pragma',
        'cache-control'
      ]);

      for (const [k, v] of Object.entries(req.headers)) {
        const low = k.toLowerCase();
        if (!skipHeaders.has(low) && !low.startsWith('sec-') && v !== undefined) {
          forwardHeaders[k] = v;
        }
      }

      // Run upstream fetch and non-secret TCP/TLS host inspection in parallel
      const [upstreamRes, netForensics] = await Promise.all([
        fetch(targetUrl, {
          method: req.method || 'GET',
          headers: forwardHeaders,
          body: ['GET', 'HEAD'].includes(req.method || 'GET') ? undefined : bodyBuffer,
          redirect: 'follow'
        }),
        inspectTargetHostInfrastructure(targetUrl)
      ]);

      upstreamRes.headers.forEach((val, key) => {
        const low = key.toLowerCase();
        if (
          ![
            'content-encoding',
            'transfer-encoding',
            'content-length',
            'access-control-allow-origin',
            'access-control-allow-headers',
            'access-control-expose-headers'
          ].includes(low)
        ) {
          res.setHeader(key, val);
        }
      });

      if (netForensics) {
        res.setHeader('x-bridge-forensics', Buffer.from(JSON.stringify(netForensics)).toString('base64'));
      }

      setCorsHeaders(req, res);
      res.writeHead(upstreamRes.status);

      if (upstreamRes.body) {
        Readable.fromWeb(upstreamRes.body).pipe(res);
      } else {
        res.end();
      }
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: {
            message: `Local CORS Bridge could not reach upstream target: ${err?.message || 'Network failure'}`
          }
        })
      );
    }
    return;
  }

  let safePath = path.normalize(parsedUrl.pathname).replace(/^(\.\.[\/\\])+/, '');
  if (safePath === '/' || safePath === '\\') safePath = '/index.html';
  const filePath = path.join(__dirname, safePath);

  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(content);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`AGENT API.IO — Local Web UI & CORS Bridge running at http://${HOST}:${PORT}`);
  console.log(`CORS Relay Endpoint: http://${HOST}:${PORT}/proxy`);
});
