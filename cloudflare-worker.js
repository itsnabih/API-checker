/**
 * cloudflare-worker.js — Self-Hosted Zero-Log Cloudflare Worker CORS Bridge (For GitHub Pages)
 *
 * How to deploy (100% Free on Cloudflare Workers):
 * 1. Go to Cloudflare Dashboard -> Workers & Pages -> Create Worker
 * 2. Paste this entire file and click "Deploy"
 * 3. Copy your Worker URL (e.g. https://agent-api-bridge.<your-subdomain>.workers.dev/proxy)
 * 4. Paste it into the "+ Headers / CORS Bridge" field in your GitHub Pages AGENT API.IO UI.
 *
 * Security Guarantees:
 * - Zero logging: Never calls console.log() on headers, keys, or bodies.
 * - Origin locking: Set ALLOWED_ORIGINS below to lock the relay strictly to your GitHub Pages URL.
 * - Exposes all upstream headers ('Access-Control-Expose-Headers: *') for full Metadata Forensics.
 */

const ALLOWED_ORIGINS = ['*']; // Replace '*' with ['https://<your-username>.github.io'] to lock to your GitHub Pages!

function buildCorsHeaders(origin) {
  const allowOrigin =
    ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin) ? origin || '*' : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Expose-Headers': '*',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
  };
}

export default {
  async fetch(request) {
    const origin = request.headers.get('Origin') || '*';
    const corsHeaders = buildCorsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', mode: 'zero-trace-cf-worker' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const targetUrl = request.headers.get('x-target-url') || url.searchParams.get('url');
    if (!targetUrl) {
      return new Response(JSON.stringify({ error: { message: 'Missing x-target-url header.' } }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const forwardHeaders = new Headers({
      accept: 'application/json, text/event-stream, */*',
      'user-agent': 'AgentAPI-Checker/1.0'
    });
    const skip = new Set([
      'host',
      'origin',
      'referer',
      'connection',
      'content-length',
      'accept-encoding',
      'accept-language',
      'x-target-url',
      'cf-connecting-ip',
      'cf-ipcountry',
      'cf-ray',
      'cf-visitor',
      'cf-ew-via',
      'cf-worker',
      'x-forwarded-for',
      'x-forwarded-proto',
      ' x-real-ip',
      'pragma',
      'cache-control'
    ]);
    for (const [k, v] of request.headers.entries()) {
      const low = k.toLowerCase();
      if (!skip.has(low) && !low.startsWith('sec-') && !low.startsWith('cf-')) {
        forwardHeaders.set(k, v);
      }
    }

    try {
      const upstreamRes = await fetch(targetUrl, {
        method: request.method,
        headers: forwardHeaders,
        body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
        redirect: 'follow'
      });

      const responseHeaders = new Headers(upstreamRes.headers);
      for (const [k, v] of Object.entries(corsHeaders)) {
        responseHeaders.set(k, v);
      }

      return new Response(upstreamRes.body, {
        status: upstreamRes.status,
        statusText: upstreamRes.statusText,
        headers: responseHeaders
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ error: { message: `Worker CORS Bridge Error: ${err?.message || 'Upstream unreachable'}` } }),
        {
          status: 502,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
      );
    }
  }
};
