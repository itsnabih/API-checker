/**
 * forensics.js — Deep API Metadata, Public IP/DNS/ASN/TLS Infrastructure & Anti-Masking Engine
 */

const IATA_POP_MAP = {
  SIN: 'Singapore (SG)',
  CGK: 'Jakarta, Indonesia (ID)',
  SUB: 'Surabaya, Indonesia (ID)',
  DPS: 'Denpasar, Indonesia (ID)',
  KUL: 'Kuala Lumpur, Malaysia (MY)',
  BKK: 'Bangkok, Thailand (TH)',
  SGN: 'Ho Chi Minh City, Vietnam (VN)',
  HAN: 'Hanoi, Vietnam (VN)',
  MNL: 'Manila, Philippines (PH)',
  HKG: 'Hong Kong (HK)',
  TPE: 'Taipei, Taiwan (TW)',
  NRT: 'Tokyo Narita, Japan (JP)',
  HND: 'Tokyo Haneda, Japan (JP)',
  KIX: 'Osaka, Japan (JP)',
  ICN: 'Seoul Incheon, South Korea (KR)',
  SYD: 'Sydney, Australia (AU)',
  MEL: 'Melbourne, Australia (AU)',
  BOM: 'Mumbai, India (IN)',
  DEL: 'New Delhi, India (IN)',
  MAA: 'Chennai, India (IN)',
  DXB: 'Dubai, UAE (AE)',
  SJC: 'San Jose, California (US)',
  SFO: 'San Francisco, California (US)',
  LAX: 'Los Angeles, California (US)',
  SEA: 'Seattle, Washington (US)',
  ORD: 'Chicago, Illinois (US)',
  DFW: 'Dallas, Texas (US)',
  IAD: 'Ashburn, Virginia (US)',
  EWR: 'Newark / New York (US)',
  ATL: 'Atlanta, Georgia (US)',
  MIA: 'Miami, Florida (US)',
  YYZ: 'Toronto, Canada (CA)',
  YVR: 'Vancouver, Canada (CA)',
  GRU: 'São Paulo, Brazil (BR)',
  LHR: 'London, United Kingdom (GB)',
  AMS: 'Amsterdam, Netherlands (NL)',
  FRA: 'Frankfurt, Germany (DE)',
  CDG: 'Paris, France (FR)',
  MAD: 'Madrid, Spain (ES)',
  MXP: 'Milan, Italy (IT)',
  ZRH: 'Zurich, Switzerland (CH)',
  ARN: 'Stockholm, Sweden (SE)',
  WAW: 'Warsaw, Poland (PL)'
};

export function extractModelFamily(modelId = '') {
  const m = String(modelId).toLowerCase();
  if (m.includes('claude')) return { family: 'claude', vendor: 'anthropic' };
  if (m.includes('gpt-') || /^o[134](-|$)/.test(m.split('/').pop())) return { family: 'gpt', vendor: 'openai' };
  if (m.includes('gemini')) return { family: 'gemini', vendor: 'google' };
  if (m.includes('deepseek')) return { family: 'deepseek', vendor: 'deepseek' };
  if (m.includes('qwen')) return { family: 'qwen', vendor: 'alibaba' };
  if (m.includes('llama')) return { family: 'llama', vendor: 'meta' };
  if (m.includes('grok')) return { family: 'grok', vendor: 'xai' };
  if (m.includes('mistral') || m.includes('mixtral') || m.includes('codestral')) return { family: 'mistral', vendor: 'mistral' };
  if (m.includes('glm')) return { family: 'glm', vendor: 'zhipu' };
  return { family: 'custom', vendor: 'unknown' };
}

export function compareModelIdentity(requestedModel, actualReturnedModel) {
  const reqRaw = (requestedModel || '').trim();
  const actRaw = (actualReturnedModel || '').trim();

  if (!actRaw) {
    return {
      matchType: 'MISSING_RETURNED_MODEL',
      isMatch: false,
      suspicious: true,
      summary: `Requested "${reqRaw}", but endpoint omitted the "model" field in response.`
    };
  }

  const reqClean = reqRaw.toLowerCase().replace(/^(openai|anthropic|google|models|openrouter)\//, '');
  const actClean = actRaw.toLowerCase().replace(/^(openai|anthropic|google|models|openrouter)\//, '');

  if (reqClean === actClean) {
    return {
      matchType: 'EXACT_MATCH',
      isMatch: true,
      suspicious: false,
      summary: `Exact match: "${actRaw}"`
    };
  }

  const reqBase = reqClean.replace(/-(latest|preview)$/, '');
  if (actClean.startsWith(reqBase) || reqBase.startsWith(actClean)) {
    const downgradeTokens = ['mini', 'nano', 'flash', 'haiku', 'lite', 'small', 'tiny'];
    for (const token of downgradeTokens) {
      if (!reqClean.includes(token) && actClean.includes(token)) {
        return {
          matchType: 'TIER_DOWNGRADE_DETECTED',
          isMatch: false,
          suspicious: true,
          summary: `TIER DOWNGRADE ALERT: Requested "${reqRaw}" but server returned lower-tier "${actRaw}"!`
        };
      }
    }

    return {
      matchType: 'OFFICIAL_SNAPSHOT_MATCH',
      isMatch: true,
      suspicious: false,
      summary: `Verified version snapshot: "${reqRaw}" → "${actRaw}"`
    };
  }

  const reqFam = extractModelFamily(reqClean);
  const actFam = extractModelFamily(actClean);

  if (reqFam.family !== actFam.family) {
    return {
      matchType: 'CROSS_FAMILY_MASKING',
      isMatch: false,
      suspicious: true,
      summary: `MODEL REMAPPING ALERT: Requested ${reqFam.family.toUpperCase()} ("${reqRaw}") but endpoint executed ${actFam.family.toUpperCase()} ("${actRaw}")!`
    };
  }

  return {
    matchType: 'VARIANT_MISMATCH',
    isMatch: false,
    suspicious: true,
    summary: `Variant mismatch: Requested "${reqRaw}" vs Returned "${actRaw}"`
  };
}

/**
 * Parses Server OS, Web Server Software, Edge Datacenter POP, HTTP/3 support, and Clock Skew from HTTP headers
 */
export function parseServerHeadersForensics(headers = {}) {
  const h = headers || {};
  const serverRaw = h['server'] || '';
  const poweredBy = h['x-powered-by'] || '';
  const viaHeader = h['via'] || '';
  const cfRay = h['cf-ray'] || '';
  const amzPop = h['x-amz-cf-pop'] || '';
  const servedBy = h['x-served-by'] || '';
  const altSvc = h['alt-svc'] || '';
  const dateHeader = h['date'] || '';

  // 1. Detect Host OS from Server / Powered-By headers
  let detectedOs = 'Not disclosed in HTTP header';
  const combinedServer = `${serverRaw} ${poweredBy} ${viaHeader}`;
  if (/ubuntu/i.test(combinedServer)) detectedOs = 'Ubuntu Linux';
  else if (/debian/i.test(combinedServer)) detectedOs = 'Debian Linux';
  else if (/alpine/i.test(combinedServer)) detectedOs = 'Alpine Linux';
  else if (/centos|rhel|red hat/i.test(combinedServer)) detectedOs = 'RHEL / CentOS Linux';
  else if (/win32|win64|microsoft-iis/i.test(combinedServer)) detectedOs = 'Windows Server (IIS)';
  else if (/uvicorn|gunicorn|hypercorn|werkzeug|Waitress/i.test(combinedServer)) detectedOs = 'Linux / Python ASGI-WSGI Runtime';
  else if (/openresty|nginx|envoy|caddy|apache/i.test(combinedServer)) detectedOs = 'Linux / Unix Server';
  else if (/cloudflare/i.test(combinedServer)) detectedOs = 'Cloudflare Anycast Edge Network';
  else if (/ESF| gws|sffe|scaffolding/i.test(combinedServer)) detectedOs = 'Google Borg / Frontend Infrastructure';

  // 2. Detect Edge Datacenter / POP (IATA Airport Code)
  let edgePopCode = null;
  let edgePopLocation = null;

  if (cfRay && cfRay.includes('-')) {
    edgePopCode = cfRay.split('-').pop().trim().toUpperCase();
  } else if (amzPop) {
    edgePopCode = amzPop.slice(0, 3).toUpperCase();
  } else if (servedBy) {
    const match = servedBy.match(/-([a-z]{3})\d*$/i);
    if (match) edgePopCode = match[1].toUpperCase();
  }

  if (edgePopCode) {
    edgePopLocation = IATA_POP_MAP[edgePopCode] ? `${edgePopCode} — ${IATA_POP_MAP[edgePopCode]}` : `${edgePopCode} Edge Datacenter`;
  }

  // 3. Detect Server Clock Skew from HTTP Date header
  let serverTimeIso = null;
  let clockSkewSec = null;
  let clockSkewSummary = 'No Date header';
  if (dateHeader) {
    const parsedTime = Date.parse(dateHeader);
    if (!Number.isNaN(parsedTime)) {
      serverTimeIso = new Date(parsedTime).toISOString();
      clockSkewSec = Math.round(((parsedTime - Date.now()) / 1000) * 10) / 10;
      clockSkewSummary =
        Math.abs(clockSkewSec) <= 2
          ? `Synced (Δ ${clockSkewSec}s)`
          : `Drift Δ ${clockSkewSec > 0 ? `+${clockSkewSec}` : clockSkewSec}s vs client`;
    }
  }

  // 4. Detect Transport Features (HTTP/3 QUIC, HSTS, Proxy Software)
  const supportsHttp3 = /h3(-|="|:)/i.test(altSvc);
  const hasHsts = Boolean(h['strict-transport-security']);

  const proxyIndicators = [];
  if (h['cf-ray']) proxyIndicators.push('Cloudflare CDN/WAF');
  if (h['x-litellm-version'] || h['x-litellm-call-id']) proxyIndicators.push(`LiteLLM (${h['x-litellm-version'] || 'active'})`);
  if (h['x-kong-upstream-latency'] || h['x-kong-proxy-latency']) proxyIndicators.push('Kong API Gateway');
  if (h['x-envoy-upstream-service-time']) proxyIndicators.push('Envoy Service Proxy');
  if (h['x-oneapi-request-id'] || h['x-newapi-request-id']) proxyIndicators.push('OneAPI / NewAPI Gateway');
  if (h['x-request-id']) proxyIndicators.push(`Request-ID (${h['x-request-id']})`);

  return {
    webServer: serverRaw || 'Not disclosed',
    poweredBy: poweredBy || null,
    via: viaHeader || null,
    detectedOs,
    edgePopCode,
    edgePopLocation,
    cfRay: cfRay || null,
    serverTimeIso,
    clockSkewSec,
    clockSkewSummary,
    supportsHttp3,
    hasHsts,
    proxyIndicators
  };
}

export function analyzeGatewayAndHeaders({
  baseUrl,
  headers = {},
  responseId = null,
  systemFingerprint = null,
  providerField = null
}) {
  let host = 'unknown';
  try {
    host = new URL(baseUrl).hostname.toLowerCase();
  } catch {
    host = String(baseUrl);
  }

  const h = headers || {};
  let gatewayType = 'UNKNOWN_ENDPOINT';
  let gatewayLabel = host;
  let isOfficialDirect = false;
  let isKnownRouter = false;
  let isThirdPartyProxy = false;
  const headerEvidence = [];

  if (host === 'api.openai.com') {
    gatewayType = 'OFFICIAL_OPENAI';
    gatewayLabel = 'OpenAI Official Native (api.openai.com)';
    isOfficialDirect = true;
    if (h['openai-processing-ms']) headerEvidence.push(`openai-processing-ms: ${h['openai-processing-ms']}ms`);
    if (h['openai-version']) headerEvidence.push(`openai-version: ${h['openai-version']}`);
  } else if (host === 'api.anthropic.com') {
    gatewayType = 'OFFICIAL_ANTHROPIC';
    gatewayLabel = 'Anthropic Official Native (api.anthropic.com)';
    isOfficialDirect = true;
    if (h['request-id']) headerEvidence.push(`request-id: ${h['request-id']}`);
  } else if (host.endsWith('googleapis.com')) {
    gatewayType = 'OFFICIAL_GEMINI';
    gatewayLabel = 'Google Gemini Official Native (googleapis.com)';
    isOfficialDirect = true;
  } else if (host.includes('openrouter.ai') || (responseId && String(responseId).startsWith('gen-'))) {
    gatewayType = 'OPENROUTER_GATEWAY';
    gatewayLabel = `OpenRouter Gateway${providerField ? ` (Upstream: ${providerField})` : ''}`;
    isKnownRouter = true;
    if (providerField) headerEvidence.push(`Upstream Provider: ${providerField}`);
  } else if (host === 'api.deepseek.com') {
    gatewayType = 'OFFICIAL_DEEPSEEK';
    gatewayLabel = 'DeepSeek Official Native (api.deepseek.com)';
    isOfficialDirect = true;
  } else if (host === 'api.groq.com' || h['x-groq-id']) {
    gatewayType = 'OFFICIAL_GROQ';
    gatewayLabel = 'Groq Cloud LPU Native (api.groq.com)';
    isOfficialDirect = true;
  } else if (host === 'api.x.ai') {
    gatewayType = 'OFFICIAL_XAI';
    gatewayLabel = 'xAI Official Native (api.x.ai)';
    isOfficialDirect = true;
  } else if (h['x-litellm-version'] || h['x-litellm-call-id'] || h['x-litellm-model-id']) {
    gatewayType = 'LITELLM_PROXY';
    gatewayLabel = `LiteLLM Proxy Gateway ${h['x-litellm-version'] ? `(v${h['x-litellm-version']})` : ''}`;
    isKnownRouter = true;
    if (h['x-litellm-model-id']) headerEvidence.push(`x-litellm-model-id: ${h['x-litellm-model-id']}`);
  } else if (host === 'localhost' || host === '127.0.0.1') {
    gatewayType = 'LOCAL_RUNTIME';
    gatewayLabel = `Local Runtime (${host})`;
    isKnownRouter = true;
  } else {
    gatewayType = 'THIRD_PARTY_PROXY';
    gatewayLabel = `Custom / Third-Party Proxy (${host})`;
    isThirdPartyProxy = true;
  }

  if (h['server']) headerEvidence.push(`server: ${h['server']}`);
  if (h['cf-ray']) headerEvidence.push(`cf-ray: ${h['cf-ray']}`);
  if (systemFingerprint) headerEvidence.push(`system_fingerprint: ${systemFingerprint}`);

  const reqLimit = h['x-ratelimit-limit-requests'] || h['anthropic-ratelimit-requests-limit'] || null;
  const reqRem = h['x-ratelimit-remaining-requests'] || h['anthropic-ratelimit-requests-remaining'] || null;
  const tokLimit = h['x-ratelimit-limit-tokens'] || h['anthropic-ratelimit-tokens-limit'] || null;
  const tokRem = h['x-ratelimit-remaining-tokens'] || h['anthropic-ratelimit-tokens-remaining'] || null;
  const serverProcessingMs = h['openai-processing-ms'] || h['x-envoy-upstream-service-time'] || null;

  let rateLimitSummary = 'Not exposed via CORS headers';
  if (reqRem !== null || tokRem !== null) {
    const parts = [];
    if (reqRem !== null) parts.push(`Req: ${reqRem}${reqLimit ? `/${reqLimit}` : ''}`);
    if (tokRem !== null) parts.push(`Tok: ${tokRem}${tokLimit ? `/${tokLimit}` : ''}`);
    rateLimitSummary = parts.join(' • ');
  }

  const serverHeadersInfo = parseServerHeadersForensics(h);

  return {
    host,
    gatewayType,
    gatewayLabel,
    isOfficialDirect,
    isKnownRouter,
    isThirdPartyProxy,
    headerEvidence,
    rateLimits: {
      requestsLimit: reqLimit,
      requestsRemaining: reqRem,
      tokensLimit: tokLimit,
      tokensRemaining: tokRem,
      summary: rateLimitSummary
    },
    serverProcessingMs,
    serverHeadersInfo
  };
}

/**
 * Resolves Public IP (A, AAAA), CNAME chain, Reverse DNS (PTR), ASN/Hosting Provider, Geolocation,
 * and combines with TCP/TLS Certificate Forensics from cors-bridge.mjs if available.
 * Zero-Secret Policy: Only queries the public target hostname/IP — NEVER sends API keys.
 */
export async function inspectNetworkAndServer({ baseUrl, headers = {} }) {
  let hostname = '';
  let port = 443;
  let protocol = 'HTTPS';
  try {
    const parsed = new URL(baseUrl);
    hostname = parsed.hostname;
    protocol = parsed.protocol.replace(':', '').toUpperCase();
    port = Number(parsed.port) || (protocol === 'HTTPS' ? 443 : 80);
  } catch {
    return null;
  }

  const result = {
    hostname,
    port,
    protocol,
    ipv4List: [],
    ipv6List: [],
    cnameChain: [],
    reversePtr: [],
    dnsTtlSec: null,
    primaryIp: null,
    asn: null,
    ispOrg: null,
    country: null,
    region: null,
    city: null,
    timezone: null,
    coordinates: null,
    tls: null,
    serverHeaders: parseServerHeadersForensics(headers),
    exposedHeadersSnapshot: {}
  };

  // Capture non-sensitive response headers snapshot
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() !== 'x-bridge-forensics') {
      result.exposedHeadersSnapshot[k] = v;
    }
  }

  // 1. Decode TCP & TLS forensics from cors-bridge.mjs if header 'x-bridge-forensics' is present
  if (headers['x-bridge-forensics']) {
    try {
      const decodedJson = atob(headers['x-bridge-forensics']);
      const bridgeData = JSON.parse(decodedJson);
      if (Array.isArray(bridgeData.resolvedIps)) {
        for (const item of bridgeData.resolvedIps) {
          if (item.family === 'IPv4' && !result.ipv4List.includes(item.address)) {
            result.ipv4List.push(item.address);
          } else if (item.family === 'IPv6' && !result.ipv6List.includes(item.address)) {
            result.ipv6List.push(item.address);
          }
        }
      }
      if (bridgeData.remoteIp && !result.ipv4List.includes(bridgeData.remoteIp) && !bridgeData.remoteIp.includes(':')) {
        result.ipv4List.unshift(bridgeData.remoteIp);
      }
      if (Array.isArray(bridgeData.cnames) && bridgeData.cnames.length > 0) {
        result.cnameChain = bridgeData.cnames;
      }
      if (Array.isArray(bridgeData.reversePtr) && bridgeData.reversePtr.length > 0) {
        result.reversePtr = bridgeData.reversePtr;
      }
      if (bridgeData.tls) {
        result.tls = bridgeData.tls;
      }
    } catch {
      // ignore malformed header
    }
  }

  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  if (isRawIp && !result.ipv4List.includes(hostname)) {
    result.ipv4List.push(hostname);
  }

  // 2. Query DNS-over-HTTPS (DoH) directly from browser for A, AAAA, and CNAME records
  if (!isLocalhost && !isRawIp) {
    try {
      const fetchDoh = async (recordType) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3500);
        try {
          const res = await fetch(
            `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${recordType}`,
            {
              method: 'GET',
              cache: 'no-store',
              credentials: 'omit',
              referrerPolicy: 'no-referrer',
              signal: controller.signal
            }
          );
          if (!res.ok) return null;
          return await res.json();
        } catch {
          return null;
        } finally {
          clearTimeout(timer);
        }
      };

      const [aData, aaaaData] = await Promise.all([fetchDoh('A'), fetchDoh('AAAA')]);

      if (aData && Array.isArray(aData.Answer)) {
        for (const ans of aData.Answer) {
          if (ans.type === 5 && ans.data) {
            const cleanCname = String(ans.data).replace(/\.$/, '');
            if (!result.cnameChain.includes(cleanCname)) result.cnameChain.push(cleanCname);
          } else if (ans.type === 1 && ans.data) {
            if (!result.ipv4List.includes(ans.data)) result.ipv4List.push(ans.data);
            if (result.dnsTtlSec === null && typeof ans.TTL === 'number') result.dnsTtlSec = ans.TTL;
          }
        }
      }

      if (aaaaData && Array.isArray(aaaaData.Answer)) {
        for (const ans of aaaaData.Answer) {
          if (ans.type === 28 && ans.data && !result.ipv6List.includes(ans.data)) {
            result.ipv6List.push(ans.data);
          }
        }
      }
    } catch {
      // ignore DoH error
    }
  }

  result.primaryIp = result.ipv4List[0] || result.ipv6List[0] || (isLocalhost ? '127.0.0.1' : null);

  // 3. Reverse DNS (PTR) via DoH if not already resolved and primaryIp is IPv4
  if (
    result.primaryIp &&
    !isLocalhost &&
    result.reversePtr.length === 0 &&
    /^\d{1,3}(\.\d{1,3}){3}$/.test(result.primaryIp)
  ) {
    try {
      const revArpa = `${result.primaryIp.split('.').reverse().join('.')}.in-addr.arpa`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const ptrRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(revArpa)}&type=PTR`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal
      }).catch(() => null);
      clearTimeout(timer);
      if (ptrRes && ptrRes.ok) {
        const ptrJson = await ptrRes.json();
        if (Array.isArray(ptrJson?.Answer)) {
          for (const ans of ptrJson.Answer) {
            if (ans.data) {
              result.reversePtr.push(String(ans.data).replace(/\.$/, ''));
            }
          }
        }
      }
    } catch {
      // ignore PTR error
    }
  }

  // 4. Public IP ASN, Hosting Provider / ISP & Geolocation Lookup
  if (result.primaryIp && !isLocalhost) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3800);
      const geoRes = await fetch(`https://ipwho.is/${encodeURIComponent(result.primaryIp)}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal
      }).catch(() => null);
      clearTimeout(timer);

      if (geoRes && geoRes.ok) {
        const geo = await geoRes.json();
        if (geo && geo.success !== false) {
          result.asn = geo.connection?.asn ? `AS${geo.connection.asn}` : null;
          result.ispOrg = geo.connection?.org || geo.connection?.isp || null;
          result.country = geo.country ? `${geo.country} (${geo.country_code || ''})` : null;
          result.region = geo.region || null;
          result.city = geo.city || null;
          result.timezone = geo.timezone?.id
            ? `${geo.timezone.id} (${geo.timezone.utc || ''})`
            : null;
          if (geo.latitude && geo.longitude) {
            result.coordinates = `${geo.latitude}, ${geo.longitude}`;
          }
        }
      }
    } catch {
      // ignore geo error
    }
  }

  return result;
}

/**
 * Evaluates Stage 7 Authenticity Probe & Aggregates Final Anti-Masking Report
 */
export function buildAuthenticityReport({
  requestedModel,
  actualModel,
  gatewayInfo,
  modelRegistryEntry,
  chatUsage,
  probeResult
}) {
  const findings = [];
  let score = 100;
  let maskingSuspected = false;

  const identityCheck = compareModelIdentity(requestedModel, actualModel);
  findings.push(`[Model Snapshot] ${identityCheck.summary}`);
  if (identityCheck.suspicious) {
    score -= 40;
    maskingSuspected = true;
  }

  const reqFamily = extractModelFamily(requestedModel);
  if (gatewayInfo.isOfficialDirect) {
    findings.push(`[Gateway Origin] Direct connection to official provider host (${gatewayInfo.host}).`);
  } else if (gatewayInfo.isKnownRouter) {
    findings.push(`[Gateway Origin] Routed via recognized gateway: ${gatewayInfo.gatewayLabel}.`);
    score -= 5;
  } else if (gatewayInfo.isThirdPartyProxy) {
    findings.push(
      `[Gateway Origin] Third-party proxy detected (${gatewayInfo.host}) serving ${reqFamily.family.toUpperCase()} model.`
    );
    score -= 20;
  }

  if (chatUsage && typeof chatUsage.prompt_tokens === 'number') {
    const pTok = chatUsage.prompt_tokens;
    const cTok = chatUsage.completion_tokens;
    if (pTok <= 0 || cTok <= 0) {
      findings.push(
        `[Tokenizer Accounting] Suspicious zero/empty token count (prompt=${pTok}, completion=${cTok}) — typical of synthetic wrapper proxies.`
      );
      score -= 25;
      maskingSuspected = true;
    } else {
      const details = [];
      if (chatUsage.prompt_tokens_details?.cached_tokens !== undefined) details.push('OpenAI prompt_tokens_details');
      if (chatUsage.completion_tokens_details?.reasoning_tokens !== undefined) details.push('reasoning_tokens');
      if (chatUsage.prompt_cache_hit_tokens !== undefined) details.push('DeepSeek cache_hit signature');
      if (chatUsage.cache_read_input_tokens !== undefined) details.push('Anthropic cache_read signature');
      findings.push(
        `[Tokenizer Accounting] Valid token accounting (prompt=${pTok}, completion=${cTok}${
          details.length ? `, native fields: ${details.join(', ')}` : ''
        }).`
      );
    }
  } else {
    findings.push(`[Tokenizer Accounting] Endpoint did not return standard token usage metadata.`);
    score -= 15;
  }

  if (probeResult && probeResult.parsedProbe) {
    const p = probeResult.parsedProbe;
    const claimedFamily = (p.model_family || '').toLowerCase();
    const claimedCreator = (p.creator || '').toLowerCase();

    findings.push(
      `[Behavioral Probe] Model self-reported family="${p.model_family || 'unknown'}", creator="${
        p.creator || 'unknown'
      }", cutoff="${p.knowledge_cutoff || 'unknown'}".`
    );

    if (
      reqFamily.family !== 'custom' &&
      claimedFamily &&
      !claimedFamily.includes(reqFamily.family) &&
      !claimedCreator.includes(reqFamily.vendor)
    ) {
      findings.push(
        `[ANTI-MASKING ALERT] Behavioral mismatch! Config requested ${reqFamily.family.toUpperCase()} (${
          reqFamily.vendor
        }), but the model identified itself as "${p.model_family}" by "${p.creator}".`
      );
      score -= 45;
      maskingSuspected = true;
    }
  } else if (probeResult && probeResult.rawContent) {
    findings.push(`[Behavioral Probe] Probe response received: "${String(probeResult.rawContent).slice(0, 110)}"`);
  }

  if (modelRegistryEntry) {
    findings.push(
      `[Registry Metadata] Model verified in /models endpoint (owned_by="${modelRegistryEntry.owned_by || 'n/a'}"${
        modelRegistryEntry.context_length ? `, context_window=${modelRegistryEntry.context_length}` : ''
      }).`
    );
  }

  score = Math.max(0, Math.min(100, score));

  let verdictCode = 'VERIFIED_NATIVE';
  let verdictBadgeText = `VERIFIED NATIVE (${score}%)`;
  let verdictClass = 'badge-passed';

  if (maskingSuspected || score < 55) {
    verdictCode = 'MASKING_OR_REMAPPED';
    verdictBadgeText = `MASKING / MISMATCH ALERT (${score}%)`;
    verdictClass = 'badge-failed';
  } else if (gatewayInfo.isThirdPartyProxy) {
    verdictCode = 'THIRD_PARTY_PROXY';
    verdictBadgeText = `3RD-PARTY PROXY (${score}%)`;
    verdictClass = 'badge-warning';
  } else if (gatewayInfo.isKnownRouter) {
    verdictCode = 'VERIFIED_GATEWAY';
    verdictBadgeText = `VERIFIED GATEWAY (${score}%)`;
    verdictClass = 'badge-passed';
  }

  return {
    verdictCode,
    verdictBadgeText,
    verdictClass,
    confidenceScore: score,
    maskingSuspected,
    identityCheck,
    findings
  };
}
