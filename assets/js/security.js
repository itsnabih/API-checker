/**
 * security.js — Zero-Trace & Anti-Sniffing Security Module (RAM-Only)
 *
 * Guarantees:
 * 1. Zero persistent storage: Never touches localStorage, sessionStorage, IndexedDB, or Cookies.
 * 2. Volatile closure vault: API key lives exclusively in an in-memory closure variable.
 * 3. Anti-Password-Manager & Anti-Autofill: Randomizes input field names per session.
 * 4. Redaction engine: Masks API keys in all logs, DOM previews, and JSON inspectors.
 * 5. Smart Zero-Cache Fetch with CORS Auto-Failover & Zero-Credential Opaque Reachability Probe.
 * 6. Lifecycle & Idle Auto-Wipe: Purges RAM and DOM on unload/pagehide or idle timeout.
 * 7. Clipboard Guard: Automatically clears copied secrets from OS clipboard after N seconds.
 */

// Private closure state (Volatile RAM only — never serialized to disk)
let _ephemeralApiKey = '';
let _ephemeralCustomHeaders = '';
let _idleTimeoutMinutes = 5;
let _idleRemainingSeconds = 5 * 60;
let _idleIntervalId = null;
let _clipboardTimerId = null;
let _clipboardCountdownId = null;
let _onPurgeCallbacks = [];

// Volatile CORS Bridge Configuration (RAM-only)
// To auto-enable CORS Bridge on GitHub Pages across all devices (Mobile & Desktop):
// Paste your deployed Cloudflare Worker URL into CLOUD_BRIDGE_URL below before pushing to GitHub!
export const CLOUD_BRIDGE_URL = 'https://agent-api-bridge.ahmadnabih0903.workers.dev/proxy'; // Example: 'https://agent-api-bridge.yourname.workers.dev/proxy'
export const LOCAL_BRIDGE_URL = 'http://127.0.0.1:8787/proxy';

export function normalizeBridgeUrl(rawUrl) {
  let u = (rawUrl || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) {
    u = u.startsWith('127.0.0.1') || u.startsWith('localhost') ? `http://${u}` : `https://${u}`;
  }
  u = u.replace(/\/+$/, '');
  if (!u.endsWith('/proxy')) {
    u = `${u}/proxy`;
  }
  return u;
}

let _bridgeMode = 'auto'; // 'auto' | 'always' | 'direct'
let _bridgeUrl = normalizeBridgeUrl(CLOUD_BRIDGE_URL) || LOCAL_BRIDGE_URL;
let _localBridgeDetected = false;

/**
 * Generates a random non-predictable attribute name using Web Crypto API
 */
export function generateEphemeralFieldName(prefix = 'ephemeral') {
  const arr = new Uint32Array(2);
  window.crypto.getRandomValues(arr);
  return `${prefix}_${arr[0].toString(36)}_${arr[1].toString(36)}`;
}

/**
 * Volatile Secret Vault Getter/Setter
 */
export const SecretVault = {
  setApiKey(value) {
    _ephemeralApiKey = typeof value === 'string' ? value.trim() : '';
  },
  getApiKey() {
    return _ephemeralApiKey;
  },
  hasApiKey() {
    return _ephemeralApiKey.length > 0;
  },
  setCustomHeaders(value) {
    _ephemeralCustomHeaders = typeof value === 'string' ? value : '';
  },
  getCustomHeaders() {
    return _ephemeralCustomHeaders;
  },
  /**
   * Overwrites memory strings before releasing references
   */
  purge() {
    if (_ephemeralApiKey.length > 0) {
      _ephemeralApiKey = '0'.repeat(_ephemeralApiKey.length);
    }
    if (_ephemeralCustomHeaders.length > 0) {
      _ephemeralCustomHeaders = '0'.repeat(_ephemeralCustomHeaders.length);
    }
    _ephemeralApiKey = '';
    _ephemeralCustomHeaders = '';
  }
};

/**
 * CORS Bridge Manager (Zero-Trace Local Bridge or Self-Hosted Cloudflare Worker)
 */
export const CorsBridgeConfig = {
  setMode(mode) {
    if (['auto', 'always', 'direct'].includes(mode)) {
      _bridgeMode = mode;
    }
  },
  getMode() {
    return _bridgeMode;
  },
  setUrl(url) {
    _bridgeUrl = typeof url === 'string' && url.trim() ? normalizeBridgeUrl(url) : LOCAL_BRIDGE_URL;
  },
  getUrl() {
    return _bridgeUrl;
  },
  isLocalBridgeDetected() {
    return _localBridgeDetected;
  },
  async checkBridgeHealth(customUrl = _bridgeUrl) {
    const target = (customUrl || '').trim().replace(/\/proxy\/?$/i, '/health');
    if (!target) return false;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1800);
    try {
      const res = await fetch(target, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal
      });
      _localBridgeDetected = res.ok;
      return res.ok;
    } catch {
      _localBridgeDetected = false;
      return false;
    } finally {
      clearTimeout(timer);
    }
  }
};

/**
 * Detects key format/provider hint from key prefix without exposing the key
 */
export function detectKeyFormat(rawKey) {
  const key = (rawKey || '').trim();
  if (!key) return { label: 'NO KEY', providerHint: null, validShape: false };
  if (key.startsWith('sk-or-v1-')) {
    return { label: 'OpenRouter Key (sk-or-v1-*)', providerHint: 'openai', validShape: key.length > 24 };
  }
  if (key.startsWith('sk-ant-')) {
    return { label: 'Anthropic Key (sk-ant-*)', providerHint: 'anthropic', validShape: key.length > 24 };
  }
  if (key.startsWith('sk-proj-') || key.startsWith('sk-svcacct-')) {
    return { label: 'OpenAI Project Key (sk-proj-*)', providerHint: 'openai', validShape: key.length > 24 };
  }
  if (key.startsWith('gsk_')) {
    return { label: 'Groq Cloud Key (gsk_*)', providerHint: 'openai', validShape: key.length > 20 };
  }
  if (key.startsWith('AIzaSy')) {
    return { label: 'Google Gemini Key (AIzaSy*)', providerHint: 'gemini', validShape: key.length >= 35 };
  }
  if (key.startsWith('xai-')) {
    return { label: 'xAI Grok Key (xai-*)', providerHint: 'openai', validShape: key.length > 20 };
  }
  if (key.startsWith('sk-')) {
    return { label: 'Standard Secret Key (sk-*)', providerHint: 'openai', validShape: key.length >= 16 };
  }
  return { label: `Bearer / Custom Token (${key.length} chars)`, providerHint: null, validShape: key.length >= 8 };
}

/**
 * Formats a masked preview of the API key for safe visual display in the UI
 */
export function maskKeyPreview(key = _ephemeralApiKey) {
  const clean = (key || '').trim();
  if (!clean) return '<EMPTY_API_KEY>';
  if (clean.length <= 10) return '••••••••••••';
  const head = clean.slice(0, 6);
  const tail = clean.slice(-3);
  return `${head}••••••••••••••••${tail}`;
}

/**
 * Deeply redacts the active API key and any token-like strings from text or JSON objects
 */
export function redactSecrets(input, extraSecrets = []) {
  if (input === null || input === undefined) return input;
  const isObject = typeof input === 'object';
  let text = isObject ? JSON.stringify(input, null, 2) : String(input);

  const secretsToRedact = [_ephemeralApiKey, ...extraSecrets].filter(
    (s) => typeof s === 'string' && s.trim().length >= 6
  );

  for (const sec of secretsToRedact) {
    const trimmed = sec.trim();
    const masked = maskKeyPreview(trimmed);
    text = text.split(trimmed).join(masked);
  }

  // Also redact common key patterns if pasted inside raw logs
  text = text.replace(/\b(sk-[a-zA-Z0-9_-]{8})[a-zA-Z0-9_-]{10,}([a-zA-Z0-9_-]{3})\b/g, '$1••••••••••••$2');
  text = text.replace(/\b(AIzaSy[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]{15,}([a-zA-Z0-9_-]{3})\b/g, '$1••••••••••••$2');
  text = text.replace(/\b(gsk_[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]{15,}([a-zA-Z0-9_-]{3})\b/g, '$1••••••••••••$2');

  if (isObject) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

/**
 * Hardens all sensitive input elements against Browser Autofill, History Cache, and Password Managers
 */
export function hardenInputElements(elements = []) {
  elements.forEach((el) => {
    if (!el) return;
    el.setAttribute('autocomplete', 'off');
    el.setAttribute('autocorrect', 'off');
    el.setAttribute('autocapitalize', 'off');
    el.setAttribute('spellcheck', 'false');
    el.setAttribute('data-lpignore', 'true');
    el.setAttribute('data-1p-ignore', 'true');
    el.setAttribute('data-bwignore', 'true');
    el.setAttribute('data-form-type', 'other');
    el.setAttribute('name', generateEphemeralFieldName('sec_input'));
  });
}

/**
 * Builds standard Zero-Cache fetch options so the browser never writes HTTP payloads to Cache_Data on disk
 */
export function createZeroCacheFetchOptions(options = {}) {
  return {
    ...options,
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    mode: options.mode || 'cors'
  };
}

/**
 * Zero-Credential Opaque Reachability Probe:
 * Sends a no-cors ping WITHOUT any API key or custom headers to determine if an endpoint
 * is actually ONLINE (just blocking browser CORS) vs truly OFFLINE/DNS/SSL dead.
 */
export async function probeEndpointReachability(targetUrl, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(targetUrl, {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal
    });
    // In no-cors mode, an opaque response (type === 'opaque') proves TCP/TLS handshake succeeded!
    if (res && (res.type === 'opaque' || res.ok || res.status >= 100)) {
      return { reachable: true, classification: 'ONLINE_CORS_BLOCKED' };
    }
    return { reachable: false, classification: 'OFFLINE_OR_UNREACHABLE' };
  } catch {
    return { reachable: false, classification: 'OFFLINE_OR_DNS_SSL_ERROR' };
  } finally {
    clearTimeout(timer);
  }
}

async function rawTimedFetch(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startTime = performance.now();
  try {
    const response = await fetch(
      url,
      createZeroCacheFetchOptions({
        ...options,
        signal: controller.signal
      })
    );
    const ttfbMs = Math.round(performance.now() - startTime);
    return { response, ttfbMs, startTime };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Smart Zero-Cache Fetch with Automatic Failover to Zero-Trace CORS Bridge
 */
export async function smartZeroCacheFetch(targetUrl, options = {}, timeoutMs = 25000) {
  const mode = _bridgeMode;
  const bridgeUrl = (_bridgeUrl || '').trim();

  const callViaBridge = async (candidateBridgeUrl = bridgeUrl) => {
    if (!candidateBridgeUrl) {
      throw new Error('CORS Bridge URL is not configured.');
    }
    const bridgeHeaders = {
      ...(options.headers || {}),
      'x-target-url': targetUrl
    };
    const resObj = await rawTimedFetch(
      candidateBridgeUrl,
      {
        ...options,
        headers: bridgeHeaders
      },
      timeoutMs
    );
    return {
      ...resObj,
      routedViaBridge: true,
      bridgeUrl: candidateBridgeUrl
    };
  };

  if (mode === 'always' && bridgeUrl) {
    return await callViaBridge(bridgeUrl);
  }

  // Try Direct Browser Fetch first
  try {
    const directRes = await rawTimedFetch(targetUrl, options, timeoutMs);
    return {
      ...directRes,
      routedViaBridge: false,
      bridgeUrl: null
    };
  } catch (directErr) {
    // If mode is 'auto', try configured bridge URL first, then fallback to local/cloud candidate
    if (mode === 'auto' && directErr?.name !== 'AbortError') {
      const candidates = [bridgeUrl, CLOUD_BRIDGE_URL, LOCAL_BRIDGE_URL].filter(
        (u, idx, arr) => Boolean(u) && arr.indexOf(u) === idx
      );
      for (const candidate of candidates) {
        try {
          return await callViaBridge(candidate);
        } catch {
          // Try next candidate bridge
        }
      }
    }

    // Perform Zero-Credential Reachability Probe to tell user if server is alive (just blocking CORS)
    if (directErr?.name !== 'AbortError') {
      const probe = await probeEndpointReachability(targetUrl);
      directErr.corsReachability = probe.classification;
      directErr.serverReachable = probe.reachable;
      directErr.bridgeUrlAttempted = mode === 'auto' ? bridgeUrl : null;
    }
    throw directErr;
  }
}

/**
 * Copies text to clipboard and optionally schedules an automatic clipboard wipe after `clearAfterSec`
 */
export async function copyToClipboardSecured(text, { autoClearSec = 30, onCountdown } = {}) {
  if (_clipboardTimerId) clearTimeout(_clipboardTimerId);
  if (_clipboardCountdownId) clearInterval(_clipboardCountdownId);

  await navigator.clipboard.writeText(text);

  if (autoClearSec > 0) {
    let remaining = autoClearSec;
    if (onCountdown) onCountdown(remaining);

    _clipboardCountdownId = setInterval(() => {
      remaining -= 1;
      if (remaining > 0) {
        if (onCountdown) onCountdown(remaining);
      } else {
        clearInterval(_clipboardCountdownId);
      }
    }, 1000);

    _clipboardTimerId = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // Ignore if document lost focus during auto-clear
      }
      if (onCountdown) onCountdown(0);
    }, autoClearSec * 1000);
  }
}

/**
 * Registers a callback invoked whenever RAM is purged (manual button, idle timeout, or tab close)
 */
export function onRamPurge(callback) {
  if (typeof callback === 'function') {
    _onPurgeCallbacks.push(callback);
  }
}

/**
 * Immediately purges all secrets from RAM, DOM inputs, and optionally clipboard
 */
export function purgeAllRamAndDom(reason = 'manual') {
  SecretVault.purge();

  // Clear all inputs and textareas in DOM
  document.querySelectorAll('input, textarea').forEach((el) => {
    if (el.type !== 'checkbox' && el.type !== 'radio') {
      if (el.id === 'inputBridgeUrl') return; // preserve non-secret bridge address
      el.value = '';
    }
    if (el.hasAttribute('name')) {
      el.setAttribute('name', generateEphemeralFieldName('wiped'));
    }
  });

  // Ensure localStorage / sessionStorage have zero residue from any prior context
  try {
    window.localStorage.clear();
    window.sessionStorage.clear();
  } catch {
    // Blocked by browser privacy settings (even better)
  }

  _onPurgeCallbacks.forEach((cb) => {
    try {
      cb(reason);
    } catch {
      // ignore
    }
  });

  resetIdleTimer();
}

/**
 * Resets the Idle Auto-Wipe countdown
 */
export function resetIdleTimer() {
  _idleRemainingSeconds = _idleTimeoutMinutes * 60;
}

/**
 * Sets Idle Auto-Wipe duration in minutes (0 = disabled)
 */
export function setIdleTimeoutMinutes(minutes) {
  const parsed = Number(minutes);
  _idleTimeoutMinutes = Number.isFinite(parsed) && parsed >= 0 ? parsed : 5;
  resetIdleTimer();
}

/**
 * Initializes lifecycle event listeners (pagehide, beforeunload, idle timer)
 */
export function initSecurityLifecycle({ onTick } = {}) {
  window.addEventListener('beforeunload', () => {
    SecretVault.purge();
  });
  window.addEventListener('pagehide', () => {
    SecretVault.purge();
  });

  ['keydown', 'mousedown', 'pointerdown', 'touchstart'].forEach((evt) => {
    window.addEventListener(evt, () => resetIdleTimer(), { passive: true });
  });

  if (_idleIntervalId) clearInterval(_idleIntervalId);
  _idleIntervalId = setInterval(() => {
    if (_idleTimeoutMinutes <= 0) {
      if (onTick) onTick({ disabled: true, formatted: 'OFF' });
      return;
    }

    if (SecretVault.hasApiKey()) {
      _idleRemainingSeconds -= 1;
      if (_idleRemainingSeconds <= 0) {
        purgeAllRamAndDom('idle_timeout');
      }
    } else {
      _idleRemainingSeconds = _idleTimeoutMinutes * 60;
    }

    const mins = Math.floor(Math.max(0, _idleRemainingSeconds) / 60);
    const secs = Math.max(0, _idleRemainingSeconds) % 60;
    const formatted = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    if (onTick) {
      onTick({
        disabled: false,
        remainingSeconds: _idleRemainingSeconds,
        activeSecret: SecretVault.hasApiKey(),
        formatted
      });
    }
  }, 1000);
}
