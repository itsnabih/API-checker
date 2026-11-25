/**
 * app.js — Main UI Controller for AGENT API.IO (JWT.io Split-Pane Debugger + Zero-Trace Security)
 */

import {
  SecretVault,
  CorsBridgeConfig,
  detectKeyFormat,
  maskKeyPreview,
  hardenInputElements,
  copyToClipboardSecured,
  onRamPurge,
  purgeAllRamAndDom,
  setIdleTimeoutMinutes,
  initSecurityLifecycle
} from './security.js';
import { INITIAL_STAGES, resolveAdapter, runDiagnosticSuite } from './diagnostics.js';
import { parseEphemeralConfigInput, generateExportConfig } from './parser.js';

// Application Volatile State
let currentProtocol = 'auto';
let currentExportFormat = 'strix';
let currentStages = INITIAL_STAGES.map((s) => ({ ...s }));
let lastTelemetry = null;
let isMaskEnabled = true;

// Keep track of expanded stages and per-stage display mode ('points' | 'json')
const expandedStageIds = new Set();
const stageViewModes = {
  1: 'points',
  2: 'points',
  3: 'points',
  4: 'points',
  5: 'points',
  6: 'points',
  7: 'points'
};

// DOM Elements
const els = {
  idleTimerDisplay: document.getElementById('idleTimerDisplay'),
  idleTimeoutSelect: document.getElementById('idleTimeoutSelect'),
  btnThemeToggle: document.getElementById('btnThemeToggle'),
  themeToggleLabel: document.getElementById('themeToggleLabel'),
  btnPurgeRam: document.getElementById('btnPurgeRam'),
  protocolPills: document.getElementById('protocolPills'),
  mobilePaneNav: document.getElementById('mobilePaneNav'),
  mobileNavScore: document.getElementById('mobileNavScore'),
  debuggerGrid: document.getElementById('debuggerGrid'),
  paneConfig: document.getElementById('paneConfig'),
  paneResults: document.getElementById('paneResults'),

  encSegHeader: document.getElementById('encSegHeader'),
  encSegPayload: document.getElementById('encSegPayload'),
  encSegSig: document.getElementById('encSegSig'),

  btnToggleImporter: document.getElementById('btnToggleImporter'),
  importerDrawer: document.getElementById('importerDrawer'),
  ephemeralImportTextarea: document.getElementById('ephemeralImportTextarea'),
  btnParseImport: document.getElementById('btnParseImport'),

  inputBaseUrl: document.getElementById('inputBaseUrl'),
  detectedProtocolBadge: document.getElementById('detectedProtocolBadge'),
  normalizedUrlHint: document.getElementById('normalizedUrlHint'),

  inputModelId: document.getElementById('inputModelId'),
  modelsCountBadge: document.getElementById('modelsCountBadge'),
  btnFetchModels: document.getElementById('btnFetchModels'),
  modelDropdownList: document.getElementById('modelDropdownList'),

  inputApiKey: document.getElementById('inputApiKey'),
  keyFormatBadge: document.getElementById('keyFormatBadge'),
  btnToggleMask: document.getElementById('btnToggleMask'),
  authHeaderHint: document.getElementById('authHeaderHint'),

  btnToggleAdvanced: document.getElementById('btnToggleAdvanced'),
  advancedDrawer: document.getElementById('advancedDrawer'),
  selectBridgeMode: document.getElementById('selectBridgeMode'),
  inputBridgeUrl: document.getElementById('inputBridgeUrl'),
  inputCustomHeaders: document.getElementById('inputCustomHeaders'),
  inputTimeoutMs: document.getElementById('inputTimeoutMs'),

  btnRunFullSuite: document.getElementById('btnRunFullSuite'),
  btnQuickPing: document.getElementById('btnQuickPing'),

  verdictHeadline: document.getElementById('verdictHeadline'),
  verdictSubtext: document.getElementById('verdictSubtext'),
  verdictScoreBadge: document.getElementById('verdictScoreBadge'),

  headerHttpStatusBadge: document.getElementById('headerHttpStatusBadge'),
  kpiGatewayName: document.getElementById('kpiGatewayName'),
  kpiLatency: document.getElementById('kpiLatency'),
  kpiRateLimit: document.getElementById('kpiRateLimit'),
  kpiCorsStatus: document.getElementById('kpiCorsStatus'),
  tabBtnHeaderSysinfo: document.getElementById('tabBtnHeaderSysinfo'),
  tabBtnHeaderPoints: document.getElementById('tabBtnHeaderPoints'),
  tabBtnHeaderJson: document.getElementById('tabBtnHeaderJson'),
  decodedHeaderSysinfo: document.getElementById('decodedHeaderSysinfo'),
  decodedHeaderPoints: document.getElementById('decodedHeaderPoints'),
  decodedHeaderJson: document.getElementById('decodedHeaderJson'),

  tabBtnStages: document.getElementById('tabBtnStages'),
  tabBtnPayloadJson: document.getElementById('tabBtnPayloadJson'),
  viewStagesChecklist: document.getElementById('viewStagesChecklist'),
  viewPayloadJson: document.getElementById('viewPayloadJson'),
  stagesContainer: document.getElementById('stagesContainer'),
  decodedPayloadJson: document.getElementById('decodedPayloadJson'),

  kpiModelComparison: document.getElementById('kpiModelComparison'),
  kpiOwnerFingerprint: document.getElementById('kpiOwnerFingerprint'),
  kpiContextSpecs: document.getElementById('kpiContextSpecs'),
  kpiCapabilities: document.getElementById('kpiCapabilities'),

  authVerdictTitle: document.getElementById('authVerdictTitle'),
  authVerdictBadge: document.getElementById('authVerdictBadge'),
  authForensicsList: document.getElementById('authForensicsList'),

  exportFormatTabs: document.getElementById('exportFormatTabs'),
  btnCopyRedacted: document.getElementById('btnCopyRedacted'),
  btnCopyRealKey: document.getElementById('btnCopyRealKey'),
  clipboardStatusBadge: document.getElementById('clipboardStatusBadge'),
  exportConfigPreview: document.getElementById('exportConfigPreview')
};

const PRESET_DEFAULTS = {
  auto: { url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  openai: { url: 'https://api.openai.com/v1', model: 'gpt-4o' },
  openrouter: { url: 'https://openrouter.ai/api/v1', model: 'anthropic/claude-3.7-sonnet' },
  anthropic: { url: 'https://api.anthropic.com/v1', model: 'claude-3-7-sonnet-latest' },
  gemini: { url: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-2.5-flash' },
  litellm: { url: 'http://localhost:4000/v1', model: 'gpt-4o' }
};

function getEffectiveProtocol() {
  const baseUrl = els.inputBaseUrl.value.trim();
  const apiKey = SecretVault.getApiKey();
  const adapter = resolveAdapter(currentProtocol, baseUrl, apiKey);
  if (adapter.protocolName === 'ANTHROPIC-NATIVE') return 'anthropic';
  if (adapter.protocolName === 'GOOGLE-GEMINI-NATIVE') return 'gemini';
  return 'openai';
}

function parseCustomHeadersInput() {
  const raw = els.inputCustomHeaders.value.trim();
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}


function refreshLivePreview() {
  const baseUrl = els.inputBaseUrl.value.trim() || 'https://api.openai.com/v1';
  const model = els.inputModelId.value.trim() || 'gpt-4o-mini';
  const apiKey = SecretVault.getApiKey();
  const adapter = resolveAdapter(currentProtocol, baseUrl, apiKey);
  const effectiveProto = getEffectiveProtocol();

  const paths = adapter.getPreviewPaths(baseUrl, model);
  els.detectedProtocolBadge.textContent = adapter.protocolName;
  els.normalizedUrlHint.textContent = paths.chatUrl;
  els.authHeaderHint.textContent = paths.authHeaderPreview;

  const keyInfo = detectKeyFormat(apiKey);
  els.keyFormatBadge.textContent = keyInfo.label;

  // Update JWT.io 3-color encoded descriptor (Clean & Minimalist)
  els.encSegHeader.textContent = paths.base;
  els.encSegPayload.textContent = model;
  els.encSegSig.textContent = maskKeyPreview(apiKey);

  // Update Config Exporter Preview (always redacted on screen!)
  const forensicsSummary = lastTelemetry?.authenticityReport
    ? `${lastTelemetry.authenticityReport.verdictBadgeText} • Actual Model: ${lastTelemetry.actualReturnedModel || model}`
    : null;

  els.exportConfigPreview.textContent = generateExportConfig({
    format: currentExportFormat,
    protocol: effectiveProto,
    baseUrl: paths.base,
    model,
    apiKey,
    useRedacted: true,
    forensicsSummary
  });
}

/**
 * Builds easy-to-read Indonesian bullet points for non-technical users for each stage (Stage 1 - 7)
 */
function buildStageHumanPoints(st) {
  const statusLabel =
    st.status === 'passed'
      ? 'BERHASIL (Passed)'
      : st.status === 'warning'
      ? 'PERHATIAN (Warning)'
      : st.status === 'failed'
      ? 'GAGAL (Failed)'
      : st.status === 'running'
      ? 'SEDANG DIUJI...'
      : 'BELUM DIUJI';

  const points = [`<strong>Status Tahap 0${st.id}:</strong> ${escapeHtml(statusLabel)}${st.latencyMs !== null ? ` (Waktu respons: ${st.latencyMs} ms)` : ''}`];
  const d = st.details || {};

  if (!st.details) {
    points.push(`<strong>Penjelasan:</strong> ${escapeHtml(st.summary)}`);
    return points;
  }

  if (st.id === 1) {
    if (d.gateway) {
      points.push(`<strong>Penyedia / Jalur Server:</strong> ${escapeHtml(d.gateway.gatewayLabel || d.gateway.host)}`);
      points.push(
        `<strong>Tipe Koneksi:</strong> ${
          d.gateway.isOfficialDirect
            ? 'Langsung ke Server Resmi (Official Native)'
            : d.gateway.isKnownRouter
            ? 'Melalui Gateway/Router Terkenal'
            : 'Melalui Server Proxy Pihak Ketiga'
        }`
      );
      if (d.gateway.rateLimits?.summary) {
        points.push(`<strong>Info Kuota / Rate Limit:</strong> ${escapeHtml(d.gateway.rateLimits.summary)}`);
      }
    }
    if (d.error) {
      points.push(`<strong>Penyebab Kendala:</strong> ${escapeHtml(d.error)}`);
    }
    if (Array.isArray(d.howToFix)) {
      d.howToFix.forEach((tip) => points.push(`<strong>Solusi:</strong> ${escapeHtml(tip)}`));
    }
  } else if (st.id === 2) {
    if (d.matchedModelSpec) {
      const m = d.matchedModelSpec;
      points.push(`<strong>Ketersediaan Model:</strong> Model <code>${escapeHtml(m.id)}</code> ditemukan dan aktif di server.`);
      points.push(`<strong>Pemilik / Pembuat Model:</strong> ${escapeHtml(m.owned_by || 'Tidak dicantumkan')}`);
      if (m.context_length) {
        points.push(`<strong>Kapasitas Memori (Context Window):</strong> ${Number(m.context_length).toLocaleString()} token`);
      }
      if (d.totalModelsAvailable) {
        points.push(`<strong>Total Model di API Key Ini:</strong> ${d.totalModelsAvailable} model tersedia.`);
      }
    } else if (Array.isArray(d.sampleAvailableModels)) {
      points.push(`<strong>Keterangan:</strong> Nama model yang diketik tidak muncul di daftar katalog, namun tetap diuji panggil langsung.`);
      points.push(`<strong>Contoh Model yang Tersedia:</strong> ${escapeHtml(d.sampleAvailableModels.slice(0, 6).join(', '))}`);
    } else {
      points.push(`<strong>Keterangan:</strong> ${escapeHtml(st.summary)}`);
    }
  } else if (st.id === 3) {
    const resp = d.response || {};
    if (st.status === 'passed') {
      points.push(`<strong>Hasil Uji Obrolan (Chat):</strong> AI merespons dengan normal dan cepat.`);
      if (resp.model || resp.modelVersion) {
        points.push(`<strong>Model yang Menjawab:</strong> <code>${escapeHtml(resp.model || resp.modelVersion)}</code>`);
      }
      const usage = resp.usage || resp.usageMetadata;
      if (usage) {
        const pTok = usage.prompt_tokens ?? usage.input_tokens ?? usage.promptTokenCount ?? 0;
        const cTok = usage.completion_tokens ?? usage.output_tokens ?? usage.candidatesTokenCount ?? 0;
        points.push(`<strong>Pemakaian Token:</strong> ${pTok} token masuk (input) + ${cTok} token balasan (output).`);
      }
    } else {
      points.push(`<strong>Kendala Chat:</strong> ${escapeHtml(st.summary)}`);
      if (d.diagnosis) {
        points.push(`<strong>Analisis Penyebab:</strong> ${escapeHtml(d.diagnosis)}`);
      }
    }
  } else if (st.id === 4) {
    if (st.status === 'passed') {
      points.push(`<strong>Status Streaming (Real-Time):</strong> Berjalan lancar (${d.chunkCount || 0} potongan data diterima bertahap).`);
      points.push(`<strong>Waktu Respons Pertama:</strong> ${d.firstChunkMs || st.latencyMs || 0} ms.`);
      points.push(`<strong>Artinya untuk Agent:</strong> API ini aman dipakai untuk proses berpikir AI Agent secara langsung tanpa putus koneksi.`);
    } else {
      points.push(`<strong>Kendala Streaming:</strong> Server gagal mengirimkan aliran teks bertahap (SSE). Beberapa agent mungkin akan mengalami lambat atau timeout.`);
    }
  } else if (st.id === 5) {
    if (st.status === 'passed') {
      const fn = d.toolCallsEmitted?.[0]?.function;
      points.push(`<strong>Kemampuan Eksekusi Tool (Wajib untuk Strix/Xalgorix):</strong> LULUS. AI ini mampu menjalankan fungsi otomatis.`);
      if (fn) {
        points.push(`<strong>Simulasi Perintah:</strong> AI berhasil memanggil tool <code>${escapeHtml(fn.name)}</code> dengan parameter <code>${escapeHtml(fn.arguments)}</code>.`);
      }
    } else {
      points.push(`<strong>Peringatan Penting:</strong> AI ini hanya bisa mengobrol biasa, tetapi <strong>TIDAK BISA</strong> memanggil Tool/Fungsi otomatis.`);
      points.push(`<strong>Dampak:</strong> Jika dipasang ke Strix atau Xalgorix, agent kemungkinan besar akan gagal menjalankan perintah scanner atau eksekusi tugas.`);
    }
  } else if (st.id === 6) {
    if (st.status === 'passed') {
      points.push(`<strong>Kepatuhan Format Data (JSON):</strong> LULUS. AI patuh mengeluarkan data terstruktur tanpa teks berantakan.`);
      points.push(`<strong>Data yang Dihasilkan:</strong> <code>${escapeHtml(JSON.stringify(d.parsedJson))}</code>`);
    } else {
      points.push(`<strong>Kendala Format Output:</strong> AI kurang patuh saat diminta menghasilkan format JSON murni.`);
    }
  } else if (st.id === 7) {
    if (d.confidenceScore !== undefined) {
      points.push(`<strong>Skor Keaslian API &amp; Model:</strong> <strong>${d.confidenceScore}%</strong> (${escapeHtml(d.authenticityVerdict)})`);
    }
    if (Array.isArray(d.forensicFindings)) {
      d.forensicFindings.forEach((f) => points.push(escapeHtml(f)));
    }
  }

  return points;
}

/**
 * Renders the 7-Stage Diagnostic Checklist inside the PAYLOAD block with Points vs JSON toggle buttons
 */
function renderStagesList(stages) {
  els.stagesContainer.innerHTML = '';
  stages.forEach((st) => {
    const item = document.createElement('div');
    const isExpanded = expandedStageIds.has(st.id);
    item.className = `stage-item status-${st.status}${isExpanded ? ' expanded' : ''}`;

    const badgeClass =
      st.status === 'passed'
        ? 'badge-passed'
        : st.status === 'warning'
        ? 'badge-warning'
        : st.status === 'failed'
        ? 'badge-failed'
        : st.status === 'running'
        ? 'badge-running'
        : 'badge-pending';

    const latencyText = st.latencyMs !== null ? `${st.latencyMs} ms` : '';
    const activeMode = stageViewModes[st.id] || 'points';

    const header = document.createElement('div');
    header.className = 'stage-header';
    header.innerHTML = `
      <div class="stage-left">
        <span class="stage-num">0${st.id}</span>
        <div>
          <div class="stage-title">${escapeHtml(st.title)}</div>
          <div class="stage-summary">${escapeHtml(st.summary)}</div>
        </div>
      </div>
      <div class="stage-right">
        ${latencyText ? `<span class="pane-top-hint">${escapeHtml(latencyText)}</span>` : ''}
        <span class="stage-badge ${badgeClass}">${escapeHtml(st.status)}</span>
      </div>
    `;

    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'stage-details';

    // Top bar inside stage details with Points | JSON mode buttons
    const toolbar = document.createElement('div');
    toolbar.className = 'stage-detail-toolbar';
    toolbar.innerHTML = `
      <span class="stage-detail-label">Hasil Detail Tahap 0${st.id}</span>
      <div class="sub-tabs">
        <button type="button" class="sub-tab ${activeMode === 'points' ? 'active-purple' : ''}" data-mode="points">Poin Teks</button>
        <button type="button" class="sub-tab ${activeMode === 'json' ? 'active-purple' : ''}" data-mode="json">JSON</button>
      </div>
    `;

    // 1. Human-Readable Bullet Points Container
    const pointsUl = document.createElement('ul');
    pointsUl.className = 'human-points-list';
    pointsUl.style.display = activeMode === 'points' ? 'flex' : 'none';
    const bulletItems = buildStageHumanPoints(st);
    pointsUl.innerHTML = bulletItems.map((b) => `<li>${b}</li>`).join('');

    // 2. Raw JSON Container
    const pre = document.createElement('pre');
    pre.className = 'jwt-json-pre pre-purple';
    pre.style.display = activeMode === 'json' ? 'block' : 'none';
    pre.textContent = st.details
      ? JSON.stringify(st.details, null, 2)
      : JSON.stringify({ stage: st.title, status: st.status, summary: st.summary }, null, 2);

    // Toggle button events
    const [btnPoints, btnJson] = toolbar.querySelectorAll('.sub-tab');
    btnPoints.addEventListener('click', (e) => {
      e.stopPropagation();
      stageViewModes[st.id] = 'points';
      btnPoints.classList.add('active-purple');
      btnJson.classList.remove('active-purple');
      pointsUl.style.display = 'flex';
      pre.style.display = 'none';
    });

    btnJson.addEventListener('click', (e) => {
      e.stopPropagation();
      stageViewModes[st.id] = 'json';
      btnJson.classList.add('active-purple');
      btnPoints.classList.remove('active-purple');
      pre.style.display = 'block';
      pointsUl.style.display = 'none';
    });

    detailsDiv.appendChild(toolbar);
    detailsDiv.appendChild(pointsUl);
    detailsDiv.appendChild(pre);

    header.addEventListener('click', () => {
      const nowOpen = item.classList.toggle('expanded');
      if (nowOpen) expandedStageIds.add(st.id);
      else expandedStageIds.delete(st.id);
    });

    item.appendChild(header);
    item.appendChild(detailsDiv);
    els.stagesContainer.appendChild(item);
  });
}

/**
 * Updates the right-hand DECODED panels (HEADER, PAYLOAD, VERIFY AUTHENTICITY) and Bottom Verdict Banner
 */
function renderDecodedTelemetry(stages, telemetry) {
  currentStages = stages;
  lastTelemetry = telemetry;
  renderStagesList(stages);

  if (!telemetry) return;

  // 1. HEADER SECTION (MAGENTA)
  els.headerHttpStatusBadge.textContent = telemetry.httpStatus
    ? `HTTP ${telemetry.httpStatus} • ${telemetry.corsStatus}`
    : 'HTTP: IDLE';

  els.kpiGatewayName.textContent = telemetry.gatewayInfo?.gatewayLabel || '—';
  els.kpiLatency.textContent =
    telemetry.latency?.ttfbMs !== null
      ? `TTFB ${telemetry.latency.ttfbMs}ms / RTT ${telemetry.latency.totalMs}ms (${telemetry.latency.tokensPerSec || 0} tok/s)`
      : '—';
  els.kpiRateLimit.textContent = telemetry.gatewayInfo?.rateLimits?.summary || '—';
  els.kpiCorsStatus.textContent = telemetry.corsStatus || '—';

  els.decodedHeaderJson.textContent = JSON.stringify(
    {
      protocol: telemetry.protocolName,
      normalized_base_url: telemetry.normalizedBaseUrl,
      http_status: telemetry.httpStatus,
      cors_direct_browser: telemetry.corsStatus,
      network_and_ip_forensics: telemetry.networkForensics || null,
      gateway_forensics: telemetry.gatewayInfo
        ? {
            host: telemetry.gatewayInfo.host,
            type: telemetry.gatewayInfo.gatewayType,
            label: telemetry.gatewayInfo.gatewayLabel,
            official_direct: telemetry.gatewayInfo.isOfficialDirect,
            known_router: telemetry.gatewayInfo.isKnownRouter,
            third_party_proxy: telemetry.gatewayInfo.isThirdPartyProxy,
            evidence_headers: telemetry.gatewayInfo.headerEvidence,
            server_processing_ms: telemetry.gatewayInfo.serverProcessingMs
          }
        : null,
      rate_limits: telemetry.gatewayInfo?.rateLimits || null,
      target_runtime_probe: telemetry.sandboxProbe || null,
      zero_trace_policy: 'cache: no-store, credentials: omit, RAM-only'
    },
    null,
    2
  );

  // Render 100% Real Server, Public IP, DNS, ASN, TLS & Target Runtime Table (Zero Decorative ASCII Art)
  if (els.decodedHeaderSysinfo) {
    const net = telemetry.networkForensics;
    const gw = telemetry.gatewayInfo;
    const sh = net?.serverHeaders || gw?.serverHeadersInfo;

    const rows = [];
    const addRow = (k, v) => {
      if (v !== null && v !== undefined && String(v).trim() !== '') {
        rows.push(
          `<div class="sysinfo-key">${escapeHtml(k)}</div><div class="sysinfo-val">${escapeHtml(String(v))}</div>`
        );
      }
    };

    addRow('Target Host & Port', net ? `${net.hostname}:${net.port} (${net.protocol})` : gw?.host);
    addRow(
      'Public IPv4 (A)',
      net?.ipv4List?.length
        ? `${net.ipv4List.join(', ')}${net.dnsTtlSec !== null ? ` (TTL ${net.dnsTtlSec}s)` : ''}`
        : 'Resolving / Not disclosed'
    );
    if (net?.ipv6List?.length) {
      addRow('Public IPv6 (AAAA)', net.ipv6List.join(', '));
    }
    addRow(
      'DNS CNAME Chain',
      net?.cnameChain?.length ? net.cnameChain.join(' → ') : 'Direct A-Record (No CNAME alias)'
    );
    addRow(
      'Reverse DNS (PTR)',
      net?.reversePtr?.length ? net.reversePtr.join(', ') : 'No PTR record registered for IP'
    );
    addRow(
      'ASN & Hosting / ISP',
      net?.asn || net?.ispOrg ? `${net.asn || ''} ${net.ispOrg || ''}`.trim() : 'Lookup pending / private network'
    );
    addRow(
      'Server Geolocation',
      [net?.city, net?.region, net?.country].filter(Boolean).join(', ') || 'Not available'
    );
    if (net?.timezone || net?.coordinates) {
      addRow('Timezone & Coords', [net?.timezone, net?.coordinates ? `[${net.coordinates}]` : null].filter(Boolean).join(' • '));
    }
    if (sh?.edgePopLocation || sh?.cfRay) {
      addRow(
        'Edge Datacenter POP',
        [sh.edgePopLocation, sh.cfRay ? `(CF-Ray: ${sh.cfRay})` : null].filter(Boolean).join(' ')
      );
    }
    addRow('Host OS Fingerprint', sh?.detectedOs || 'Not disclosed');
    addRow(
      'Web Server & Runtime',
      [sh?.webServer, sh?.poweredBy ? `Powered-By: ${sh.poweredBy}` : null, sh?.via ? `Via: ${sh.via}` : null]
        .filter(Boolean)
        .join(' • ')
    );
    addRow(
      'Gateway / Middleware',
      sh?.proxyIndicators?.length ? `${gw?.gatewayLabel} [${sh.proxyIndicators.join(', ')}]` : gw?.gatewayLabel
    );
    addRow(
      'Transport & Clock',
      `HTTP ${telemetry.httpStatus || 'ERR'} • ${telemetry.corsStatus}${
        sh?.supportsHttp3 ? ' • HTTP/3 (QUIC)' : ''
      }${sh?.hasHsts ? ' • HSTS' : ''} • Clock: ${sh?.clockSkewSummary || 'n/a'}`
    );

    if (net?.tls) {
      const t = net.tls;
      addRow(
        'TLS Protocol & Cipher',
        [t.protocol, t.cipherName].filter(Boolean).join(' / ') || 'TLS Active'
      );
      addRow(
        'SSL Cert Issuer',
        [t.issuerOrg, t.issuerCN, t.issuerCountry ? `(${t.issuerCountry})` : null].filter(Boolean).join(' ')
      );
      addRow(
        'SSL Cert Validity',
        t.validFrom && t.validTo ? `${t.validFrom} → ${t.validTo}` : null
      );
      if (t.altNames?.length) {
        addRow('SSL Cert SANs (Domains)', t.altNames.join(', '));
      }
      if (t.fingerprint256) {
        addRow('SSL SHA-256 Fingerprint', t.fingerprint256);
      }
    }

    addRow(
      'Model & Registry',
      `Requested: ${telemetry.requestedModel} → Actual: ${telemetry.actualReturnedModel || 'unverified'}${
        telemetry.discoveredModels?.length ? ` (${telemetry.discoveredModels.length} models in /models)` : ''
      }`
    );

    if (telemetry.sandboxProbe?.rawOutput) {
      addRow('Raw Target Probe Reply', String(telemetry.sandboxProbe.rawOutput).trim());
    }

    const headerKeys = Object.keys(net?.exposedHeadersSnapshot || {});
    if (headerKeys.length > 0) {
      addRow(
        'Exposed HTTP Headers',
        headerKeys.map((k) => `${k}: ${net.exposedHeadersSnapshot[k]}`).join(' | ')
      );
    }

    const hostHeader = net?.hostname || gw?.host || 'target';
    const ipHeader = net?.primaryIp ? ` [${net.primaryIp}]` : '';
    els.decodedHeaderSysinfo.innerHTML = `
      <div class="sysinfo-header-line">
        <span>target@${escapeHtml(hostHeader)}${escapeHtml(ipHeader)}</span>
        <span class="pane-top-hint">${escapeHtml(telemetry.protocolName)}</span>
      </div>
      <div class="sysinfo-grid">${rows.join('')}</div>
    `;
  }

  if (els.decodedHeaderPoints) {
    const gw = telemetry.gatewayInfo;
    const headerBullets = [
      `<li><strong>Protokol &amp; Endpoint:</strong> ${escapeHtml(telemetry.protocolName)} (<code>${escapeHtml(telemetry.normalizedBaseUrl)}</code>)</li>`,
      `<li><strong>Status Server:</strong> ${telemetry.httpStatus ? `HTTP ${telemetry.httpStatus}` : 'Tidak merespons'} • ${escapeHtml(telemetry.corsStatus)}</li>`,
      `<li><strong>Identitas Gateway / Server:</strong> ${escapeHtml(gw?.gatewayLabel || 'Belum teridentifikasi')}</li>`,
      `<li><strong>Kecepatan Jaringan:</strong> ${
        telemetry.latency?.ttfbMs !== null
          ? `Respons awal ${telemetry.latency.ttfbMs} ms • Total selesai ${telemetry.latency.totalMs} ms (${telemetry.latency.tokensPerSec || 0} token/detik)`
          : 'Belum diukur'
      }</li>`,
      `<li><strong>Sisa Kuota / Rate Limit:</strong> ${escapeHtml(gw?.rateLimits?.summary || 'Tidak ditampilkan oleh server')}</li>`
    ];
    els.decodedHeaderPoints.innerHTML = headerBullets.join('');
  }

  // 2. PAYLOAD SECTION (PURPLE)
  const reqM = telemetry.requestedModel || '—';
  const actM = telemetry.actualReturnedModel || '—';
  els.kpiModelComparison.textContent = actM !== '—' ? `${reqM} → ${actM}` : reqM;

  const owner = telemetry.modelRegistryEntry?.owned_by || 'n/a';
  const fp = telemetry.systemFingerprint || 'none';
  els.kpiOwnerFingerprint.textContent = `${owner} • FP: ${fp}`;

  const ctxLen = telemetry.modelRegistryEntry?.context_length;
  const maxOut = telemetry.modelRegistryEntry?.max_completion_tokens;
  els.kpiContextSpecs.textContent = ctxLen
    ? `${Number(ctxLen).toLocaleString()} ctx${maxOut ? ` / ${Number(maxOut).toLocaleString()} out` : ''}`
    : 'Not exposed in /models';

  const caps = telemetry.capabilities;
  const activeCaps = [];
  if (caps.chat_completion) activeCaps.push('Chat');
  if (caps.sse_streaming) activeCaps.push('SSE');
  if (caps.tool_function_calling) activeCaps.push('Tools');
  if (caps.structured_json_mode) activeCaps.push('JSON');
  if (caps.reasoning_tokens) activeCaps.push('Reasoning');
  if (caps.prompt_caching) activeCaps.push('Cache');
  els.kpiCapabilities.textContent = activeCaps.length > 0 ? activeCaps.join(' • ') : '—';

  els.decodedPayloadJson.textContent = JSON.stringify(
    {
      requested_model: telemetry.requestedModel,
      actual_returned_model: telemetry.actualReturnedModel,
      system_fingerprint: telemetry.systemFingerprint,
      service_tier: telemetry.serviceTier,
      registry_metadata: telemetry.modelRegistryEntry
        ? {
            id: telemetry.modelRegistryEntry.id,
            owned_by: telemetry.modelRegistryEntry.owned_by,
            created_date: telemetry.modelRegistryEntry.created
              ? new Date(telemetry.modelRegistryEntry.created * 1000).toISOString().split('T')[0]
              : null,
            context_length: telemetry.modelRegistryEntry.context_length,
            max_completion_tokens: telemetry.modelRegistryEntry.max_completion_tokens
          }
        : 'Not found or /models hidden',
      agent_capabilities: telemetry.capabilities,
      token_usage_sample: telemetry.usageSample
    },
    null,
    2
  );

  // 3. VERIFY AUTHENTICITY SECTION (CYAN)
  if (telemetry.authenticityReport) {
    const rep = telemetry.authenticityReport;
    els.authVerdictBadge.className = `stage-badge ${rep.verdictClass}`;
    els.authVerdictBadge.textContent = rep.verdictBadgeText;
    els.authForensicsList.innerHTML = rep.findings
      .map((f) => `<li>• ${escapeHtml(f)}</li>`)
      .join('');
  }

  // 4. BOTTOM VERIFICATION BANNER (JWT.IO SIGNATURE VERIFIED STYLE)
  const passedCount = stages.filter((s) => s.status === 'passed').length;
  const failedCount = stages.filter((s) => s.status === 'failed').length;
  const runningCount = stages.filter((s) => s.status === 'running').length;

  els.verdictScoreBadge.textContent = `${passedCount} / ${stages.length} PASSED`;
  if (els.mobileNavScore) {
    els.mobileNavScore.textContent = `${passedCount}/${stages.length}`;
  }

  if (runningCount > 0) {
    els.verdictHeadline.className = 'verdict-main verdict-verified';
    els.verdictHeadline.innerHTML = '<span>Probing Agent API...</span>';
    els.verdictSubtext.textContent = 'Executing zero-cache diagnostics & metadata forensics...';
    els.verdictScoreBadge.className = 'stage-badge badge-running';
  } else if (failedCount === 0 && passedCount >= 5) {
    els.verdictHeadline.className = 'verdict-main verdict-verified';
    els.verdictHeadline.innerHTML = '<span>✓ Agent API Verified &amp; Tool-Ready</span>';
    els.verdictSubtext.textContent = `Ready for Strix & Xalgorix (${telemetry.actualReturnedModel || telemetry.requestedModel} via ${telemetry.gatewayInfo?.gatewayLabel || 'endpoint'}).`;
    els.verdictScoreBadge.className = 'stage-badge badge-passed';
  } else if (telemetry.capabilities.chat_completion && !telemetry.capabilities.tool_function_calling && stages[4].status === 'failed') {
    els.verdictHeadline.className = 'verdict-main verdict-warning';
    els.verdictHeadline.innerHTML = '<span>! Chat Works, But Agent Tool Calling Failed</span>';
    els.verdictSubtext.textContent = 'This model answered chat, but failed Stage 5 (Tool Calling) required by autonomous agents like Strix/Xalgorix.';
    els.verdictScoreBadge.className = 'stage-badge badge-warning';
  } else if (telemetry.authenticityReport?.maskingSuspected) {
    els.verdictHeadline.className = 'verdict-main verdict-failed';
    els.verdictHeadline.innerHTML = '<span>✕ Model Masking / Downgrade Detected</span>';
    els.verdictSubtext.textContent = telemetry.authenticityReport.identityCheck.summary;
    els.verdictScoreBadge.className = 'stage-badge badge-failed';
  } else if (telemetry.corsBlockedButOnline) {
    els.verdictHeadline.className = 'verdict-main verdict-warning';
    els.verdictHeadline.innerHTML = '<span>! Server Online, Direct Browser CORS Blocked</span>';
    els.verdictSubtext.textContent = 'Run "node cors-bridge.mjs" locally or paste your Cloudflare Worker URL in "+ Headers" to bypass browser CORS.';
    els.verdictScoreBadge.className = 'stage-badge badge-warning';
    els.advancedDrawer.classList.add('open');
  } else if (failedCount > 0) {
    els.verdictHeadline.className = 'verdict-main verdict-failed';
    els.verdictHeadline.innerHTML = '<span>✕ Invalid API Configuration or Endpoint Failed</span>';
    const firstFail = stages.find((s) => s.status === 'failed');
    els.verdictSubtext.textContent = firstFail ? firstFail.summary : 'One or more diagnostic stages failed.';
    els.verdictScoreBadge.className = 'stage-badge badge-failed';
  }

  refreshLivePreview();
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Queries /models on demand and populates the searchable dropdown
 */
async function handleFetchModelsClick() {
  const baseUrl = els.inputBaseUrl.value.trim();
  const apiKey = SecretVault.getApiKey();
  const adapter = resolveAdapter(currentProtocol, baseUrl, apiKey);
  const customHeaders = parseCustomHeadersInput();

  els.btnFetchModels.disabled = true;
  els.btnFetchModels.textContent = 'Fetching...';

  try {
    const res = await adapter.fetchModels({
      baseUrl,
      apiKey,
      customHeaders,
      timeoutMs: Number(els.inputTimeoutMs.value) || 20000
    });

    if (res.ok && res.models.length > 0) {
      els.modelsCountBadge.textContent = `MODELS: ${res.models.length} FOUND`;
      els.modelDropdownList.innerHTML = '';
      res.models.forEach((m) => {
        const div = document.createElement('div');
        div.className = 'model-option-item';
        div.innerHTML = `
          <span>${escapeHtml(m.id)}</span>
          <span class="pane-top-hint">${escapeHtml(m.owned_by || '')}${m.context_length ? ` • ${Math.round(m.context_length / 1024)}k` : ''}</span>
        `;
        div.addEventListener('click', () => {
          els.inputModelId.value = m.id;
          els.modelDropdownList.classList.remove('open');
          refreshLivePreview();
        });
        els.modelDropdownList.appendChild(div);
      });
      els.modelDropdownList.classList.add('open');
    } else {
      els.modelsCountBadge.textContent = `MODELS: HTTP ${res.status}`;
      els.modelDropdownList.classList.remove('open');
    }
  } catch {
    els.modelsCountBadge.textContent = 'MODELS: FETCH FAILED';
    els.modelDropdownList.classList.remove('open');
  } finally {
    els.btnFetchModels.disabled = false;
    els.btnFetchModels.textContent = 'Fetch /models';
  }
}

/**
 * Triggers the 7-Stage Diagnostic Suite
 */
async function executeSuite(quickOnly = false) {
  const baseUrl = els.inputBaseUrl.value.trim();
  const model = els.inputModelId.value.trim();
  const apiKey = SecretVault.getApiKey();
  const customHeaders = parseCustomHeadersInput();
  const timeoutMs = Number(els.inputTimeoutMs.value) || 25000;

  els.btnRunFullSuite.disabled = true;
  els.btnQuickPing.disabled = true;

  // On mobile/tablet, if currently in single-pane 'config' view, auto-switch to 'results' or scroll smoothly to results
  if (window.innerWidth <= 1024 && els.debuggerGrid) {
    const activeView = els.debuggerGrid.getAttribute('data-mobile-view') || 'all';
    if (activeView === 'config') {
      setMobileView('results');
    } else if (els.paneResults) {
      setTimeout(() => {
        els.paneResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    }
  }

  try {
    await runDiagnosticSuite({
      protocol: currentProtocol,
      baseUrl,
      model,
      apiKey,
      customHeaders,
      timeoutMs,
      quickOnly,
      onStateUpdate: ({ stages, telemetry }) => {
        renderDecodedTelemetry(stages, telemetry);
      }
    });
  } finally {
    els.btnRunFullSuite.disabled = false;
    els.btnQuickPing.disabled = false;
  }
}

/**
 * Initializes all event listeners and Zero-Trace security hooks
 */
function setMobileView(viewMode = 'all') {
  if (!els.debuggerGrid || !els.mobilePaneNav) return;
  els.debuggerGrid.setAttribute('data-mobile-view', viewMode);
  els.mobilePaneNav.querySelectorAll('.mobile-nav-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-mobile-view') === viewMode);
  });
}

function initApp() {
  if (els.mobilePaneNav) {
    els.mobilePaneNav.querySelectorAll('.mobile-nav-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        setMobileView(btn.getAttribute('data-mobile-view') || 'all');
      });
    });
  }
  // Harden all inputs against Browser Autofill, History Cache, and Password Managers
  hardenInputElements([
    els.inputBaseUrl,
    els.inputModelId,
    els.inputApiKey,
    els.inputCustomHeaders,
    els.ephemeralImportTextarea
  ]);

  // Initialize Security Lifecycle & Idle Auto-Wipe Countdown
  initSecurityLifecycle({
    onTick: ({ formatted, activeSecret }) => {
      els.idleTimerDisplay.textContent = activeSecret ? formatted : `${formatted} (IDLE)`;
    }
  });

  els.idleTimeoutSelect.addEventListener('change', (e) => {
    setIdleTimeoutMinutes(e.target.value);
  });

  // Register RAM Purge callback to reset UI state cleanly
  onRamPurge((reason) => {
    els.inputBaseUrl.value = 'https://api.openai.com/v1';
    els.inputModelId.value = 'gpt-4o-mini';
    lastTelemetry = null;
    currentStages = INITIAL_STAGES.map((s) => ({ ...s }));
    renderStagesList(currentStages);
    els.modelDropdownList.innerHTML = '';
    els.modelDropdownList.classList.remove('open');
    els.modelsCountBadge.textContent = 'MODELS: NOT FETCHED';
    els.verdictHeadline.className = 'verdict-main verdict-idle';
    els.verdictHeadline.innerHTML =
      reason === 'idle_timeout'
        ? '<span>Auto-Wiped RAM (Idle Timeout)</span>'
        : '<span>RAM &amp; DOM Purged Clean</span>';
    els.verdictSubtext.textContent = 'All ephemeral secrets and diagnostic logs have been overwritten and cleared from memory.';
    els.verdictScoreBadge.className = 'stage-badge badge-pending';
    els.verdictScoreBadge.textContent = '0 / 7';
    if (els.mobileNavScore) {
      els.mobileNavScore.textContent = '0/7';
    }
    els.authVerdictBadge.className = 'stage-badge badge-pending';
    els.authVerdictBadge.textContent = 'UNVERIFIED';
    els.authForensicsList.innerHTML = '<li>Memory purged. Enter a new configuration to run forensics.</li>';
    if (els.decodedHeaderPoints) {
      els.decodedHeaderPoints.innerHTML =
        '<li><strong>Status Koneksi:</strong> Memori telah dibersihkan. Masukkan konfigurasi baru untuk memulai tes.</li>';
    }
    if (els.decodedHeaderSysinfo) {
      els.decodedHeaderSysinfo.innerHTML =
        '<div class="sysinfo-empty">Memori telah dibersihkan. Masukkan konfigurasi baru untuk mengekstrak Public IP, DNS, ASN, sertifikat TLS, dan OS Server.</div>';
    }
    refreshLivePreview();
  });

  els.btnPurgeRam.addEventListener('click', () => {
    purgeAllRamAndDom('manual_button');
  });

  // Sync API Key input immediately into volatile closure SecretVault
  els.inputApiKey.addEventListener('input', (e) => {
    SecretVault.setApiKey(e.target.value);
    refreshLivePreview();
  });

  els.inputBaseUrl.addEventListener('input', () => refreshLivePreview());
  els.inputModelId.addEventListener('input', () => refreshLivePreview());

  // Toggle visual masking on API key input
  els.btnToggleMask.addEventListener('click', () => {
    isMaskEnabled = !isMaskEnabled;
    if (isMaskEnabled) {
      els.inputApiKey.classList.add('secret-masked');
      els.btnToggleMask.textContent = 'Show';
    } else {
      els.inputApiKey.classList.remove('secret-masked');
      els.btnToggleMask.textContent = 'Hide';
    }
  });

  // Protocol Preset Pills
  els.protocolPills.querySelectorAll('.protocol-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      els.protocolPills.querySelectorAll('.protocol-pill').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentProtocol = btn.getAttribute('data-preset') || 'auto';
      const preset = PRESET_DEFAULTS[currentProtocol];
      if (preset) {
        els.inputBaseUrl.value = preset.url;
        els.inputModelId.value = preset.model;
      }
      refreshLivePreview();
    });
  });

  // Dark / Light Mode Toggle (100% RAM-Only, no localStorage)
  if (els.btnThemeToggle) {
    els.btnThemeToggle.addEventListener('click', () => {
      const htmlEl = document.documentElement;
      const currentTheme = htmlEl.getAttribute('data-theme') || 'dark';
      const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
      htmlEl.setAttribute('data-theme', nextTheme);
      if (els.themeToggleLabel) {
        els.themeToggleLabel.textContent = nextTheme === 'dark' ? 'Light' : 'Dark';
      }
    });
  }

  // Ephemeral Quick Paste Importer Drawer
  els.btnToggleImporter.addEventListener('click', () => {
    els.importerDrawer.classList.toggle('open');
  });

  const handleImportParse = () => {
    const raw = els.ephemeralImportTextarea.value;
    if (!raw.trim()) return;
    const parsed = parseEphemeralConfigInput(raw);
    // Immediately wipe textarea DOM value so raw secret never lingers in textarea!
    els.ephemeralImportTextarea.value = '';
    els.importerDrawer.classList.remove('open');

    if (!parsed) return;
    if (parsed.protocol) {
      currentProtocol = parsed.protocol;
      els.protocolPills.querySelectorAll('.protocol-pill').forEach((b) => {
        b.classList.toggle('active', b.getAttribute('data-preset') === currentProtocol);
      });
    }
    if (parsed.baseUrl) els.inputBaseUrl.value = parsed.baseUrl;
    if (parsed.model) els.inputModelId.value = parsed.model;
    if (parsed.apiKey) {
      SecretVault.setApiKey(parsed.apiKey);
      els.inputApiKey.value = parsed.apiKey;
    }
    refreshLivePreview();
  };

  els.btnParseImport.addEventListener('click', handleImportParse);
  els.ephemeralImportTextarea.addEventListener('paste', () => {
    setTimeout(handleImportParse, 60);
  });

  // Advanced Drawer & Zero-Trace CORS Bridge Controls
  els.btnToggleAdvanced.addEventListener('click', () => {
    els.advancedDrawer.classList.toggle('open');
  });

  if (els.selectBridgeMode) {
    els.selectBridgeMode.addEventListener('change', (e) => {
      CorsBridgeConfig.setMode(e.target.value);
    });
  }
  if (els.inputBridgeUrl) {
    els.inputBridgeUrl.value = CorsBridgeConfig.getUrl();
    els.inputBridgeUrl.addEventListener('input', (e) => {
      CorsBridgeConfig.setUrl(e.target.value);
    });
  }
  CorsBridgeConfig.checkBridgeHealth();

  // Fetch /models button
  els.btnFetchModels.addEventListener('click', handleFetchModelsClick);

  // Header sub-tabs (Server & IP vs Points vs JSON)
  if (els.tabBtnHeaderSysinfo && els.tabBtnHeaderPoints && els.tabBtnHeaderJson) {
    const setHeaderTab = (mode) => {
      els.tabBtnHeaderSysinfo.classList.toggle('active-magenta', mode === 'sysinfo');
      els.tabBtnHeaderPoints.classList.toggle('active-magenta', mode === 'points');
      els.tabBtnHeaderJson.classList.toggle('active-magenta', mode === 'json');
      els.decodedHeaderSysinfo.style.display = mode === 'sysinfo' ? 'block' : 'none';
      els.decodedHeaderPoints.style.display = mode === 'points' ? 'flex' : 'none';
      els.decodedHeaderJson.style.display = mode === 'json' ? 'block' : 'none';
    };

    els.tabBtnHeaderSysinfo.addEventListener('click', () => setHeaderTab('sysinfo'));
    els.tabBtnHeaderPoints.addEventListener('click', () => setHeaderTab('points'));
    els.tabBtnHeaderJson.addEventListener('click', () => setHeaderTab('json'));
  }

  // Payload sub-tabs (7-Stage Checklist vs Decoded Metadata JSON)
  els.tabBtnStages.addEventListener('click', () => {
    els.tabBtnStages.classList.add('active-purple');
    els.tabBtnPayloadJson.classList.remove('active-purple');
    els.viewStagesChecklist.style.display = 'block';
    els.viewPayloadJson.style.display = 'none';
  });

  els.tabBtnPayloadJson.addEventListener('click', () => {
    els.tabBtnPayloadJson.classList.add('active-purple');
    els.tabBtnStages.classList.remove('active-purple');
    els.viewPayloadJson.style.display = 'block';
    els.viewStagesChecklist.style.display = 'none';
  });

  // Export Format Tabs
  els.exportFormatTabs.querySelectorAll('.sub-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      els.exportFormatTabs.querySelectorAll('.sub-tab').forEach((b) => b.classList.remove('active-cyan'));
      btn.classList.add('active-cyan');
      currentExportFormat = btn.getAttribute('data-export') || 'strix';
      refreshLivePreview();
    });
  });

  // Copy Buttons (Redacted vs Real Key with 30s Auto-Clear Clipboard)
  els.btnCopyRedacted.addEventListener('click', async () => {
    await copyToClipboardSecured(els.exportConfigPreview.textContent, { autoClearSec: 0 });
    els.clipboardStatusBadge.textContent = 'COPIED (REDACTED SAFE)';
  });

  els.btnCopyRealKey.addEventListener('click', async () => {
    const apiKey = SecretVault.getApiKey();
    const baseUrl = els.inputBaseUrl.value.trim();
    const model = els.inputModelId.value.trim();
    const adapter = resolveAdapter(currentProtocol, baseUrl, apiKey);
    const paths = adapter.getPreviewPaths(baseUrl, model);

    const realSnippet = generateExportConfig({
      format: currentExportFormat,
      protocol: getEffectiveProtocol(),
      baseUrl: paths.base,
      model,
      apiKey,
      useRedacted: false,
      forensicsSummary: lastTelemetry?.authenticityReport?.verdictBadgeText || null
    });

    await copyToClipboardSecured(realSnippet, {
      autoClearSec: 30,
      onCountdown: (rem) => {
        if (rem > 0) {
          els.clipboardStatusBadge.textContent = `CLIPBOARD AUTO-WIPE IN ${rem}s`;
        } else {
          els.clipboardStatusBadge.textContent = 'CLIPBOARD PURGED CLEAN';
        }
      }
    });
  });

  // Run Suite Buttons
  els.btnRunFullSuite.addEventListener('click', () => executeSuite(false));
  els.btnQuickPing.addEventListener('click', () => executeSuite(true));

  // Initial render
  renderStagesList(currentStages);
  refreshLivePreview();
}

initApp();
