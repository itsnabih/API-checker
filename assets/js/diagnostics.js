/**
 * diagnostics.js — 7-Stage AI Agent Readiness & Anti-Masking Forensics Runner
 */

import { redactSecrets } from './security.js';
import { OpenAiAdapter } from './providers/openai.js';
import { AnthropicAdapter } from './providers/anthropic.js';
import { GeminiAdapter } from './providers/gemini.js';
import {
  analyzeGatewayAndHeaders,
  buildAuthenticityReport,
  compareModelIdentity,
  inspectNetworkAndServer
} from './forensics.js';

export const INITIAL_STAGES = [
  {
    id: 1,
    key: 'auth_handshake',
    title: 'Endpoint, CORS & Auth Handshake',
    status: 'pending',
    latencyMs: null,
    summary: 'Verifies Base URL reachability, HTTP authentication status, CORS policy, and gateway headers.',
    details: null
  },
  {
    id: 2,
    key: 'model_discovery',
    title: 'Model Registry & Spec Lookup (/models)',
    status: 'pending',
    latencyMs: null,
    summary: 'Checks if the configured Model ID exists in the endpoint registry and extracts specs.',
    details: null
  },
  {
    id: 3,
    key: 'basic_chat',
    title: 'Basic Chat Completion & Latency Breakdown',
    status: 'pending',
    latencyMs: null,
    summary: 'Measures TTFB, total RTT, token generation speed, and token usage metadata.',
    details: null
  },
  {
    id: 4,
    key: 'sse_streaming',
    title: 'Server-Sent Events (SSE) Streaming Integrity',
    status: 'pending',
    latencyMs: null,
    summary: 'Tests stream: true chunk parsing required by real-time autonomous agents.',
    details: null
  },
  {
    id: 5,
    key: 'tool_calling',
    title: 'Agent Tool / Function Calling Validation',
    status: 'pending',
    latencyMs: null,
    summary: 'Crucial for Strix & Xalgorix: verifies the model emits structured tool_calls with valid JSON arguments.',
    details: null
  },
  {
    id: 6,
    key: 'json_mode',
    title: 'Structured JSON Output & System Prompt Adherence',
    status: 'pending',
    latencyMs: null,
    summary: 'Verifies strict adherence to system instructions and machine-parseable JSON output.',
    details: null
  },
  {
    id: 7,
    key: 'anti_masking',
    title: 'Provider Authenticity & Anti-Masking Forensics',
    status: 'pending',
    latencyMs: null,
    summary: 'Detects proxy model remapping, tier downgrades, tokenizer accounting anomalies, and identity spoofing.',
    details: null
  }
];

export function resolveAdapter(protocol, baseUrl = '', apiKey = '') {
  if (protocol === 'anthropic') return AnthropicAdapter;
  if (protocol === 'gemini') return GeminiAdapter;
  if (protocol === 'openai' || protocol === 'openrouter' || protocol === 'litellm') return OpenAiAdapter;

  // Auto-detect from URL or key prefix
  const urlLower = (baseUrl || '').toLowerCase();
  const keyTrim = (apiKey || '').trim();
  if (urlLower.includes('anthropic.com') || keyTrim.startsWith('sk-ant-')) {
    return AnthropicAdapter;
  }
  if (urlLower.includes('googleapis.com') || keyTrim.startsWith('AIzaSy')) {
    return GeminiAdapter;
  }
  return OpenAiAdapter;
}

function classifyNetworkError(err) {
  const msg = err?.message || String(err);
  if (err?.name === 'AbortError') {
    return 'Request timed out. The endpoint took too long to respond.';
  }
  if (err?.corsReachability === 'ONLINE_CORS_BLOCKED') {
    return 'Server is ONLINE, but blocks Direct Browser CORS! Run "node cors-bridge.mjs" locally or set your Cloudflare Worker URL in "+ Headers" to test from browser.';
  }
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
    return 'Endpoint Unreachable (DNS / SSL / Offline): Server did not respond even to a zero-credential no-cors ping.';
  }
  return msg;
}

/**
 * Runs the 7-Stage Diagnostic Suite (or Quick Ping Stages 1-3)
 */
export async function runDiagnosticSuite({
  protocol,
  baseUrl,
  model,
  apiKey,
  customHeaders = {},
  timeoutMs = 25000,
  quickOnly = false,
  onStateUpdate
}) {
  let adapter = resolveAdapter(protocol, baseUrl, apiKey);
  const stages = INITIAL_STAGES.map((s) => ({ ...s }));

  const telemetry = {
    protocolName: adapter.protocolName,
    normalizedBaseUrl: adapter.normalizeBaseUrl(baseUrl),
    httpStatus: null,
    corsStatus: 'UNTESTED',
    gatewayInfo: null,
    latency: { ttfbMs: null, totalMs: null, tokensPerSec: null },
    requestedModel: model,
    actualReturnedModel: null,
    systemFingerprint: null,
    serviceTier: null,
    modelRegistryEntry: null,
    discoveredModels: [],
    capabilities: {
      chat_completion: null,
      sse_streaming: null,
      tool_function_calling: null,
      structured_json_mode: null,
      reasoning_tokens: false,
      prompt_caching: false
    },
    usageSample: null,
    authenticityReport: null,
    networkForensics: null,
    sandboxProbe: null
  };

  const notify = () => {
    if (onStateUpdate) {
      onStateUpdate({
        stages: stages.map((s) => ({ ...s })),
        telemetry: { ...telemetry }
      });
    }
  };

  const updateStage = (index, patch) => {
    stages[index] = { ...stages[index], ...patch };
    notify();
  };

  // Stage 1 & 2: Endpoint Handshake & Model Registry Discovery
  updateStage(0, { status: 'running', summary: 'Connecting to endpoint and checking authentication...' });
  updateStage(1, { status: 'running', summary: 'Querying /models registry...' });

  let modelsRes = null;
  let modelsFetchError = null;
  try {
    modelsRes = await adapter.fetchModels({
      baseUrl,
      apiKey,
      customHeaders,
      timeoutMs
    });
  } catch (err) {
    modelsFetchError = err;
  }

  // Also run a lightweight Stage 3 chat probe if /models failed or returned 404 (some proxies don't expose GET /models)
  updateStage(2, { status: 'running', summary: 'Sending deterministic chat completion ping...' });
  let chatRes = null;
  let chatFetchError = null;
  let chatFallbackNote = null;
  try {
    chatRes = await adapter.sendChat({
      baseUrl,
      apiKey,
      model,
      messages: [
        { role: 'system', content: 'You are a concise diagnostic responder.' },
        { role: 'user', content: 'Reply with the single word: PONG' }
      ],
      maxTokens: 64,
      temperature: 0,
      customHeaders,
      timeoutMs
    });

    // Smart Fallback 1: Some Claude 4.x / Thinking / Custom Proxy models reject temperature=0, system role, or small max_tokens with HTTP 400/500/502
    if (chatRes && !chatRes.ok && [400, 422, 500, 502, 503].includes(chatRes.status)) {
      updateStage(2, {
        status: 'running',
        summary: `HTTP ${chatRes.status} on strict payload; retrying with minimal compatibility payload (no temperature/system role)...`
      });
      const retryMinimal = await adapter.sendChat({
        baseUrl,
        apiKey,
        model,
        messages: [{ role: 'user', content: 'Reply with the single word: PONG' }],
        maxTokens: null,
        temperature: null,
        customHeaders,
        timeoutMs
      });
      if (retryMinimal.ok) {
        chatRes = retryMinimal;
        chatFallbackNote = 'Succeeded via Minimal Payload (endpoint rejects temperature:0 or system role).';
      } else {
        chatRes = retryMinimal;
      }
    }

    // Smart Fallback 2: Some reverse proxies only support stream: true and return 502 on non-streaming chat
    if (chatRes && !chatRes.ok && [500, 502, 503].includes(chatRes.status)) {
      updateStage(2, {
        status: 'running',
        summary: `HTTP ${chatRes.status} on non-streaming chat; probing stream: true fallback...`
      });
      const streamFallback = await adapter.sendStreamChat({
        baseUrl,
        apiKey,
        model,
        messages: [{ role: 'user', content: 'Reply with the single word: PONG' }],
        maxTokens: 64,
        customHeaders,
        timeoutMs
      });
      if (streamFallback.ok && streamFallback.chunkCount > 0) {
        chatRes = {
          ok: true,
          status: streamFallback.status,
          url: streamFallback.url,
          ttfbMs: streamFallback.ttfbMs,
          totalMs: streamFallback.totalMs,
          routedViaBridge: streamFallback.routedViaBridge,
          headers: streamFallback.headers,
          actualModel: streamFallback.actualModel || model,
          content: streamFallback.assembledText,
          usage: { prompt_tokens: 12, completion_tokens: streamFallback.chunkCount, total_tokens: 12 + streamFallback.chunkCount },
          rawRequest: streamFallback.rawRequest,
          rawResponse: { streaming_fallback_chunks: streamFallback.rawSampleChunks }
        };
        chatFallbackNote = 'Succeeded via Streaming-Only Fallback (proxy requires stream: true).';
      }
    }

    // Smart Fallback 3: If model is a Claude model on an OpenAI proxy that returned 404/500/502, probe Anthropic Native /v1/messages
    if (
      chatRes &&
      !chatRes.ok &&
      [400, 404, 500, 502, 503].includes(chatRes.status) &&
      adapter.protocolName === 'OPENAI-COMPATIBLE' &&
      String(model).toLowerCase().includes('claude')
    ) {
      updateStage(2, {
        status: 'running',
        summary: `HTTP ${chatRes.status} on /chat/completions for Claude model; probing Anthropic Native /v1/messages...`
      });
      const anthHeaders = {
        ...customHeaders,
        Authorization: `Bearer ${(apiKey || '').trim()}`
      };
      const anthTry = await AnthropicAdapter.sendChat({
        baseUrl,
        apiKey,
        model,
        messages: [{ role: 'user', content: 'Reply with the single word: PONG' }],
        maxTokens: 64,
        temperature: 1,
        customHeaders: anthHeaders,
        timeoutMs
      });
      if (anthTry.ok) {
        adapter = AnthropicAdapter;
        telemetry.protocolName = AnthropicAdapter.protocolName;
        chatRes = anthTry;
        chatFallbackNote = 'Succeeded via Anthropic Native (/v1/messages) protocol.';
      }
    }
  } catch (err) {
    chatFetchError = err;
  }

  // Evaluate Stage 1 (Auth & Endpoint Handshake)
  const primaryRes = chatRes || modelsRes;
  if (!primaryRes) {
    const rawErr = chatFetchError || modelsFetchError;
    const errMsg = classifyNetworkError(rawErr);
    const isCorsOnlyBlock = rawErr?.corsReachability === 'ONLINE_CORS_BLOCKED';
    telemetry.corsStatus = isCorsOnlyBlock ? 'SERVER ONLINE (BROWSER CORS BLOCKED)' : 'OFFLINE / UNREACHABLE';
    telemetry.corsBlockedButOnline = isCorsOnlyBlock;
    telemetry.networkForensics = await inspectNetworkAndServer({
      baseUrl: adapter.normalizeBaseUrl(baseUrl),
      headers: {}
    });

    updateStage(0, {
      status: isCorsOnlyBlock ? 'warning' : 'failed',
      summary: errMsg,
      details: {
        error: errMsg,
        reachabilityProbe: rawErr?.corsReachability || 'UNKNOWN',
        networkForensics: telemetry.networkForensics,
        howToFix: isCorsOnlyBlock
          ? [
              '1. This endpoint is ONLINE and will work in CLI agents, which do not enforce browser CORS.',
              '2. To test all 7 stages here in the browser, run: node cors-bridge.mjs',
              '3. Or deploy cloudflare-worker.js to your free Cloudflare Worker and paste its URL into "+ Headers".'
            ]
          : ['Verify the Base URL hostname, port, and HTTPS certificate.']
      }
    });
    updateStage(1, { status: 'pending', summary: 'Waiting for CORS Bridge connection to query /models.' });
    updateStage(2, { status: 'pending', summary: 'Waiting for CORS Bridge connection to run chat probe.' });
    return { stages, telemetry };
  }

  telemetry.corsStatus = primaryRes.routedViaBridge ? 'ZERO-TRACE BRIDGE ACTIVE' : 'DIRECT BROWSER CORS OK';
  telemetry.httpStatus = primaryRes.status;
  telemetry.gatewayInfo = analyzeGatewayAndHeaders({
    baseUrl: adapter.normalizeBaseUrl(baseUrl),
    headers: primaryRes.headers,
    responseId: chatRes?.id,
    systemFingerprint: chatRes?.systemFingerprint,
    providerField: chatRes?.providerName
  });

  // Resolve Public IP, DNS CNAME/PTR chain, ASN/ISP, Geolocation & TLS Certificate in parallel
  telemetry.networkForensics = await inspectNetworkAndServer({
    baseUrl: adapter.normalizeBaseUrl(baseUrl),
    headers: primaryRes.headers
  });

  if (primaryRes.status === 401 || primaryRes.status === 403) {
    updateStage(0, {
      status: 'failed',
      latencyMs: primaryRes.ttfbMs,
      summary: `Authentication Failed (HTTP ${primaryRes.status}): ${chatRes?.errorMessage || 'Invalid or unauthorized API Key.'}`,
      details: redactSecrets({
        request: primaryRes.rawRequest,
        response: primaryRes.rawResponse,
        responseHeaders: primaryRes.headers
      })
    });
  } else if (primaryRes.status === 429) {
    updateStage(0, {
      status: 'warning',
      latencyMs: primaryRes.ttfbMs,
      summary: `Rate Limited / Quota Exceeded (HTTP 429): ${chatRes?.errorMessage || 'Check billing or RPM limits.'}`,
      details: redactSecrets({
        request: primaryRes.rawRequest,
        response: primaryRes.rawResponse,
        responseHeaders: primaryRes.headers
      })
    });
  } else if (primaryRes.ok || modelsRes?.ok) {
    updateStage(0, {
      status: 'passed',
      latencyMs: primaryRes.ttfbMs,
      summary: `Authenticated (HTTP ${primaryRes.status}) via ${telemetry.gatewayInfo.gatewayLabel}`,
      details: redactSecrets({
        endpoint: primaryRes.url,
        gateway: telemetry.gatewayInfo,
        responseHeaders: primaryRes.headers
      })
    });
  } else {
    updateStage(0, {
      status: 'failed',
      latencyMs: primaryRes.ttfbMs,
      summary: `Endpoint Error (HTTP ${primaryRes.status}): ${chatRes?.errorMessage || primaryRes.statusText}`,
      details: redactSecrets({
        request: primaryRes.rawRequest,
        response: primaryRes.rawResponse
      })
    });
  }

  // Evaluate Stage 2 (/models Registry Lookup)
  if (modelsRes && modelsRes.ok && modelsRes.models.length > 0) {
    telemetry.discoveredModels = modelsRes.models;
    const cleanTarget = model.trim().toLowerCase().replace(/^(openai|anthropic|google|models)\//, '');
    const found = modelsRes.models.find((m) => {
      const idLow = String(m.id).toLowerCase();
      return idLow === cleanTarget || idLow === model.trim().toLowerCase() || idLow.endsWith(`/${cleanTarget}`);
    });

    if (found) {
      telemetry.modelRegistryEntry = found;
      updateStage(1, {
        status: 'passed',
        latencyMs: modelsRes.totalMs,
        summary: `Verified "${found.id}" in registry (${modelsRes.models.length} total models • owner: ${found.owned_by || 'n/a'})`,
        details: redactSecrets({
          matchedModelSpec: found,
          totalModelsAvailable: modelsRes.models.length
        })
      });
    } else {
      updateStage(1, {
        status: 'warning',
        latencyMs: modelsRes.totalMs,
        summary: `Model "${model}" not listed in /models (${modelsRes.models.length} models returned), testing direct invocation...`,
        details: redactSecrets({
          requestedModel: model,
          sampleAvailableModels: modelsRes.models.slice(0, 20).map((m) => m.id)
        })
      });
    }
  } else {
    updateStage(1, {
      status: chatRes?.ok ? 'warning' : 'failed',
      latencyMs: modelsRes?.totalMs || null,
      summary: modelsRes
        ? `/models endpoint returned HTTP ${modelsRes.status} (some gateways hide model listing).`
        : 'Could not query /models endpoint.',
      details: redactSecrets({
        request: modelsRes?.rawRequest,
        response: modelsRes?.rawResponse
      })
    });
  }

  // Evaluate Stage 3 (Basic Chat & Latency)
  if (chatRes && chatRes.ok) {
    telemetry.actualReturnedModel = chatRes.actualModel || model;
    telemetry.systemFingerprint = chatRes.systemFingerprint;
    telemetry.serviceTier = chatRes.serviceTier;
    telemetry.usageSample = chatRes.usage;
    telemetry.capabilities.chat_completion = true;

    if (chatRes.reasoningContent || chatRes.usage?.completion_tokens_details?.reasoning_tokens > 0) {
      telemetry.capabilities.reasoning_tokens = true;
    }
    if (
      chatRes.usage?.prompt_tokens_details?.cached_tokens > 0 ||
      chatRes.usage?.prompt_cache_hit_tokens > 0 ||
      chatRes.usage?.cache_read_input_tokens > 0
    ) {
      telemetry.capabilities.prompt_caching = true;
    }

    const outTokens = chatRes.usage?.completion_tokens || 1;
    const genTimeSec = Math.max(0.05, (chatRes.totalMs - chatRes.ttfbMs) / 1000);
    const tokPerSec = Math.round((outTokens / genTimeSec) * 10) / 10;

    telemetry.latency = {
      ttfbMs: chatRes.ttfbMs,
      totalMs: chatRes.totalMs,
      tokensPerSec: tokPerSec
    };

    updateStage(2, {
      status: 'passed',
      latencyMs: chatRes.totalMs,
      summary: `TTFB: ${chatRes.ttfbMs}ms • Total: ${chatRes.totalMs}ms • Model: "${telemetry.actualReturnedModel}" • Reply: "${String(chatRes.content).trim().slice(0, 40)}"${chatFallbackNote ? ` (${chatFallbackNote})` : ''}`,
      details: redactSecrets({
        compatibilityNote: chatFallbackNote,
        request: chatRes.rawRequest,
        response: chatRes.rawResponse
      })
    });
  } else {
    telemetry.capabilities.chat_completion = false;
    const isUpstream502 = chatRes && [500, 502, 503, 504].includes(chatRes.status) && modelsRes?.ok;
    updateStage(2, {
      status: 'failed',
      latencyMs: chatRes?.totalMs || null,
      summary: isUpstream502
        ? `Upstream Proxy Error (HTTP ${chatRes.status}): "${chatRes?.errorMessage}" — API Key & Server valid, but the proxy failed to reach upstream model "${model}".`
        : `Chat Completion Failed: ${chatRes?.errorMessage || classifyNetworkError(chatFetchError)}`,
      details: redactSecrets({
        diagnosis: isUpstream502
          ? `Server proxy (${telemetry.gatewayInfo?.host}) aktif dan API Key Anda VALID (terbukti /models berhasil), tetapi proxy gagal memproses model "${model}" (HTTP ${chatRes.status}: ${chatRes?.errorMessage}). Biasanya ini terjadi karena gangguan upstream di sisi penyedia proxy, nama model sedang maintenance, atau proxy mewajibkan mode Streaming.`
          : null,
        request: chatRes?.rawRequest,
        response: chatRes?.rawResponse
      })
    });

    // If Stage 3 failed with 502 on non-streaming chat, still test Stage 4 (SSE Streaming) because some proxies only allow stream: true!
    if (!isUpstream502) {
      return { stages, telemetry };
    }
  }

  if (quickOnly) {
    for (let i = 3; i < 7; i++) {
      updateStage(i, { status: 'pending', summary: 'Skipped in Quick Ping mode (Click Run 7-Stage Suite for full agent test).' });
    }
    return { stages, telemetry };
  }

  // Stage 4: Streaming (SSE) Integrity Test
  updateStage(3, { status: 'running', summary: 'Testing stream: true Server-Sent Events (SSE) chunks...' });
  try {
    const streamRes = await adapter.sendStreamChat({
      baseUrl,
      apiKey,
      model,
      messages: [{ role: 'user', content: 'Count 1, 2, 3.' }],
      maxTokens: 40,
      customHeaders,
      timeoutMs
    });

    if (streamRes.ok && streamRes.chunkCount > 0) {
      telemetry.capabilities.sse_streaming = true;
      updateStage(3, {
        status: 'passed',
        latencyMs: streamRes.totalMs,
        summary: `SSE Stream Verified (${streamRes.chunkCount} chunks • First chunk: ${streamRes.ttfbMs}ms • Output: "${streamRes.assembledText.trim().slice(0, 45)}")`,
        details: redactSecrets({
          chunkCount: streamRes.chunkCount,
          receivedDoneMarker: streamRes.receivedDone,
          firstChunkMs: streamRes.ttfbMs,
          totalStreamMs: streamRes.totalMs,
          sampleChunks: streamRes.rawSampleChunks
        })
      });
    } else {
      telemetry.capabilities.sse_streaming = false;
      updateStage(3, {
        status: 'failed',
        latencyMs: streamRes.totalMs,
        summary: `Streaming failed or returned 0 SSE data chunks (HTTP ${streamRes.status}).`,
        details: redactSecrets({
          request: streamRes.rawRequest,
          sampleChunks: streamRes.rawSampleChunks
        })
      });
      if (!telemetry.capabilities.chat_completion) {
        return { stages, telemetry };
      }
    }
  } catch (err) {
    telemetry.capabilities.sse_streaming = false;
    updateStage(3, {
      status: 'failed',
      summary: `SSE Stream Error: ${classifyNetworkError(err)}`
    });
    if (!telemetry.capabilities.chat_completion) {
      return { stages, telemetry };
    }
  }

  // Stage 5: Agent Tool / Function Calling Test
  updateStage(4, { status: 'running', summary: 'Testing agent tool_calls execution (check_target_port)...' });
  const dummyTools = [
    {
      type: 'function',
      function: {
        name: 'check_target_port',
        description: 'Checks if a specific TCP port is open on a target host during an agent task.',
        parameters: {
          type: 'object',
          properties: {
            host: { type: 'string', description: 'Target hostname or IP' },
            port: { type: 'integer', description: 'TCP port number' }
          },
          required: ['host', 'port']
        }
      }
    }
  ];

  try {
    const toolRes = await adapter.sendChat({
      baseUrl,
      apiKey,
      model,
      messages: [
        { role: 'system', content: 'You are an autonomous agent. Always call the provided tool when asked to check a host and port.' },
        { role: 'user', content: 'Use the check_target_port tool to check host "10.0.0.1" on port 443.' }
      ],
      tools: dummyTools,
      toolChoice: 'auto',
      maxTokens: 160,
      temperature: 0,
      customHeaders,
      timeoutMs
    });

    if (toolRes.ok && Array.isArray(toolRes.toolCalls) && toolRes.toolCalls.length > 0) {
      const tc = toolRes.toolCalls[0];
      const fnName = tc.function?.name || '';
      let parsedArgs = null;
      try {
        parsedArgs = JSON.parse(tc.function?.arguments || '{}');
      } catch {
        parsedArgs = null;
      }

      if (fnName === 'check_target_port' && parsedArgs && parsedArgs.host) {
        telemetry.capabilities.tool_function_calling = true;
        updateStage(4, {
          status: 'passed',
          latencyMs: toolRes.totalMs,
          summary: `Tool Calling Verified! Invoked "${fnName}" with args: ${JSON.stringify(parsedArgs)}`,
          details: redactSecrets({
            toolCallsEmitted: toolRes.toolCalls,
            request: toolRes.rawRequest,
            response: toolRes.rawResponse
          })
        });
      } else {
        telemetry.capabilities.tool_function_calling = false;
        updateStage(4, {
          status: 'warning',
          latencyMs: toolRes.totalMs,
          summary: `Tool call emitted ("${fnName}"), but JSON arguments were incomplete or malformed.`,
          details: redactSecrets({
            toolCallsEmitted: toolRes.toolCalls,
            response: toolRes.rawResponse
          })
        });
      }
    } else {
      telemetry.capabilities.tool_function_calling = false;
      updateStage(4, {
        status: 'failed',
        latencyMs: toolRes.totalMs,
        summary: `Model did NOT emit tool_calls (Strix & Xalgorix require tool calling!). Returned plain text instead.`,
        details: redactSecrets({
          plainTextContent: toolRes.content,
          errorMessage: toolRes.errorMessage,
          request: toolRes.rawRequest,
          response: toolRes.rawResponse
        })
      });
    }
  } catch (err) {
    telemetry.capabilities.tool_function_calling = false;
    updateStage(4, {
      status: 'failed',
      summary: `Tool Calling Error: ${classifyNetworkError(err)}`
    });
  }

  // Stage 6: Structured JSON & System Prompt Adherence
  updateStage(5, { status: 'running', summary: 'Testing structured JSON output mode and system prompt adherence...' });
  try {
    const jsonRes = await adapter.sendChat({
      baseUrl,
      apiKey,
      model,
      messages: [
        {
          role: 'system',
          content: 'You must output strictly valid JSON with keys: {"agent_ready": true, "engine": "verified"}. No markdown fences.'
        },
        {
          role: 'user',
          content: 'Generate the verification JSON object now.'
        }
      ],
      responseFormat: { type: 'json_object' },
      maxTokens: 120,
      temperature: 0,
      customHeaders,
      timeoutMs
    });

    // Fallback without response_format if endpoint rejects response_format parameter
    let effectiveRes = jsonRes;
    if (!jsonRes.ok && jsonRes.status === 400) {
      effectiveRes = await adapter.sendChat({
        baseUrl,
        apiKey,
        model,
        messages: [
          {
            role: 'system',
            content: 'Output ONLY a raw JSON object: {"agent_ready": true, "engine": "verified"}. Do not wrap in markdown.'
          },
          { role: 'user', content: 'Return the JSON object.' }
        ],
        maxTokens: 120,
        temperature: 0,
        customHeaders,
        timeoutMs
      });
    }

    const cleanedContent = String(effectiveRes.content || '')
      .trim()
      .replace(/^```json\s*/i, '')
      .replace(/```$/i, '')
      .trim();

    let parsedJson = null;
    try {
      parsedJson = JSON.parse(cleanedContent);
    } catch {
      parsedJson = null;
    }

    if (effectiveRes.ok && parsedJson && parsedJson.agent_ready === true) {
      telemetry.capabilities.structured_json_mode = true;
      updateStage(5, {
        status: 'passed',
        latencyMs: effectiveRes.totalMs,
        summary: `Valid Structured JSON verified: ${JSON.stringify(parsedJson)}`,
        details: redactSecrets({
          parsedJson,
          request: effectiveRes.rawRequest,
          response: effectiveRes.rawResponse
        })
      });
    } else {
      telemetry.capabilities.structured_json_mode = false;
      updateStage(5, {
        status: parsedJson ? 'warning' : 'failed',
        latencyMs: effectiveRes.totalMs,
        summary: parsedJson
          ? `JSON parsed but schema keys differed from system prompt: ${JSON.stringify(parsedJson)}`
          : `Failed to produce parseable JSON output.`,
        details: redactSecrets({
          rawContent: effectiveRes.content,
          response: effectiveRes.rawResponse
        })
      });
    }
  } catch (err) {
    telemetry.capabilities.structured_json_mode = false;
    updateStage(5, {
      status: 'failed',
      summary: `Structured JSON Test Error: ${classifyNetworkError(err)}`
    });
  }

  // Stage 7: Provider Authenticity & Anti-Masking Forensics Probe
  updateStage(6, { status: 'running', summary: 'Running tokenizer accounting & model identity anti-masking forensics...' });
  try {
    const probeRes = await adapter.sendChat({
      baseUrl,
      apiKey,
      model,
      messages: [
        {
          role: 'system',
          content:
            'Respond ONLY with a valid JSON object containing: {"model_family": "<your base model architecture e.g. GPT / Claude / Gemini / DeepSeek / Qwen / Llama>", "creator": "<organization that trained you>", "knowledge_cutoff": "<YYYY-MM>", "probe_token": "VERIFY_7"}.'
        },
        {
          role: 'user',
          content: 'Identify your model architecture family, creator organization, and knowledge cutoff in JSON. Tokenizer calibration symbols: [αβγ-漢字-🚀-42]'
        }
      ],
      maxTokens: 160,
      temperature: 0,
      customHeaders,
      timeoutMs
    });

    let parsedProbe = null;
    const rawClean = String(probeRes.content || '')
      .trim()
      .replace(/^```json\s*/i, '')
      .replace(/```$/i, '')
      .trim();
    try {
      parsedProbe = JSON.parse(rawClean);
    } catch {
      // Try extracting JSON substring
      const match = rawClean.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          parsedProbe = JSON.parse(match[0]);
        } catch {
          parsedProbe = null;
        }
      }
    }

    if (probeRes.actualModel) {
      telemetry.actualReturnedModel = probeRes.actualModel;
    }
    if (probeRes.usage) {
      telemetry.usageSample = probeRes.usage;
    }

    const report = buildAuthenticityReport({
      requestedModel: model,
      actualModel: telemetry.actualReturnedModel,
      gatewayInfo: telemetry.gatewayInfo,
      modelRegistryEntry: telemetry.modelRegistryEntry,
      chatUsage: probeRes.usage || telemetry.usageSample,
      probeResult: {
        parsedProbe,
        rawContent: probeRes.content
      }
    });

    telemetry.authenticityReport = report;
    telemetry.sandboxProbe = {
      parsed: parsedProbe,
      rawOutput: probeRes.content,
      reasoningOutput: probeRes.reasoningContent || null
    };

    updateStage(6, {
      status: report.maskingSuspected ? 'failed' : report.verdictClass === 'badge-warning' ? 'warning' : 'passed',
      latencyMs: probeRes.totalMs,
      summary: `${report.verdictBadgeText} — ${report.identityCheck.summary}`,
      details: redactSecrets({
        authenticityVerdict: report.verdictCode,
        confidenceScore: report.confidenceScore,
        forensicFindings: report.findings,
        behavioralProbeResponse: parsedProbe || probeRes.content,
        probeUsageMetadata: probeRes.usage
      })
    });
  } catch (err) {
    const fallbackIdentity = compareModelIdentity(model, telemetry.actualReturnedModel);
    updateStage(6, {
      status: fallbackIdentity.suspicious ? 'warning' : 'passed',
      summary: `${fallbackIdentity.summary} (Probe error: ${classifyNetworkError(err)})`
    });
  }

  return { stages, telemetry };
}
