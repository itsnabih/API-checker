/**
 * providers/openai.js — OpenAI-Compatible Zero-Cache Provider Adapter
 * Supports: OpenAI, OpenRouter, DeepSeek, Groq, xAI, Together, Mistral, Ollama, vLLM, LiteLLM, Custom Gateways
 */

import { smartZeroCacheFetch } from '../security.js';

export function normalizeOpenAiBaseUrl(rawUrl) {
  let url = (rawUrl || 'https://api.openai.com/v1').trim();
  url = url.replace(/\/+$/, '');
  // Strip accidental endpoint suffixes pasted by user
  url = url.replace(/\/chat\/completions$/i, '');
  url = url.replace(/\/completions$/i, '');
  url = url.replace(/\/models$/i, '');
  url = url.replace(/\/responses$/i, '');

  // Auto-append /v1 if bare domain is given without a version path
  try {
    const parsed = new URL(url);
    if (!parsed.pathname || parsed.pathname === '/') {
      url = `${url}/v1`;
    }
  } catch {
    // Keep as-is if invalid URL so stage 1 can flag it cleanly
  }
  return url;
}

export function extractHeadersMap(headers) {
  const map = {};
  if (!headers || typeof headers.forEach !== 'function') return map;
  headers.forEach((value, key) => {
    map[key.toLowerCase()] = value;
  });
  return map;
}

export function buildOpenAiHeaders(apiKey, customHeaders = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...customHeaders
  };
  if (apiKey && apiKey.trim()) {
    headers['Authorization'] = `Bearer ${apiKey.trim()}`;
  }
  return headers;
}

async function fetchWithTimeout(url, options, timeoutMs = 25000) {
  return await smartZeroCacheFetch(url, options, timeoutMs);
}

export const OpenAiAdapter = {
  protocolName: 'OPENAI-COMPATIBLE',

  normalizeBaseUrl: normalizeOpenAiBaseUrl,

  getPreviewPaths(rawUrl) {
    const base = normalizeOpenAiBaseUrl(rawUrl);
    return {
      base,
      modelsUrl: `${base}/models`,
      chatUrl: `${base}/chat/completions`,
      authHeaderPreview: 'Authorization: Bearer ***'
    };
  },

  async fetchModels({ baseUrl, apiKey, customHeaders = {}, timeoutMs = 20000 }) {
    const base = normalizeOpenAiBaseUrl(baseUrl);
    const url = `${base}/models`;
    const reqHeaders = buildOpenAiHeaders(apiKey, customHeaders);

    const { response, ttfbMs, startTime, routedViaBridge } = await fetchWithTimeout(
      url,
      { method: 'GET', headers: reqHeaders },
      timeoutMs
    );

    const rawText = await response.text();
    const totalMs = Math.round(performance.now() - startTime);
    const headersMap = extractHeadersMap(response.headers);

    let json = null;
    try {
      json = JSON.parse(rawText);
    } catch {
      json = { raw: rawText.slice(0, 1000) };
    }

    const rawList = Array.isArray(json?.data)
      ? json.data
      : Array.isArray(json?.models)
      ? json.models
      : Array.isArray(json)
      ? json
      : [];

    const models = rawList.map((m) => ({
      id: m.id || m.name || String(m),
      owned_by: m.owned_by || m.architecture?.tokenizer || m.top_provider?.name || 'unknown',
      created: m.created || null,
      context_length: m.context_length || m.max_model_len || m.top_provider?.context_length || null,
      max_completion_tokens: m.top_provider?.max_completion_tokens || m.max_output_tokens || null,
      pricing: m.pricing || null,
      supported_parameters: m.supported_parameters || null,
      raw: m
    }));

    return {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      url,
      ttfbMs,
      totalMs,
      routedViaBridge: Boolean(routedViaBridge),
      headers: headersMap,
      models,
      rawRequest: { method: 'GET', url, headers: reqHeaders },
      rawResponse: json
    };
  },

  async sendChat({
    baseUrl,
    apiKey,
    model,
    messages,
    tools = null,
    toolChoice = null,
    responseFormat = null,
    maxTokens = 160,
    temperature = 0,
    customHeaders = {},
    timeoutMs = 25000
  }) {
    const base = normalizeOpenAiBaseUrl(baseUrl);
    const url = `${base}/chat/completions`;
    const reqHeaders = buildOpenAiHeaders(apiKey, customHeaders);

    const bodyObj = {
      model,
      messages
    };

    if (temperature !== null && temperature !== undefined) bodyObj.temperature = temperature;
    if (maxTokens) bodyObj.max_tokens = maxTokens;
    if (tools && tools.length > 0) bodyObj.tools = tools;
    if (toolChoice) bodyObj.tool_choice = toolChoice;
    if (responseFormat) bodyObj.response_format = responseFormat;

    const { response, ttfbMs, startTime, routedViaBridge } = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify(bodyObj)
      },
      timeoutMs
    );

    const rawText = await response.text();
    const totalMs = Math.round(performance.now() - startTime);
    const headersMap = extractHeadersMap(response.headers);

    let json = null;
    try {
      json = JSON.parse(rawText);
    } catch {
      json = { raw: rawText.slice(0, 1200) };
    }

    const choice = json?.choices?.[0] || {};
    const msg = choice.message || {};

    return {
      ok: response.ok && !json?.error,
      status: response.status,
      statusText: response.statusText,
      url,
      ttfbMs,
      totalMs,
      routedViaBridge: Boolean(routedViaBridge),
      headers: headersMap,
      id: json?.id || null,
      actualModel: json?.model || null,
      systemFingerprint: json?.system_fingerprint || null,
      serviceTier: json?.service_tier || null,
      providerName: json?.provider || null,
      created: json?.created || null,
      content: msg.content ?? '',
      reasoningContent: msg.reasoning_content || msg.reasoning || null,
      toolCalls: Array.isArray(msg.tool_calls)
        ? msg.tool_calls
        : msg.function_call
        ? [{ id: 'legacy_fn', type: 'function', function: msg.function_call }]
        : [],
      finishReason: choice.finish_reason || null,
      usage: json?.usage || null,
      errorMessage: json?.error?.message || json?.message || (!response.ok ? `HTTP ${response.status}` : null),
      rawRequest: { method: 'POST', url, headers: reqHeaders, body: bodyObj },
      rawResponse: json
    };
  },

  async sendStreamChat({
    baseUrl,
    apiKey,
    model,
    messages,
    maxTokens = 64,
    customHeaders = {},
    timeoutMs = 25000
  }) {
    const base = normalizeOpenAiBaseUrl(baseUrl);
    const url = `${base}/chat/completions`;
    const reqHeaders = buildOpenAiHeaders(apiKey, customHeaders);
    const bodyObj = {
      model,
      messages,
      max_tokens: maxTokens,
      temperature: 0,
      stream: true
    };

    const { response, ttfbMs, startTime } = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: reqHeaders,
        body: JSON.stringify(bodyObj)
      },
      timeoutMs
    );

    const headersMap = extractHeadersMap(response.headers);

    if (!response.ok || !response.body) {
      const errText = await response.text();
      return {
        ok: false,
        status: response.status,
        url,
        ttfbMs,
        totalMs: Math.round(performance.now() - startTime),
        headers: headersMap,
        chunkCount: 0,
        receivedDone: false,
        assembledText: '',
        actualModel: null,
        rawSampleChunks: [errText.slice(0, 600)],
        rawRequest: { method: 'POST', url, headers: reqHeaders, body: bodyObj }
      };
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    let chunkCount = 0;
    let receivedDone = false;
    let assembledText = '';
    let actualModel = null;
    let firstChunkMs = null;
    const rawSampleChunks = [];

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (firstChunkMs === null) {
        firstChunkMs = Math.round(performance.now() - startTime);
      }
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data:')) continue;
        const dataPayload = trimmed.slice(5).trim();
        if (dataPayload === '[DONE]') {
          receivedDone = true;
          continue;
        }
        try {
          const parsed = JSON.parse(dataPayload);
          chunkCount += 1;
          if (!actualModel && parsed.model) actualModel = parsed.model;
          const delta = parsed.choices?.[0]?.delta;
          if (delta?.content) assembledText += delta.content;
          if (delta?.reasoning_content) assembledText += delta.reasoning_content;
          if (rawSampleChunks.length < 4) {
            rawSampleChunks.push(parsed);
          }
        } catch {
          // ignore non-json comment keepalives
        }
      }
    }

    const totalMs = Math.round(performance.now() - startTime);
    return {
      ok: chunkCount > 0,
      status: response.status,
      url,
      ttfbMs: firstChunkMs || ttfbMs,
      totalMs,
      headers: headersMap,
      chunkCount,
      receivedDone,
      assembledText,
      actualModel,
      rawSampleChunks,
      rawRequest: { method: 'POST', url, headers: reqHeaders, body: bodyObj }
    };
  }
};
