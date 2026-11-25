/**
 * providers/gemini.js — Google Gemini Native (v1beta) Zero-Cache Provider Adapter
 * Enforces Header-Only Authentication via 'x-goog-api-key' (NEVER leaks key in URL query string!)
 */

import { smartZeroCacheFetch } from '../security.js';
import { extractHeadersMap } from './openai.js';

export function normalizeGeminiBaseUrl(rawUrl) {
  let url = (rawUrl || 'https://generativelanguage.googleapis.com/v1beta').trim();
  url = url.replace(/\/+$/, '');
  url = url.replace(/\/models$/i, '');

  try {
    const parsed = new URL(url);
    if (!parsed.pathname || parsed.pathname === '/') {
      url = `${url}/v1beta`;
    }
  } catch {
    // ignore
  }
  return url;
}

export function cleanGeminiModelId(modelId) {
  return (modelId || 'gemini-2.5-flash').trim().replace(/^models\//i, '');
}

export function buildGeminiHeaders(apiKey, customHeaders = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...customHeaders
  };
  if (apiKey && apiKey.trim()) {
    headers['x-goog-api-key'] = apiKey.trim();
  }
  return headers;
}

async function fetchWithTimeout(url, options, timeoutMs = 25000) {
  return await smartZeroCacheFetch(url, options, timeoutMs);
}

export const GeminiAdapter = {
  protocolName: 'GOOGLE-GEMINI-NATIVE',

  normalizeBaseUrl: normalizeGeminiBaseUrl,

  getPreviewPaths(rawUrl, modelId = 'gemini-2.5-flash') {
    const base = normalizeGeminiBaseUrl(rawUrl);
    const cleanModel = cleanGeminiModelId(modelId);
    return {
      base,
      modelsUrl: `${base}/models`,
      chatUrl: `${base}/models/${cleanModel}:generateContent`,
      authHeaderPreview: 'x-goog-api-key: *** (Zero URL Query Leak)'
    };
  },

  async fetchModels({ baseUrl, apiKey, customHeaders = {}, timeoutMs = 20000 }) {
    const base = normalizeGeminiBaseUrl(baseUrl);
    const url = `${base}/models`;
    const reqHeaders = buildGeminiHeaders(apiKey, customHeaders);

    const { response, ttfbMs, startTime } = await fetchWithTimeout(
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

    const rawList = Array.isArray(json?.models) ? json.models : [];
    const models = rawList.map((m) => ({
      id: cleanGeminiModelId(m.name),
      owned_by: 'google',
      display_name: m.displayName || cleanGeminiModelId(m.name),
      version: m.version || null,
      context_length: m.inputTokenLimit || null,
      max_completion_tokens: m.outputTokenLimit || null,
      supported_parameters: m.supportedGenerationMethods || [],
      raw: m
    }));

    return {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      url,
      ttfbMs,
      totalMs,
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
    responseFormat = null,
    maxTokens = 200,
    temperature = 0,
    customHeaders = {},
    timeoutMs = 25000
  }) {
    const base = normalizeGeminiBaseUrl(baseUrl);
    const cleanModel = cleanGeminiModelId(model);
    const url = `${base}/models/${cleanModel}:generateContent`;
    const reqHeaders = buildGeminiHeaders(apiKey, customHeaders);

    let systemText = '';
    const contents = [];

    for (const m of messages) {
      if (m.role === 'system') {
        systemText += (systemText ? '\n' : '') + m.content;
      } else {
        contents.push({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: m.content }]
        });
      }
    }

    const bodyObj = {
      contents: contents.length > 0 ? contents : [{ role: 'user', parts: [{ text: 'Hello' }] }],
      generationConfig: {
        temperature,
        maxOutputTokens: maxTokens || 200
      }
    };

    if (systemText) {
      bodyObj.systemInstruction = {
        parts: [{ text: systemText }]
      };
    }

    if (responseFormat?.type === 'json_object') {
      bodyObj.generationConfig.responseMimeType = 'application/json';
    }

    if (tools && tools.length > 0) {
      bodyObj.tools = [
        {
          functionDeclarations: tools.map((t) => {
            const fn = t.function || t;
            return {
              name: fn.name,
              description: fn.description || '',
              parameters: fn.parameters || { type: 'OBJECT', properties: {} }
            };
          })
        }
      ];
    }

    const { response, ttfbMs, startTime } = await fetchWithTimeout(
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

    const candidate = json?.candidates?.[0] || {};
    const parts = candidate.content?.parts || [];
    const textParts = [];
    const toolCalls = [];

    for (const part of parts) {
      if (typeof part.text === 'string') {
        textParts.push(part.text);
      }
      if (part.functionCall) {
        toolCalls.push({
          id: `gemini_call_${toolCalls.length + 1}`,
          type: 'function',
          function: {
            name: part.functionCall.name,
            arguments: JSON.stringify(part.functionCall.args || {})
          }
        });
      }
    }

    const usageMeta = json?.usageMetadata;
    const usage = usageMeta
      ? {
          prompt_tokens: usageMeta.promptTokenCount || 0,
          completion_tokens: usageMeta.candidatesTokenCount || 0,
          total_tokens: usageMeta.totalTokenCount || 0,
          reasoning_tokens: usageMeta.thoughtsTokenCount || 0
        }
      : null;

    return {
      ok: response.ok && !json?.error,
      status: response.status,
      statusText: response.statusText,
      url,
      ttfbMs,
      totalMs,
      headers: headersMap,
      id: json?.responseId || null,
      actualModel: json?.modelVersion || cleanModel,
      systemFingerprint: json?.modelVersion || null,
      serviceTier: null,
      providerName: 'Google Gemini',
      created: null,
      content: textParts.join('\n'),
      reasoningContent: null,
      toolCalls,
      finishReason: candidate.finishReason || null,
      usage,
      errorMessage: json?.error?.message || (!response.ok ? `HTTP ${response.status}` : null),
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
    const base = normalizeGeminiBaseUrl(baseUrl);
    const cleanModel = cleanGeminiModelId(model);
    const url = `${base}/models/${cleanModel}:streamGenerateContent?alt=sse`;
    const reqHeaders = buildGeminiHeaders(apiKey, customHeaders);

    const userContents = messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }]
      }));

    const bodyObj = {
      contents: userContents.length > 0 ? userContents : [{ role: 'user', parts: [{ text: 'Ping' }] }],
      generationConfig: {
        temperature: 0,
        maxOutputTokens: maxTokens
      }
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
        if (!trimmed.startsWith('data:')) continue;
        const dataPayload = trimmed.slice(5).trim();
        try {
          const parsed = JSON.parse(dataPayload);
          chunkCount += 1;
          if (!actualModel && parsed.modelVersion) actualModel = parsed.modelVersion;
          const parts = parsed.candidates?.[0]?.content?.parts || [];
          for (const p of parts) {
            if (p.text) assembledText += p.text;
          }
          if (rawSampleChunks.length < 4) {
            rawSampleChunks.push(parsed);
          }
        } catch {
          // ignore
        }
      }
    }

    return {
      ok: chunkCount > 0,
      status: response.status,
      url,
      ttfbMs: firstChunkMs || ttfbMs,
      totalMs: Math.round(performance.now() - startTime),
      headers: headersMap,
      chunkCount,
      receivedDone: chunkCount > 0,
      assembledText,
      actualModel,
      rawSampleChunks,
      rawRequest: { method: 'POST', url, headers: reqHeaders, body: bodyObj }
    };
  }
};
