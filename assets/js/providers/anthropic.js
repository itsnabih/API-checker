/**
 * providers/anthropic.js — Anthropic Native (/v1/messages) Zero-Cache Provider Adapter
 * Includes 'anthropic-dangerous-direct-browser-access: true' so GitHub Pages can test Claude directly.
 */

import { smartZeroCacheFetch } from '../security.js';
import { extractHeadersMap } from './openai.js';

export function normalizeAnthropicBaseUrl(rawUrl) {
  let url = (rawUrl || 'https://api.anthropic.com/v1').trim();
  url = url.replace(/\/+$/, '');
  url = url.replace(/\/messages$/i, '');
  url = url.replace(/\/models$/i, '');

  try {
    const parsed = new URL(url);
    if (!parsed.pathname || parsed.pathname === '/') {
      url = `${url}/v1`;
    }
  } catch {
    // ignore
  }
  return url;
}

export function buildAnthropicHeaders(apiKey, customHeaders = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'anthropic-version': '2023-06-01',
    'anthropic-dangerous-direct-browser-access': 'true',
    ...customHeaders
  };
  if (apiKey && apiKey.trim()) {
    headers['x-api-key'] = apiKey.trim();
  }
  return headers;
}

async function fetchWithTimeout(url, options, timeoutMs = 25000) {
  return await smartZeroCacheFetch(url, options, timeoutMs);
}

export const AnthropicAdapter = {
  protocolName: 'ANTHROPIC-NATIVE',

  normalizeBaseUrl: normalizeAnthropicBaseUrl,

  getPreviewPaths(rawUrl) {
    const base = normalizeAnthropicBaseUrl(rawUrl);
    return {
      base,
      modelsUrl: `${base}/models`,
      chatUrl: `${base}/messages`,
      authHeaderPreview: 'x-api-key: *** (Direct Browser Access Enabled)'
    };
  },

  async fetchModels({ baseUrl, apiKey, customHeaders = {}, timeoutMs = 20000 }) {
    const base = normalizeAnthropicBaseUrl(baseUrl);
    const url = `${base}/models`;
    const reqHeaders = buildAnthropicHeaders(apiKey, customHeaders);

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

    const rawList = Array.isArray(json?.data) ? json.data : [];
    const models = rawList.map((m) => ({
      id: m.id,
      owned_by: m.type || 'anthropic',
      created: m.created_at ? Math.floor(new Date(m.created_at).getTime() / 1000) : null,
      display_name: m.display_name || m.id,
      context_length: 200000,
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
    toolChoice = null,
    responseFormat = null,
    maxTokens = 200,
    temperature = 0,
    customHeaders = {},
    timeoutMs = 25000
  }) {
    const base = normalizeAnthropicBaseUrl(baseUrl);
    const url = `${base}/messages`;
    const reqHeaders = buildAnthropicHeaders(apiKey, customHeaders);

    let systemPrompt = '';
    const userMessages = [];

    for (const m of messages) {
      if (m.role === 'system') {
        systemPrompt += (systemPrompt ? '\n' : '') + m.content;
      } else {
        userMessages.push({
          role: m.role === 'assistant' ? 'assistant' : 'user',
          content: m.content
        });
      }
    }

    if (responseFormat?.type === 'json_object') {
      systemPrompt += '\nRespond ONLY with a valid raw JSON object without markdown code fences.';
    }

    const bodyObj = {
      model,
      max_tokens: maxTokens || 200,
      temperature,
      messages: userMessages.length > 0 ? userMessages : [{ role: 'user', content: 'Hello' }]
    };

    if (systemPrompt) {
      bodyObj.system = systemPrompt;
    }

    if (tools && tools.length > 0) {
      bodyObj.tools = tools.map((t) => {
        const fn = t.function || t;
        return {
          name: fn.name,
          description: fn.description || '',
          input_schema: fn.parameters || fn.input_schema || { type: 'object', properties: {} }
        };
      });
      if (toolChoice) {
        bodyObj.tool_choice = { type: 'any' };
      }
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

    const contentBlocks = Array.isArray(json?.content) ? json.content : [];
    const textParts = [];
    const thinkingParts = [];
    const toolCalls = [];

    for (const block of contentBlocks) {
      if (block.type === 'text') {
        textParts.push(block.text);
      } else if (block.type === 'thinking') {
        thinkingParts.push(block.thinking);
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id || 'toolu_1',
          type: 'function',
          function: {
            name: block.name,
            arguments: JSON.stringify(block.input || {})
          }
        });
      }
    }

    const usage = json?.usage
      ? {
          prompt_tokens: json.usage.input_tokens,
          completion_tokens: json.usage.output_tokens,
          total_tokens: (json.usage.input_tokens || 0) + (json.usage.output_tokens || 0),
          cache_read_input_tokens: json.usage.cache_read_input_tokens || 0
        }
      : null;

    return {
      ok: response.ok && json?.type !== 'error',
      status: response.status,
      statusText: response.statusText,
      url,
      ttfbMs,
      totalMs,
      headers: headersMap,
      id: json?.id || null,
      actualModel: json?.model || null,
      systemFingerprint: headersMap['request-id'] || headersMap['anthropic-organization-id'] || null,
      serviceTier: json?.usage?.service_tier || null,
      providerName: 'Anthropic',
      created: null,
      content: textParts.join('\n'),
      reasoningContent: thinkingParts.length > 0 ? thinkingParts.join('\n') : null,
      toolCalls,
      finishReason: json?.stop_reason || null,
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
    const base = normalizeAnthropicBaseUrl(baseUrl);
    const url = `${base}/messages`;
    const reqHeaders = buildAnthropicHeaders(apiKey, customHeaders);

    const userMessages = messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));

    const bodyObj = {
      model,
      max_tokens: maxTokens,
      temperature: 0,
      stream: true,
      messages: userMessages.length > 0 ? userMessages : [{ role: 'user', content: 'Ping' }]
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
        if (!trimmed.startsWith('data:')) continue;
        const dataPayload = trimmed.slice(5).trim();
        try {
          const parsed = JSON.parse(dataPayload);
          chunkCount += 1;
          if (parsed.type === 'message_start' && parsed.message?.model) {
            actualModel = parsed.message.model;
          }
          if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
            assembledText += parsed.delta.text;
          }
          if (parsed.type === 'message_stop') {
            receivedDone = true;
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
      receivedDone,
      assembledText,
      actualModel,
      rawSampleChunks,
      rawRequest: { method: 'POST', url, headers: reqHeaders, body: bodyObj }
    };
  }
};
