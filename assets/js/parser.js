/**
 * parser.js — Ephemeral Config Importer (.env / Strix / Xalgorix / JSON / cURL) & Ready-to-Use Exporter
 */

import { maskKeyPreview } from './security.js';

/**
 * Parses an ephemeral paste block (.env, export commands, JSON, or cURL) into { protocol, baseUrl, model, apiKey }
 */
export function parseEphemeralConfigInput(rawText = '') {
  const text = String(rawText || '').trim();
  if (!text) return null;

  const result = {
    protocol: null,
    baseUrl: null,
    model: null,
    apiKey: null,
    customHeaders: null
  };

  // 1. Try JSON format first
  if (text.startsWith('{') && text.endsWith('}')) {
    try {
      const obj = JSON.parse(text);
      result.baseUrl = obj.base_url || obj.baseUrl || obj.api_base || obj.endpoint || null;
      result.apiKey = obj.api_key || obj.apiKey || obj.key || obj.token || null;
      result.model = obj.model || obj.model_id || obj.modelId || obj.strix_llm || null;
      result.protocol = obj.provider || obj.protocol || null;
      return normalizeParsedConfig(result);
    } catch {
      // fall through to line/regex parsing
    }
  }

  // 2. Check if it's a cURL command
  if (/^\s*curl\b/i.test(text)) {
    const urlMatch = text.match(/https?:\/\/[^\s"']+/i);
    if (urlMatch) {
      result.baseUrl = urlMatch[0]
        .replace(/\/chat\/completions.*$/i, '')
        .replace(/\/messages.*$/i, '')
        .replace(/:generateContent.*$/i, '');
    }
    const bearerMatch = text.match(/Authorization:\s*Bearer\s+([^\s"']+)/i);
    const xApiKeyMatch = text.match(/x-api-key:\s*([^\s"']+)/i);
    const googKeyMatch = text.match(/x-goog-api-key:\s*([^\s"']+)/i);
    result.apiKey = bearerMatch?.[1] || xApiKeyMatch?.[1] || googKeyMatch?.[1] || null;

    const modelMatch = text.match(/"model"\s*:\s*"([^"]+)"/i);
    if (modelMatch) result.model = modelMatch[1];

    return normalizeParsedConfig(result);
  }

  // 3. Parse .env / shell export lines
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.+)$/);
    if (!match) continue;

    const key = match[1].toUpperCase();
    let val = match[2].trim();
    // Strip surrounding quotes
    val = val.replace(/^["']|["']$/g, '').trim();
    if (!val) continue;

    // Base URL keys
    if (
      [
        'LLM_BASE_URL',
        'STRIX_BASE_URL',
        'XALGORIX_BASE_URL',
        'OPENAI_BASE_URL',
        'OPENAI_API_BASE',
        'ANTHROPIC_BASE_URL',
        'GEMINI_BASE_URL',
        'BASE_URL',
        'API_BASE'
      ].includes(key)
    ) {
      result.baseUrl = val;
    }

    // API Key keys
    if (
      [
        'LLM_API_KEY',
        'STRIX_API_KEY',
        'XALGORIX_API_KEY',
        'OPENAI_API_KEY',
        'ANTHROPIC_API_KEY',
        'GEMINI_API_KEY',
        'GOOGLE_API_KEY',
        'OPENROUTER_API_KEY',
        'DEEPSEEK_API_KEY',
        'GROQ_API_KEY',
        'API_KEY'
      ].includes(key)
    ) {
      result.apiKey = val;
      if (key === 'ANTHROPIC_API_KEY' && !result.protocol) result.protocol = 'anthropic';
      if ((key === 'GEMINI_API_KEY' || key === 'GOOGLE_API_KEY') && !result.protocol) result.protocol = 'gemini';
      if (key === 'OPENROUTER_API_KEY' && !result.baseUrl) result.baseUrl = 'https://openrouter.ai/api/v1';
      if (key === 'DEEPSEEK_API_KEY' && !result.baseUrl) result.baseUrl = 'https://api.deepseek.com/v1';
      if (key === 'GROQ_API_KEY' && !result.baseUrl) result.baseUrl = 'https://api.groq.com/openai/v1';
    }

    // Model keys
    if (
      [
        'STRIX_LLM',
        'XALGORIX_MODEL',
        'XALGORIX_LLM',
        'LLM_MODEL',
        'OPENAI_MODEL',
        'ANTHROPIC_MODEL',
        'GEMINI_MODEL',
        'MODEL',
        'MODEL_ID'
      ].includes(key)
    ) {
      result.model = val;
    }
  }

  return normalizeParsedConfig(result);
}

function normalizeParsedConfig(res) {
  if (res.model && res.model.includes('/')) {
    const parts = res.model.split('/');
    const prefix = parts[0].toLowerCase();
    if (prefix === 'openai') {
      res.protocol = res.protocol || 'openai';
      res.model = parts.slice(1).join('/');
    } else if (prefix === 'anthropic') {
      res.protocol = res.protocol || 'anthropic';
      res.model = parts.slice(1).join('/');
      if (!res.baseUrl) res.baseUrl = 'https://api.anthropic.com/v1';
    } else if (prefix === 'gemini' || prefix === 'google') {
      res.protocol = res.protocol || 'gemini';
      res.model = parts.slice(1).join('/');
      if (!res.baseUrl) res.baseUrl = 'https://generativelanguage.googleapis.com/v1beta';
    } else if (prefix === 'openrouter') {
      res.protocol = 'openai';
      res.model = parts.slice(1).join('/');
      if (!res.baseUrl) res.baseUrl = 'https://openrouter.ai/api/v1';
    }
  }
  return res;
}

/**
 * Generates ready-to-use configuration snippets for Strix, Xalgorix, .env, JSON, or cURL
 */
export function generateExportConfig({
  format = 'strix',
  protocol = 'openai',
  baseUrl = 'https://api.openai.com/v1',
  model = 'gpt-4o-mini',
  apiKey = '',
  useRedacted = true,
  forensicsSummary = null
}) {
  const keyToOutput = useRedacted ? maskKeyPreview(apiKey) : apiKey || '<YOUR_API_KEY>';
  const cleanBase = (baseUrl || '').trim().replace(/\/+$/, '');
  const cleanModel = (model || '').trim();

  // LiteLLM prefix for Strix / LiteLLM-based agents
  let litellmPrefix = 'openai';
  if (protocol === 'anthropic') litellmPrefix = 'anthropic';
  else if (protocol === 'gemini') litellmPrefix = 'gemini';
  else if (cleanBase.includes('openrouter.ai')) litellmPrefix = 'openrouter';

  const strixModelString = cleanModel.startsWith(`${litellmPrefix}/`)
    ? cleanModel
    : `${litellmPrefix}/${cleanModel}`;

  if (format === 'strix') {
    return [
      `export STRIX_LLM="${strixModelString}"`,
      `export LLM_API_KEY="${keyToOutput}"`,
      `export LLM_BASE_URL="${cleanBase}"`,
      ``,
      protocol === 'anthropic'
        ? `export ANTHROPIC_API_KEY="${keyToOutput}"`
        : protocol === 'gemini'
        ? `export GEMINI_API_KEY="${keyToOutput}"`
        : `export OPENAI_API_KEY="${keyToOutput}"\nexport OPENAI_BASE_URL="${cleanBase}"`
    ].join('\n');
  }

  if (format === 'xalgorix') {
    return [
      `export XALGORIX_PROVIDER="${protocol}"`,
      `export XALGORIX_MODEL="${cleanModel}"`,
      `export XALGORIX_API_KEY="${keyToOutput}"`,
      `export XALGORIX_BASE_URL="${cleanBase}"`,
      ``,
      `export LLM_MODEL="${strixModelString}"`,
      `export LLM_API_KEY="${keyToOutput}"`,
      `export LLM_BASE_URL="${cleanBase}"`
    ].join('\n');
  }

  if (format === 'dotenv') {
    return [
      `PROVIDER_PROTOCOL="${protocol}"`,
      `LLM_MODEL="${cleanModel}"`,
      `LITELLM_MODEL="${strixModelString}"`,
      `LLM_BASE_URL="${cleanBase}"`,
      `LLM_API_KEY="${keyToOutput}"`,
      `OPENAI_API_KEY="${keyToOutput}"`,
      `OPENAI_BASE_URL="${cleanBase}"`
    ].join('\n');
  }

  if (format === 'json') {
    return JSON.stringify(
      {
        agent_config: {
          protocol,
          base_url: cleanBase,
          model: cleanModel,
          litellm_model: strixModelString,
          api_key: keyToOutput
        },
        verification: {
          verified_by: 'AGENT API.IO (Zero-Trace Edition)',
          summary: forensicsSummary || 'Unverified'
        }
      },
      null,
      2
    );
  }

  if (format === 'curl') {
    if (protocol === 'anthropic') {
      return [
        `curl -sS --no-buffer "${cleanBase}/messages" \\`,
        `  -H "Content-Type: application/json" \\`,
        `  -H "x-api-key: ${keyToOutput}" \\`,
        `  -H "anthropic-version: 2023-06-01" \\`,
        `  -d '{"model":"${cleanModel}","max_tokens":64,"messages":[{"role":"user","content":"Ping"}]}'`
      ].join('\n');
    }
    if (protocol === 'gemini') {
      const m = cleanModel.replace(/^models\//, '');
      return [
        `curl -sS --no-buffer "${cleanBase}/models/${m}:generateContent" \\`,
        `  -H "Content-Type: application/json" \\`,
        `  -H "x-goog-api-key: ${keyToOutput}" \\`,
        `  -d '{"contents":[{"role":"user","parts":[{"text":"Ping"}]}]}'`
      ].join('\n');
    }
    return [
      `curl -sS --no-buffer "${cleanBase}/chat/completions" \\`,
      `  -H "Content-Type: application/json" \\`,
      `  -H "Authorization: Bearer ${keyToOutput}" \\`,
      `  -d '{"model":"${cleanModel}","max_tokens":64,"messages":[{"role":"user","content":"Ping"}]}'`
    ].join('\n');
  }

  return '';
}
