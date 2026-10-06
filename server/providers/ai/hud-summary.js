import { anthropicClient } from './client.js';

import { HUD_SUMMARY_INSTRUCTIONS } from '../../../src/hudSummaryResponse.js';
import { makeCostRateLimiter, clientKey } from '../common/rate-limit.js';
import { readRequestBody } from '../common/request.js';

/**
 * Claude-backed HUD summary. Mirrors the OpenAI handler's request and response
 * shape so the client is unchanged, but runs on Claude when ANTHROPIC_API_KEY
 * is present. The HUD asks every 15s, so this uses a small, fast model by
 * default (overridable via GEV_HUD_SUMMARY_MODEL) rather than the analyst's
 * Opus — a five-word line does not need it, and the cost would add up.
 */

const MODEL_DEFAULT = 'claude-haiku-4-5';
const ANTHROPIC_DEFAULT_PER_MIN = 30;

let limiter;

/** Collapse the model's reply to exactly five words, matching the OpenAI path. */
function toFiveWordHudSummary(value) {
  return String(value || '')
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 5)
    .join(' ');
}

export async function handleClaudeHudSummary(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Shares the analyst's per-IP budget (GEV_RATELIMIT_ANTHROPIC_PER_MIN).
  if (limiter === undefined)
    limiter = makeCostRateLimiter(
      process.env.GEV_RATELIMIT_ANTHROPIC_PER_MIN,
      ANTHROPIC_DEFAULT_PER_MIN,
    );
  if (limiter && !limiter(clientKey(req))) {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Retry-After', '5');
    res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
    return;
  }

  const apiKey = String(process.env.ANTHROPIC_API_KEY || '').trim();
  try {
    const body = await readRequestBody(req, 64 * 1024);
    const context = JSON.parse(body || '{}');
    const response = await anthropicClient(apiKey).messages.create({
      model: process.env.GEV_HUD_SUMMARY_MODEL || MODEL_DEFAULT,
      max_tokens: 32,
      system: HUD_SUMMARY_INSTRUCTIONS,
      messages: [{ role: 'user', content: JSON.stringify(context) }],
    });
    const text = response.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join(' ');
    const summary = toFiveWordHudSummary(text);
    res.statusCode = summary ? 200 : 502;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(
      JSON.stringify({
        summary: summary || null,
        // Never relay the upstream message: it can carry request ids and
        // organization details.
        error: summary ? null : 'Claude HUD summary request failed',
      }),
    );
  } catch {
    console.warn('[claude-hud-summary] request failed');
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Claude HUD summary request failed' }));
  }
}

/** True when a Claude key is configured, so the brain prefers Claude. */
export function claudeConfigured() {
  return Boolean(String(process.env.ANTHROPIC_API_KEY || '').trim());
}
