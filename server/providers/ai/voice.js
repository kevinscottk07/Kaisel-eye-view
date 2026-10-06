import Anthropic from '@anthropic-ai/sdk';

import { readRequestBody } from '../common/request.js';
import { makeCostRateLimiter, clientKey } from '../common/rate-limit.js';
import { sameSiteGated } from '../common/same-site.js';
import { anthropicClient } from './client.js';

/**
 * Claude voice command endpoint. The browser does speech-to-text and
 * text-to-speech itself (Web Speech API); this turns one transcribed command
 * into a short spoken reply plus an optional console action, so voice control
 * runs on the Anthropic key with no OpenAI dependency.
 *
 * POST /api/voice/claude {transcript, context} →
 *   {speech, actions:[{type, ...}], model} | 503 {error:'no_key'}
 */

const MODEL_DEFAULT = 'claude-sonnet-5-5';
const ANTHROPIC_DEFAULT_PER_MIN = 20;

const SYSTEM = `You are the voice of a cinematic intelligence console ("God's Eye View / Kaisel"). The user speaks to you; your words are read aloud, so reply in one or two short, natural spoken sentences — no markdown, no lists, no emoji.

The console has three views: the 3D globe ("globe"), the cyber "threat intel" view, and the geopolitical "osint" view. The globe has toggleable data layers (e.g. earthquakes, flights, satellites, vessels, traffic, cctv, "osint-events" for strategic chokepoints).

You can act on the console with the provided tools — switch view, toggle a globe layer, or fly the globe to a place. Use a tool only when the user clearly asks to navigate or change what is shown; otherwise just answer. You may both say a brief sentence and call one tool in the same turn. For questions, answer helpfully and concisely from general knowledge; for deep, current intelligence detail tell the user which view or the Analyst tab to open. Never invent specific live readings you were not given.`;

const TOOLS = [
  {
    name: 'switch_view',
    description: 'Switch the console to a top-level view.',
    input_schema: {
      type: 'object',
      properties: {
        view: { type: 'string', enum: ['globe', 'threat-intel', 'osint'] },
      },
      required: ['view'],
      additionalProperties: false,
    },
  },
  {
    name: 'toggle_layer',
    description:
      'Turn a globe data layer on or off. Use the layer name the user said (e.g. "earthquakes", "satellites", "osint events").',
    input_schema: {
      type: 'object',
      properties: {
        layer: { type: 'string' },
        on: { type: 'boolean' },
      },
      required: ['layer', 'on'],
      additionalProperties: false,
    },
  },
  {
    name: 'fly_to',
    description: 'Fly the 3D globe camera to a named place, city, or region.',
    input_schema: {
      type: 'object',
      properties: { place: { type: 'string' } },
      required: ['place'],
      additionalProperties: false,
    },
  },
];

let limiter;

export async function handleClaudeVoice(req, res) {
  const send = (status, body) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(body));
  };
  if (req.method !== 'POST') {
    send(405, { error: 'Method not allowed' });
    return;
  }
  const apiKey = String(process.env.ANTHROPIC_API_KEY || '').trim();
  if (!apiKey) {
    send(503, { error: 'no_key' });
    return;
  }
  if (limiter === undefined)
    limiter = makeCostRateLimiter(
      process.env.GEV_RATELIMIT_ANTHROPIC_PER_MIN,
      ANTHROPIC_DEFAULT_PER_MIN,
    );
  if (limiter && !limiter(clientKey(req))) {
    res.setHeader('Retry-After', '5');
    send(429, { error: 'Rate limit exceeded' });
    return;
  }

  let transcript = '';
  let context = {};
  try {
    const body = JSON.parse((await readRequestBody(req, 16 * 1024)) || '{}');
    transcript =
      typeof body.transcript === 'string'
        ? body.transcript.trim().slice(0, 1000)
        : '';
    if (body.context && typeof body.context === 'object')
      context = body.context;
  } catch {
    send(400, { error: 'Invalid request body' });
    return;
  }
  if (!transcript) {
    send(400, { error: 'Empty transcript' });
    return;
  }

  try {
    const response = await anthropicClient(apiKey).messages.create({
      model: process.env.GEV_VOICE_MODEL || MODEL_DEFAULT,
      max_tokens: 400,
      system: SYSTEM,
      tools: TOOLS,
      messages: [
        {
          role: 'user',
          content: `Current view: ${context.view || 'globe'}. The user said: "${transcript}"`,
        },
      ],
    });
    const speech = response.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join(' ')
      .trim();
    const actions = response.content
      .filter((block) => block.type === 'tool_use')
      .map((block) => ({ type: block.name, ...block.input }));
    send(200, {
      speech: speech || null,
      actions,
      model: response.model,
    });
  } catch (error) {
    if (error instanceof Anthropic.AuthenticationError) {
      send(401, { error: 'The Anthropic API key was rejected.' });
      return;
    }
    if (error instanceof Anthropic.RateLimitError) {
      send(429, { error: 'Anthropic rate limit reached.' });
      return;
    }
    console.warn('[voice] Claude request failed:', error?.message || error);
    send(502, { error: 'The voice request failed.' });
  }
}

/** True when a Claude key is configured (voice can run without OpenAI). */
export function claudeVoiceConfigured() {
  return Boolean(String(process.env.ANTHROPIC_API_KEY || '').trim());
}

/**
 * Vite plugin: the Claude voice command endpoint. Same-site gated like the
 * other cost-bearing endpoints.
 * @returns {import('vite').Plugin}
 */
export function claudeVoiceProxy() {
  const install = (middlewares) => {
    middlewares.use('/api/voice/claude', sameSiteGated(handleClaudeVoice));
    middlewares.use('/api/voice/status', (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({ available: claudeVoiceConfigured() }));
    });
  };
  return {
    name: 'claude-voice-proxy',
    configureServer(server) {
      install(server.middlewares);
    },
    configurePreviewServer(server) {
      install(server.middlewares);
    },
  };
}
