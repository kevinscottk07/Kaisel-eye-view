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

const SYSTEM = `You are the voice of a cinematic intelligence console ("Kaisel's Eyes"). The user speaks to you; your words are read aloud, so reply in one or two short, natural spoken sentences — no markdown, no lists, no emoji.

The console has four views: the 3D globe ("globe"), the cyber "threat intel" view, the geopolitical "osint" view, and the "cases" link-analysis board. The globe has toggleable data layers (e.g. earthquakes, flights, satellites, vessels, traffic, cctv, "osint-events" for strategic chokepoints).

The Case Board lets the user build an investigation from threat entities — threat groups, malware, ATT&CK techniques/software, indicators, and CVEs. You can drive it by voice: start a case, add an entity by name, expand a node to pull in everything it connects to, or remove one. The user watches the board assemble as you act. Cases are about threat entities, never private individuals.

Act on the console with the provided tools — switch view, toggle a globe layer, fly the globe to a place, or build the case. When the user says things like "add APT29 to the case", "expand it", "pull in its techniques", "start a new case", call the matching case tool. You may both say a brief sentence and call one tool in the same turn; for a multi-step request, call the single most important tool and briefly say the next step. For questions, answer concisely; for deep live detail point the user to the right view. Never invent specific live readings you were not given.`;

const TOOLS = [
  {
    name: 'switch_view',
    description: 'Switch the console to a top-level view.',
    input_schema: {
      type: 'object',
      properties: {
        view: {
          type: 'string',
          enum: ['globe', 'threat-intel', 'osint', 'cases'],
        },
      },
      required: ['view'],
      additionalProperties: false,
    },
  },
  {
    name: 'case_new',
    description: 'Start a new, empty case on the Case Board.',
    input_schema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: 'case_add',
    description:
      'Add a threat entity to the current case by name — a threat group (e.g. "APT29"), malware ("Cobalt Strike"), ATT&CK technique ("T1055" or "Process Injection"), indicator, or CVE. Starts a case if none is open.',
    input_schema: {
      type: 'object',
      properties: { entity: { type: 'string' } },
      required: ['entity'],
      additionalProperties: false,
    },
  },
  {
    name: 'case_expand',
    description:
      'Expand a case node into everything it connects to. Name the node (e.g. "APT29"); omit to expand the most recently added node.',
    input_schema: {
      type: 'object',
      properties: { entity: { type: 'string' } },
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: 'case_remove',
    description: 'Remove a node from the current case by name.',
    input_schema: {
      type: 'object',
      properties: { entity: { type: 'string' } },
      required: ['entity'],
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
