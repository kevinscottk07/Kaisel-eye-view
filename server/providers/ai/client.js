import Anthropic from '@anthropic-ai/sdk';

/**
 * Shared Anthropic client for the Claude-powered features (analyst, exposure
 * triage, HUD summary, voice). Cached by key + workspace.
 *
 * Most keys are workspace-scoped and work as-is. An org/admin-scoped key is
 * rejected unless the request carries an `anthropic-workspace-id` header, so
 * ANTHROPIC_WORKSPACE_ID (optional) is forwarded as a default header when set —
 * letting an org key work without changing the key itself.
 */
let cachedClient = null;
let cachedKey = null;
let cachedWorkspace = null;

export function anthropicClient(apiKey) {
  const workspace = String(process.env.ANTHROPIC_WORKSPACE_ID || '').trim();
  if (!cachedClient || cachedKey !== apiKey || cachedWorkspace !== workspace) {
    cachedClient = new Anthropic({
      apiKey,
      ...(workspace
        ? { defaultHeaders: { 'anthropic-workspace-id': workspace } }
        : {}),
    });
    cachedKey = apiKey;
    cachedWorkspace = workspace;
  }
  return cachedClient;
}
