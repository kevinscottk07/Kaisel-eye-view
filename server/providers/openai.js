import { defaultSourceRoot } from './common/source-root.js';
import { handleHudSummary } from './openai/hud-summary.js';
import { createDebugLogHandler } from './openai/debug-log.js';
import { createRealtimeTokenHandler } from './openai/realtime.js';
import { sameSiteGated } from './common/same-site.js';

/**
 * Vite plugin: OpenAI Realtime ephemeral client secret.
 *
 * Keeps OPENAI_API_KEY server-side while the browser connects to the
 * Realtime API over WebRTC with a short-lived secret.
 *
 * `hudSummary` optionally supplies an alternative HUD-summary brain:
 * `{ prefer(): boolean, handle(req, res) }`. When `prefer()` is true the
 * request runs through `handle` (Claude); otherwise the OpenAI handler runs,
 * which also returns the keyless capability response when no key is set. The
 * alternative is injected so this exported provider keeps no dependency on it.
 */
function openAiRealtimeProxy({
  sourceRoot = defaultSourceRoot,
  annotationGuidance,
  realtime = {},
  hudSummary = null,
} = {}) {
  function install(middlewares) {
    // Cost-bearing and log endpoints refuse cross-site browser requests
    // (see server/providers/common/same-site.js and SECURITY.md).
    const hudSummaryHandler =
      hudSummary && typeof hudSummary.handle === 'function'
        ? (req, res) =>
            hudSummary.prefer()
              ? hudSummary.handle(req, res)
              : handleHudSummary(req, res)
        : handleHudSummary;
    middlewares.use(
      '/api/openai/hud-summary',
      sameSiteGated(hudSummaryHandler),
    );

    middlewares.use(
      '/api/realtime/debug-log',
      sameSiteGated(createDebugLogHandler({ sourceRoot })),
    );

    middlewares.use(
      '/api/realtime/token',
      sameSiteGated(
        createRealtimeTokenHandler({ ...realtime, annotationGuidance }),
      ),
    );
  }

  return {
    name: 'openai-realtime-proxy',
    configureServer(server) {
      install(server.middlewares);
    },
    configurePreviewServer(server) {
      install(server.middlewares);
    },
  };
}

export { openAiRealtimeProxy };
