import { createOsintEventsLayer } from '../../layers/osintEvents/index.js';
import { overlayHost } from './overlayHost.js';
/** Wire the OSINT events layer to the application overlay host. */
export function createApplicationOsintEvents(options) {
  return createOsintEventsLayer({ overlayHost, ...options });
}
