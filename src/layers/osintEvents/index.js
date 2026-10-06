import * as Cesium from 'cesium';
import {
  OSINT_OVERLAY_SOURCE_ID,
  OSINT_OVERLAY_COHORT_LIMIT,
  OSINT_OVERLAY_COLLISION_CAPACITY,
  kindColor,
  createOsintOverlayEntry,
  selectOsintOverlayCohort,
} from './model.js';
export * from './model.js';
export { createOsintEventsSource } from './source.js';

/** Own one OSINT-events display (chokepoints and live events) and its refresh. */
export function createOsintEventsLayer({ source, overlayHost } = {}) {
  if (typeof source?.getSnapshot !== 'function')
    throw new TypeError('OSINT events require a snapshot source');
  if (!overlayHost) throw new TypeError('OSINT events require an overlay host');
  let _viewer = null;
  let _request = null;
  let _dataSource = null;
  let _count = 0;
  let _lastUpdate = null;
  let _lastError = null;
  let _enabled = false;

  const PRIORITY = { chokepoint: 700, conflict: 600, event: 500 };

  const layer = {
    id: 'osint-events',
    name: 'OSINT Events',
    icon: '🌐',
    source: 'Crucix',
    updateInterval: 300000,

    init(viewer) {
      if (_viewer) throw new Error('OSINT layer is already initialized');
      _viewer = viewer;
      _dataSource = new Cesium.CustomDataSource('osint-events');
      _dataSource.show = false;
      viewer.dataSources.add(_dataSource);
      _count = 0;
      _lastUpdate = null;
      _lastError = null;
      _enabled = false;
      overlayHost.setVisible(OSINT_OVERLAY_SOURCE_ID, false);
      console.log('[Data:OSINT] Initialized');
    },

    enable() {
      _enabled = true;
      if (_dataSource) _dataSource.show = true;
      overlayHost.setVisible(OSINT_OVERLAY_SOURCE_ID, true);
    },

    disable() {
      _request?.abort();
      _request = null;
      _enabled = false;
      if (_dataSource) _dataSource.show = false;
      overlayHost.clearSource(OSINT_OVERLAY_SOURCE_ID);
      overlayHost.setVisible(OSINT_OVERLAY_SOURCE_ID, false);
    },

    async update() {
      if (!_enabled || !_dataSource) return false;
      _request?.abort();
      const request = new AbortController();
      _request = request;
      try {
        const rows = await source.getSnapshot({ signal: request.signal });
        if (request.signal.aborted || _request !== request || !_enabled)
          return false;

        const nextEntities = [];
        const overlayEntries = [];
        let count = 0;

        for (const { stableId, kind, lon, lat, title, note } of rows) {
          count += 1;
          const color = kindColor(kind);
          const position = Cesium.Cartesian3.fromDegrees(lon, lat);
          nextEntities.push(
            new Cesium.Entity({
              id: `osint:${stableId}`,
              position,
              point: {
                pixelSize: kind === 'chokepoint' ? 11 : 9,
                color: color.withAlpha(0.9),
                outlineColor: Cesium.Color.BLACK.withAlpha(0.6),
                outlineWidth: 1,
                heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
                disableDepthTestDistance: Number.POSITIVE_INFINITY,
              },
              properties: { kind, title, note },
            }),
          );
          overlayEntries.push(
            createOsintOverlayEntry({
              id: String(stableId),
              position,
              title,
              accent: color.toCssColorString(),
              priority: PRIORITY[kind] || 500,
            }),
          );
        }

        _dataSource.entities.removeAll();
        for (const entity of nextEntities) _dataSource.entities.add(entity);
        if (_enabled) {
          overlayHost.setEntries(
            OSINT_OVERLAY_SOURCE_ID,
            selectOsintOverlayCohort(overlayEntries),
            {
              cohortLimit: OSINT_OVERLAY_COHORT_LIMIT,
              collisionCapacity: OSINT_OVERLAY_COLLISION_CAPACITY,
              moving: false,
            },
          );
        }

        _count = count;
        _lastUpdate = Date.now();
        _lastError = null;
        console.log(`[Data:OSINT] Updated: ${_count} points`);
        return true;
      } catch (e) {
        if (request.signal.aborted || _request !== request || !_enabled)
          return false;
        console.warn('[Data:OSINT] Fetch error:', e);
        _lastError = e?.message || 'OSINT source unavailable';
        return false;
      } finally {
        if (_request === request) _request = null;
      }
    },

    destroy(viewer = _viewer) {
      _request?.abort();
      _request = null;
      _viewer = null;
      _enabled = false;
      overlayHost.clearSource(OSINT_OVERLAY_SOURCE_ID);
      overlayHost.setVisible(OSINT_OVERLAY_SOURCE_ID, false);
      if (_dataSource) {
        viewer.dataSources.remove(_dataSource, true);
        _dataSource = null;
      }
      _count = 0;
      _lastUpdate = null;
      _lastError = null;
    },

    getStats() {
      return {
        count: _count,
        lastUpdate: _lastUpdate,
        error: _lastError,
      };
    },
  };
  return layer;
}
