import * as Cesium from 'cesium';

export const OSINT_OVERLAY_SOURCE_ID = 'osint-events';
export const OSINT_OVERLAY_COHORT_LIMIT = 64;
export const OSINT_OVERLAY_COLLISION_CAPACITY = 32;

const KIND_COLOR = {
  chokepoint: Cesium.Color.fromCssColorString('#00d4ff'),
  conflict: Cesium.Color.fromCssColorString('#ff5d6c'),
  event: Cesium.Color.fromCssColorString('#ff9f43'),
};

export function kindColor(kind) {
  return KIND_COLOR[kind] || KIND_COLOR.chokepoint;
}

/** Build the overlay label entry for one OSINT point. */
export function createOsintOverlayEntry({
  id,
  position,
  title,
  accent,
  priority = 500,
}) {
  return {
    id: String(id),
    position,
    variant: 'label',
    title: String(title || ''),
    accent,
    priority,
    collisionGroup: 'ambient-label',
    paintLane: 'ambient-label',
    interactive: false,
    edgeFade: 'keyhole',
    horizonCull: true,
    terrainOcclusion: false,
    gapPx: 15,
    verticalOnly: true,
    placement: 'above',
  };
}

/** Keep the highest-priority points, with stable identity as the tie-break. */
export function selectOsintOverlayCohort(
  entries,
  limit = OSINT_OVERLAY_COHORT_LIMIT,
) {
  const cap = Math.max(
    0,
    Math.min(OSINT_OVERLAY_COHORT_LIMIT, Math.floor(Number(limit) || 0)),
  );
  if (!Array.isArray(entries) || cap === 0) return [];
  return entries
    .slice()
    .sort(
      (a, b) =>
        b.priority - a.priority || String(a.id).localeCompare(String(b.id)),
    )
    .slice(0, cap);
}
