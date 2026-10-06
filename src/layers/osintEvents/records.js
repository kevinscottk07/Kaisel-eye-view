/**
 * Reduce a Kaisel-Crucix OSINT snapshot to validated geographic points for the
 * globe layer: strategic chokepoints, and — when those Crucix sources are
 * populated — GDELT event points and ACLED conflict events. Pure and portable:
 * no Cesium, no browser globals. Invalid coordinates are dropped, never
 * truncated.
 *
 * @param {object} snapshot - The /api/osint/data payload.
 * @returns {Array<{stableId: string, kind: string, lon: number, lat: number,
 *   title: string, note: string}>}
 */
export function normalizeOsintGeo(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return [];
  const rows = [];
  const ids = new Set();
  const add = (kind, rawId, lon, lat, title, note) => {
    const lonN = Number(lon);
    const latN = Number(lat);
    if (!Number.isFinite(lonN) || Math.abs(lonN) > 180) return;
    if (!Number.isFinite(latN) || Math.abs(latN) > 90) return;
    const stableId = `${kind}:${String(rawId)}`;
    if (ids.has(stableId)) return;
    ids.add(stableId);
    rows.push({
      stableId,
      kind,
      lon: lonN,
      lat: latN,
      title: String(title ?? '').slice(0, 120),
      note: String(note ?? '').slice(0, 200),
    });
  };

  for (const c of Array.isArray(snapshot.chokepoints)
    ? snapshot.chokepoints
    : [])
    add(
      'chokepoint',
      c?.label ?? `${c?.lat},${c?.lon}`,
      c?.lon,
      c?.lat,
      c?.label,
      c?.note,
    );

  const geoPoints = Array.isArray(snapshot.gdelt?.geoPoints)
    ? snapshot.gdelt.geoPoints
    : [];
  for (const p of geoPoints)
    add(
      'event',
      p?.id ?? p?.title ?? `${p?.lat},${p?.lon}`,
      p?.lon ?? p?.longitude,
      p?.lat ?? p?.latitude,
      p?.title || p?.name || 'Event',
      p?.note || p?.location || '',
    );

  const events = Array.isArray(snapshot.acled?.deadliestEvents)
    ? snapshot.acled.deadliestEvents
    : [];
  for (const e of events)
    add(
      'conflict',
      e?.id ?? e?.event_id_cnty ?? `${e?.lat},${e?.lon}`,
      e?.lon ?? e?.longitude,
      e?.lat ?? e?.latitude,
      e?.type || e?.event_type || 'Conflict event',
      e?.notes || e?.location || '',
    );

  return rows;
}
