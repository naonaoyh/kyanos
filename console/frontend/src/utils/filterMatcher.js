/**
 * Filter match scoring and color assignment.
 *
 * Filters are defined per capture task (mountpoints + usernames arrays).
 * Match scoring determines how many loaded sessions pass each filter,
 * and assigns a stable HSL hue to each filter so UI elements (dots, rows,
 * filter panel) share the same color.
 */

/** Stable hue rotation for filter identity. Index into this with the
 *  filter's position in the active-filters list. */
const FILTER_HUES = [200, 160, 280, 40, 320, 80] // blue, teal, purple, gold, pink, green

/**
 * Compute match statistics for a set of active filters against loaded sessions.
 *
 * @param {Array} filters — Task-like objects with { id, ntrip_filter: { mountpoints?, usernames? }, status }
 * @param {Array} sessions — SessionRecord-like objects
 * @returns {Map<string, { matchCount: number, totalSessions: number, matchRate: number, matches: Set<string> }>}
 */
export function computeFilterMatches(filters, sessions) {
  const stats = new Map()
  if (!filters || !sessions) return stats

  for (const filter of filters) {
    if (filter.status !== 'running') continue
    const ntrip = filter.ntrip_filter
    if (!ntrip) continue

    const mountpoints = ntrip.mountpoints || []
    const usernames = ntrip.usernames || []
    const hasFilter = mountpoints.length > 0 || usernames.length > 0
    if (!hasFilter) continue

    let matchCount = 0
    const matches = new Set()
    for (const session of sessions) {
      let matched = false
      if (mountpoints.length > 0 && mountpoints.includes(session.mountpoint)) matched = true
      if (usernames.length > 0 && usernames.includes(session.username)) matched = true
      if (matched) {
        matchCount++
        matches.add(session.session_id)
      }
    }
    const totalSessions = sessions.length
    const matchRate = totalSessions > 0 ? matchCount / totalSessions : 0
    stats.set(filter.id, { matchCount, totalSessions, matchRate, matches })
  }
  return stats
}

/**
 * Filter color derived from its index in the active list and its match rate.
 * Match rate drives saturation and lightness so high-hit filters are more
 * saturated and richer, while never-matched filters are pale/muted.
 *
 * @param {string} filterId
 * @param {number} index — position in the active-filter list (stable)
 * @param {number} matchRate — 0.0 (never matched) to 1.0 (matches all sessions)
 * @returns {{ bg: string, accent: string, dot: string }}
 */
export function filterColor(filterId, index, matchRate) {
  const hue = FILTER_HUES[index % FILTER_HUES.length]
  const saturation = 30 + Math.round(matchRate * 70) // 30% (never) → 100% (all)
  const lightness = matchRate > 0.3 ? 55 : 70          // bright for low-match, rich for high-match
  return {
    bg: `hsla(${hue}, ${saturation}%, ${lightness}%, 0.12)`,
    accent: `hsl(${hue}, ${saturation}%, ${lightness}%)`,
    dot: `hsl(${hue}, 80%, 48%)`,
  }
}

/** Gray color for disabled / stopped filters. */
export function disabledFilterColor() {
  return {
    bg: 'hsla(0, 0%, 70%, 0.08)',
    accent: 'hsl(0, 0%, 70%)',
    dot: 'hsl(0, 0%, 82%)',
  }
}

/**
 * Filter display label from its config.
 */
export function filterLabel(filter) {
  const parts = []
  const ntrip = filter.ntrip_filter
  if (!ntrip) return 'All traffic'
  if (ntrip.mountpoints?.length) parts.push(ntrip.mountpoints.join(','))
  if (ntrip.usernames?.length) parts.push(ntrip.usernames.join(','))
  return parts.length > 0 ? parts.join(' / ') : 'All traffic'
}
