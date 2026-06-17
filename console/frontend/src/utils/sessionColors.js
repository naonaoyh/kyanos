/**
 * HSL color model for session quality flags and filter matches.
 *
 * All functions return plain objects suitable for Vue :style bindings.
 * Colors use CSS custom property-style naming but are applied as inline
 * styles so they can transition smoothly via CSS transitions.
 *
 * Design:
 *   Problematic (red)    → hsl(350, 75%, 55%)  — requires attention
 *   Truncated  (amber)   → hsl(30,  80%, 60%)  — incomplete data
 *   Anomalous  (gold)    → hsl(40,  90%, 50%)  — has issues but operational
 *   Healthy    (green)   → hsl(140, 40%, 45%)  — no flags, score >= 100
 */

/** Base hues for session state categories (not filter-assigned). */
export const STATE_COLORS = {
  problematic: { hue: 350, saturation: 75, lightness: 53 },
  truncated:   { hue: 30,  saturation: 80, lightness: 60 },
  anomalous:   { hue: 40,  saturation: 90, lightness: 50 },
  healthy:     { hue: 140, saturation: 40, lightness: 45 },
}

/**
 * Row style for a session row.
 * Returns an object to bind to :style on the el-table row
 * (or pass to row-class-name CSS rules).
 *
 * @param {Object} session — SessionRecord
 * @param {Object} flags — classifySession() output
 * @returns {{ borderLeft?: string, background?: string }}
 */
export function sessionRowStyle(session, flags) {
  if (!flags) return {}
  if (flags.problematic) {
    return {
      borderLeft: '3px solid hsl(350, 75%, 53%)',
      background: 'hsla(350, 75%, 53%, 0.04)',
    }
  }
  if (flags.truncated) {
    return {
      borderLeft: '3px solid hsl(30, 80%, 60%)',
      background: 'hsla(30, 80%, 60%, 0.04)',
    }
  }
  if (flags.anomalous) {
    return {
      borderLeft: '3px solid hsl(40, 90%, 50%)',
      background: 'hsla(40, 90%, 50%, 0.04)',
    }
  }
  return {}
}

/**
 * Row class name for el-table :row-class-name binding.
 * Used when styles cannot be applied via :style (el-table renders
 * the row before the cell scope).
 */
export function sessionRowClass({ row, classifications }) {
  if (!classifications || !row) return ''
  const flags = classifications[row.session_id]
  if (!flags) return ''
  if (flags.problematic) return 'row-problematic'
  if (flags.truncated) return 'row-truncated'
  if (flags.anomalous) return 'row-anomalous'
  return ''
}

/**
 * Score badge color — transitions along a green→amber→red gradient
 * based on score value.
 */
export function scoreColor(score) {
  if (score >= 80) return { color: '#67c23a' }           // green
  if (score >= 60) return { color: '#e6a23c' }           // amber
  return { color: '#f56c6c' }                            // red
}

/**
 * Flag chip labels and abbreviations for display.
 */
export function flagLabel(flag) {
  const map = {
    problematic: { abbr: 'NO-RTCM', title: 'No correction stream (auth passed + GGA present but zero RTCM frames)' },
    truncated:   { abbr: 'TRUNC',  title: 'Truncated session (missing handshake or close event)' },
    anomalous:   { abbr: 'ANOM',   title: 'Session has diagnostic anomalies' },
  }
  return map[flag] || { abbr: flag, title: '' }
}
