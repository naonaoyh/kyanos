/**
 * Derive session classification flags from SessionRecord fields.
 *
 * All flags are computed client-side from data already available in the
 * REST API response — no new proto fields or server changes needed.
 *
 * @param {Object} session — SessionRecord-like object with the standard JSON shape
 * @returns {{ truncated: boolean, problematic: boolean, anomalous: boolean }}
 */
export function classifySession(session) {
  const authChecked = session.auth_checked || false
  const closed = session.closed || false
  const ggaEvents = session.gga_events || 0
  const rtcmFrames = session.rtcm_frames || 0
  const authSuccess = session.auth_success || false
  const issues = session.issues || []
  const score = session.score || 0

  // Truncated: missing handshake (capture started mid-stream), or
  // close event never captured (stopped before TCP close), or GGA
  // data present but zero RTCM and session isn't formally closed —
  // the data stream was cut mid-flight.
  const truncated =
    !authChecked ||
    !closed ||
    (ggaEvents > 0 && rtcmFrames === 0 && !closed)

  // Problematic: auth succeeded, GGA is being uploaded, but zero RTCM
  // frames arrived — the device reconnected but never received a
  // correction stream. Distinct from truncated (has handshake, no data).
  const problematic = authSuccess && ggaEvents > 0 && rtcmFrames === 0

  // Anomalous: session has diagnostic issues OR a sub-100 score.
  const anomalous = issues.length > 0 || (score > 0 && score < 100)

  return { truncated, problematic, anomalous }
}

/**
 * Returns the single most important classification for a session.
 * Priority: problematic > truncated > anomalous.
 */
export function primaryFlag(session) {
  const flags = classifySession(session)
  if (flags.problematic) return 'problematic'
  if (flags.truncated) return 'truncated'
  if (flags.anomalous) return 'anomalous'
  return null
}
