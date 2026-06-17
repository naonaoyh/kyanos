<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getSession, getSessionEvents } from '../api'
import { classifySession } from '../utils/sessionFlags'

const route = useRoute()
const router = useRouter()
const session = ref(null)
const events = ref([])
const loading = ref(false)
const wsConnected = ref(false)
const liveDuration = ref(0)

// Truncation notice and identity card color
const flags = computed(() => session.value ? classifySession(session.value) : {})

const truncationNotice = computed(() => {
  if (!session.value) return null
  const hasHandshake = events.value.some(e => e.event_type === 'auth')
  const isClosed = session.value.closed
  if (!hasHandshake && !isClosed) return { severity: 'warning', text: 'Handshake not captured and session is still active — data may be incomplete.' }
  if (!hasHandshake) return { severity: 'info', text: 'Handshake data not captured (capture started mid-stream).' }
  if (!isClosed) return { severity: 'info', text: 'Session still active — close event not yet captured. GGA/RTCM counters may be partial.' }
  return null
})

const identityBorderColor = computed(() => {
  const f = flags.value
  if (f.problematic) return 'hsl(350, 75%, 53%)'
  if (f.truncated)   return 'hsl(30, 80%, 55%)'
  if (f.anomalous)   return 'hsl(40, 90%, 45%)'
  return 'transparent'
})

let socket = null
let durationTimer = null

// ---------------------------------------------------------------------------
// NTRIP data model: events classified by their role in the session lifecycle.
//
//   - Handshake:   auth events (GET/SOURCE request + ICY/HTTP response)
//   - GGA uplink:   periodic client→caster position reports (▲)
//   - RTCM downlink: continuous caster→client correction frames (▼)
//   - Network:      TCP-level retransmissions / RTT (not shown inline, summarized in stats)
//   - Close:        session termination event
// ---------------------------------------------------------------------------

const MAX_INLINE_ROWS = 10

const handshakeEvents = computed(() =>
  events.value.filter(e => e.event_type === 'auth')
)

const ggaEvents = computed(() =>
  events.value.filter(e => e.event_type === 'gga').slice(-Math.min(events.value.filter(x => x.event_type === 'gga').length, MAX_INLINE_ROWS))
)

const rtcmEvents = computed(() =>
  events.value.filter(e => e.event_type === 'rtcm').slice(-Math.min(events.value.filter(x => x.event_type === 'rtcm').length, MAX_INLINE_ROWS))
)

const ggaTotal = computed(() => events.value.filter(e => e.event_type === 'gga').length)
const rtcmTotal = computed(() => events.value.filter(e => e.event_type === 'rtcm').length)
const ggaOverflow = computed(() => Math.max(0, ggaTotal.value - MAX_INLINE_ROWS))
const rtcmOverflow = computed(() => Math.max(0, rtcmTotal.value - MAX_INLINE_ROWS))

// Stats cards
const sessionStats = computed(() => {
  if (!session.value) return []
  const s = session.value
  const gga = ggaEvents.value
  const lastFix = gga.length > 0 ? gga[gga.length - 1].event_data : null
  const rtcm = rtcmEvents.value
  const lastCRC = rtcm.filter(x => x.event_data && !x.event_data.crc_valid).length
  return [
    { label: 'GGA Events', value: (s.gga_events || 0).toLocaleString(), detail: lastFix ? `Last fix: ${lastFix.fix_quality || '?'}/${lastFix.num_satellites || '?'} sats` : '' },
    { label: 'RTCM Frames', value: (s.rtcm_frames || 0).toLocaleString(), detail: s.rtcm_crc_errors ? `${s.rtcm_crc_errors} CRC errors` : '' },
    { label: 'Avg RTT', value: s.avg_rtt_ms ? s.avg_rtt_ms.toFixed(1) + 'ms' : '-', detail: '' },
    { label: 'Retransmissions', value: s.retransmissions || 0, detail: s.tcp_resets ? `${s.tcp_resets} resets` : '' },
  ]
})

// Score color
const scoreColor = (score) => { return score >= 80 ? '#67c23a' : score >= 60 ? '#e6a23c' : '#f56c6c' }

// Time formatting
const formatDuration = (ms) => {
  if (!ms) return '-'
  const h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000), s = Math.floor((ms % 60000) / 1000)
  if (h > 0) return `${h}h${m}m${s}s`
  if (m > 0) return `${m}m${s}s`
  return `${s}s`
}
const formatTimestamp = (ns) => {
  const d = new Date(ns / 1e6)
  return d.toISOString().substring(11, 23)
}

// --- GGA helpers (from event_data) ---
const ggaFixLabel = (fix) => { return ['', 'GPS', 'DGPS', '', 'RTK-F', 'RTK-F'][fix] || `Q${fix}` }
const ggaData = (evt) => { return evt.event_data || {} }

// --- RTCM helpers ---
const rtcmData = (evt) => { return evt.event_data || {} }

// ---------------------------------------------------------------------------
// Lifecycle & WebSocket (unchanged real-time plumbing)
// ---------------------------------------------------------------------------

const startDurationTimer = () => {
  if (session.value && !session.value.closed) {
    const startTime = new Date(session.value.start_time).getTime()
    durationTimer = setInterval(() => { liveDuration.value = Date.now() - startTime }, 1000)
  }
}

const connectWebSocket = () => {
  if (session.value && session.value.closed) return
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/api/v1/ws/sessions/${route.params.id}`
  socket = new WebSocket(url)
  socket.onopen = () => { wsConnected.value = true }
  socket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'session_event') {
        const evt = msg.data
        if (!evt || events.value.some(e => e.timestamp_ns === evt.timestamp_ns && e.event_type === evt.event_type)) return
        events.value.push(evt)
        events.value.sort((a, b) => a.timestamp_ns - b.timestamp_ns)
        // Update live session counters
        if (session.value) {
          if (evt.event_type === 'rtcm') {
            session.value.rtcm_frames = (session.value.rtcm_frames || 0) + 1
            session.value.rtcm_bytes = (session.value.rtcm_bytes || 0) + ((evt.event_data && evt.event_data.size) || 0)
            if (evt.event_data && !evt.event_data.crc_valid) session.value.rtcm_crc_errors = (session.value.rtcm_crc_errors || 0) + 1
          } else if (evt.event_type === 'gga') {
            session.value.gga_events = (session.value.gga_events || 0) + 1
          } else if (evt.event_type === 'network' && evt.event_data) {
            session.value.retransmissions = (session.value.retransmissions || 0) + evt.event_data.retransmissions
            session.value.tcp_resets = (session.value.tcp_resets || 0) + evt.event_data.tcp_resets
            if (evt.event_data.avg_rtt_us > 0) session.value.avg_rtt_ms = evt.event_data.avg_rtt_us / 1000.0
          }
        }
      } else if (msg.type === 'session_update') {
        session.value = msg.data
        if (session.value && session.value.closed) { liveDuration.value = session.value.duration_ms || liveDuration.value; clearInterval(durationTimer); durationTimer = null; closeWebSocket() }
      }
    } catch (e) { console.error('WS parse error', e) }
  }
  socket.onclose = () => { wsConnected.value = false; if (session.value && !session.value.closed) setTimeout(connectWebSocket, 3000) }
  socket.onerror = () => { socket.close() }
}

const closeWebSocket = () => { if (socket) { socket.close(); socket = null }; wsConnected.value = false }

onMounted(async () => {
  loading.value = true
  try {
    const [sessResp, evtsResp] = await Promise.all([getSession(route.params.id), getSessionEvents(route.params.id)])
    session.value = sessResp.data
    events.value = (evtsResp.data.items || []).sort((a, b) => a.timestamp_ns - b.timestamp_ns)
    if (session.value) liveDuration.value = session.value.duration_ms || 0
    startDurationTimer()
    connectWebSocket()
  } catch (e) { console.error('Failed to load session:', e) }
  finally { loading.value = false }
})

onUnmounted(() => { closeWebSocket(); if (durationTimer) { clearInterval(durationTimer); durationTimer = null } })
</script>

<template>
  <div class="ntrip-session" v-loading="loading">
    <!-- ── Top bar ── -->
    <div class="top-bar">
      <el-button @click="router.push('/sessions')" link><el-icon><ArrowLeft /></el-icon> Back to Sessions</el-button>
      <div class="top-right">
        <el-tag :type="wsConnected ? 'success' : 'warning'" size="small" effect="plain">{{ wsConnected ? 'Live' : 'Disconnected' }}</el-tag>
        <el-button type="primary" size="small" @click="router.push(`/sessions/${route.params.id}/report`)">View Report</el-button>
      </div>
    </div>

    <template v-if="session">
      <!-- ── Truncation banner ── -->
      <el-alert
        v-if="truncationNotice"
        :type="truncationNotice.severity"
        :title="truncationNotice.text"
        show-icon
        :closable="false"
        class="truncation-banner"
      />

      <!-- ── Session identity card ── -->
      <el-card class="identity-card" :style="{ borderLeft: '4px solid ' + identityBorderColor }">
        <div class="identity-row">
          <div class="identity-main">
            <h2>{{ session.username || 'anonymous' }}@{{ session.mountpoint }}</h2>
            <el-tag :type="session.closed ? 'info' : 'success'" size="large">{{ session.closed ? 'Closed' : 'Active' }}</el-tag>
            <span class="score-badge" :style="{ color: scoreColor(session.score) }">{{ session.score }}/100</span>
          </div>
          <div class="identity-meta">
            <span>{{ session.server_pod || '-' }} ({{ session.node_name || '-' }})</span>
            <span>Started: {{ session.start_time ? new Date(session.start_time).toLocaleString() : '-' }}</span>
            <span>Duration: {{ formatDuration(liveDuration) }}</span>
          </div>
        </div>
      </el-card>

      <!-- ── Handshake band ── -->
      <el-card class="handshake-card" v-if="handshakeEvents.length > 0">
        <template #header><span class="section-title">Handshake</span></template>
        <div class="handshake-row">
          <el-tag
            v-for="(evt, i) in handshakeEvents"
            :key="i"
            :type="evt.event_type === 'auth' && evt.event_data?.success ? 'success' : evt.event_type === 'auth' ? 'danger' : 'info'"
            size="small"
            class="hs-tag"
          >
            <strong>{{ evt.event_type === 'auth' ? 'AUTH' : evt.event_type.toUpperCase() }}</strong>
            {{ formatTimestamp(evt.timestamp_ns) }}
            <template v-if="evt.event_data">
              <span v-if="evt.event_data.method"> &middot; {{ evt.event_data.method }}</span>
              <span v-if="evt.event_data.mountpoint"> /{{ evt.event_data.mountpoint }}</span>
              <span v-if="evt.event_data.http_status"> &middot; HTTP {{ evt.event_data.http_status }}</span>
              <span v-if="evt.event_data.success !== undefined"> &middot; {{ evt.event_data.success ? 'OK' : 'FAIL' }}</span>
            </template>
          </el-tag>
        </div>
      </el-card>

      <!-- ── Dual data-stream columns ── -->
      <el-row :gutter="12" class="stream-row">
        <!-- ── ▲ Uplink: GGA ── -->
        <el-col :span="12">
          <el-card class="stream-card uplink" shadow="never">
            <template #header>
              <div class="stream-header">
                <span class="direction-title uplink">▲ GGA Uplink — Client → Caster</span>
                <el-tag size="small" type="primary">{{ ggaTotal.toLocaleString() }} events</el-tag>
              </div>
            </template>

            <el-empty v-if="ggaEvents.length === 0" description="No GGA data" :image-size="48" />

            <table v-else class="stream-table">
              <thead>
                <tr><th>Time</th><th>Fix</th><th>Sats</th><th>HDOP</th><th>Position</th></tr>
              </thead>
              <tbody>
                <tr v-for="(evt, i) in ggaEvents" :key="'g'+i">
                  <td class="cell-time">{{ formatTimestamp(evt.timestamp_ns) }}</td>
                  <td>{{ ggaFixLabel(ggaData(evt).fix_quality) }}</td>
                  <td>{{ ggaData(evt).num_satellites ?? '-' }}</td>
                  <td>{{ ggaData(evt).hdop?.toFixed(1) ?? '-' }}</td>
                  <td class="cell-pos">
                    {{ ggaData(evt).latitude?.toFixed(6) ?? '?' }}, {{ ggaData(evt).longitude?.toFixed(6) ?? '?' }}
                  </td>
                </tr>
              </tbody>
            </table>

            <div v-if="ggaOverflow > 0" class="overflow-hint">
              Showing latest {{ MAX_INLINE_ROWS }} of {{ ggaTotal.toLocaleString() }} GGA events
            </div>
          </el-card>
        </el-col>

        <!-- ── ▼ Downlink: RTCM ── -->
        <el-col :span="12">
          <el-card class="stream-card downlink" shadow="never">
            <template #header>
              <div class="stream-header">
                <span class="direction-title downlink">▼ RTCM Downlink — Caster → Client</span>
                <el-tag size="small" type="success">{{ rtcmTotal.toLocaleString() }} frames</el-tag>
              </div>
            </template>

            <el-empty v-if="rtcmEvents.length === 0" description="No RTCM data" :image-size="48" />

            <table v-else class="stream-table">
              <thead>
                <tr><th>Time</th><th>Msg</th><th>Size</th><th>CRC</th><th>Interval</th></tr>
              </thead>
              <tbody>
                <tr v-for="(evt, i) in rtcmEvents" :key="'r'+i" :class="{ crcFail: !rtcmData(evt).crc_valid }">
                  <td class="cell-time">{{ formatTimestamp(evt.timestamp_ns) }}</td>
                  <td>{{ rtcmData(evt).message_type ?? '-' }}</td>
                  <td>{{ rtcmData(evt).size ?? '-' }}B</td>
                  <td :class="rtcmData(evt).crc_valid ? 'crc-ok' : 'crc-fail'">
                    {{ rtcmData(evt).crc_valid ? '✓' : '✗' }}
                  </td>
                  <td>{{ rtcmData(evt).interval_ms ? (rtcmData(evt).interval_ms < 1000 ? rtcmData(evt).interval_ms+'ms' : (rtcmData(evt).interval_ms/1000).toFixed(1)+'s') : '-' }}</td>
                </tr>
              </tbody>
            </table>

            <div v-if="rtcmOverflow > 0" class="overflow-hint">
              Showing latest {{ MAX_INLINE_ROWS }} of {{ rtcmTotal.toLocaleString() }} RTCM frames
            </div>
          </el-card>
        </el-col>
      </el-row>

      <!-- ── Session stats ── -->
      <el-row :gutter="12" class="stats-row">
        <el-col :span="6" v-for="stat in sessionStats" :key="stat.label">
          <el-card shadow="never" class="stat-card">
            <div class="stat-value">{{ stat.value }}</div>
            <div class="stat-label">{{ stat.label }}</div>
            <div class="stat-detail" v-if="stat.detail">{{ stat.detail }}</div>
          </el-card>
        </el-col>
      </el-row>

      <!-- ── Disconnect reason (if closed) ── -->
      <el-card class="close-card" v-if="session.closed && session.disconnect_reason">
        <div class="close-info">
          <el-icon><CircleClose /></el-icon>
          <span><strong>Disconnect:</strong> {{ session.disconnect_reason }}</span>
          <span v-if="session.disconnect_detail">— {{ session.disconnect_detail }}</span>
        </div>
      </el-card>
    </template>
  </div>
</template>

<style scoped>
.ntrip-session { padding: 8px; max-width: 1400px; }

/* ── Top bar ── */
.top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.top-right { display: flex; align-items: center; gap: 8px; }

/* ── Identity ── */
.identity-card { margin-bottom: 10px; transition: border-left-color 0.5s ease; }
.truncation-banner { margin-bottom: 10px; transition: opacity 0.4s ease; }
.identity-row { display: flex; flex-direction: column; gap: 8px; }
.identity-main { display: flex; align-items: center; gap: 12px; }
.identity-main h2 { margin: 0; font-size: 20px; }
.score-badge { font-size: 26px; font-weight: 700; margin-left: auto; }
.identity-meta { display: flex; gap: 20px; color: #909399; font-size: 13px; }

/* ── Handshake ── */
.handshake-card { margin-bottom: 10px; }
.handshake-row { display: flex; flex-wrap: wrap; gap: 8px; }
.hs-tag { font-family: 'SF Mono', monospace; font-size: 12px; }
.section-title { font-size: 13px; font-weight: 700; color: #303133; text-transform: uppercase; letter-spacing: 0.5px; }

/* ── Data-stream columns ── */
.stream-row { margin-bottom: 10px; }
.stream-card { height: 100%; }
.stream-header { display: flex; justify-content: space-between; align-items: center; }
.direction-title { font-weight: 700; font-size: 13px; }
.direction-title.uplink { color: #409eff; }
.direction-title.downlink { color: #67c23a; }

.stream-table { width: 100%; font-size: 12px; border-collapse: collapse; font-family: 'SF Mono', 'Fira Code', monospace; }
.stream-table thead { position: sticky; top: 0; }
.stream-table th { text-align: left; padding: 4px 6px; background: #f5f7fa; font-weight: 600; font-size: 11px; text-transform: uppercase; color: #606266; border-bottom: 1px solid #e4e7ed; }
.stream-table td { padding: 3px 6px; border-bottom: 1px solid #f0f0f0; white-space: nowrap; }
.stream-table tr:hover { background: #fafafa; }
.cell-time { color: #909399; font-size: 11px; }
.cell-pos { font-size: 11px; color: #606266; }
.crc-ok { color: #67c23a; font-weight: 700; }
.crc-fail { color: #f56c6c; font-weight: 700; }
tr.crcFail { background: #fff5f5; }

.overflow-hint { text-align: center; color: #c0c4cc; font-size: 11px; padding: 6px 0 2px; }

/* ── Stats ── */
.stats-row { margin-bottom: 10px; }
.stat-card { text-align: center; padding: 4px; }
.stat-value { font-size: 22px; font-weight: 700; }
.stat-label { font-size: 12px; color: #909399; margin-top: 2px; }
.stat-detail { font-size: 11px; color: #c0c4cc; margin-top: 2px; }

/* ── Disconnect ── */
.close-card { margin-bottom: 10px; }
.close-info { display: flex; gap: 8px; align-items: center; color: #909399; font-size: 13px; }
</style>
