<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getSession, getSessionEvents } from '../api'
import EventTimeline from '../components/EventTimeline.vue'

const route = useRoute()
const router = useRouter()
const session = ref(null)
const events = ref([])
const loading = ref(false)

const sessionStats = computed(() => {
  if (!session.value) return null
  const s = session.value
  return [
    { label: 'GGA Events', value: s.gga_events, icon: 'Location' },
    { label: 'RTCM Frames', value: s.rtcm_frames, icon: 'Document' },
    { label: 'Retransmissions', value: s.retransmissions, icon: 'RefreshRight' },
    { label: 'Avg RTT', value: s.avg_rtt_ms ? s.avg_rtt_ms.toFixed(1) + 'ms' : '-', icon: 'Timer' },
    { label: 'CRC Errors', value: s.rtcm_crc_errors, icon: 'Warning' },
    { label: 'TCP Resets', value: s.tcp_resets, icon: 'Close' },
  ]
})

const scoreColor = (score) => {
  if (score >= 80) return '#67c23a'
  if (score >= 60) return '#e6a23c'
  return '#f56c6c'
}

const formatDuration = (ms) => {
  if (!ms) return '-'
  const h = Math.floor(ms / 3600000)
  const m = Math.floor((ms % 3600000) / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  if (h > 0) return `${h}h${m}m${s}s`
  if (m > 0) return `${m}m${s}s`
  return `${s}s`
}

onMounted(async () => {
  loading.value = true
  try {
    const [sessResp, evtsResp] = await Promise.all([
      getSession(route.params.id),
      getSessionEvents(route.params.id),
    ])
    session.value = sessResp.data
    events.value = evtsResp.data.items || []
  } catch (e) {
    console.error('Failed to load session:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="session-detail" v-loading="loading">
    <div class="view-header">
      <el-button @click="router.push('/sessions')" link>
        <el-icon><ArrowLeft /></el-icon> Back to Sessions
      </el-button>
      <el-button
        type="primary"
        size="small"
        @click="router.push(`/sessions/${route.params.id}/report`)"
      >
        View Report
      </el-button>
    </div>

    <template v-if="session">
      <el-card class="session-header">
        <div class="session-title">
          <h2>{{ session.username || 'anonymous' }}@{{ session.mountpoint }}</h2>
          <el-tag :type="session.closed ? 'info' : 'success'" size="large">
            {{ session.closed ? 'Closed' : 'Active' }}
          </el-tag>
        </div>
        <div class="session-meta">
          <span>{{ session.server_pod }} ({{ session.node_name }})</span>
          <span>Started: {{ new Date(session.start_time).toLocaleString() }}</span>
          <span>Duration: {{ formatDuration(session.duration_ms) }}</span>
        </div>
        <div class="session-score" :style="{ color: scoreColor(session.score) }">
          {{ session.score }}/100
        </div>
      </el-card>

      <el-row :gutter="16" class="stats-row">
        <el-col :span="4" v-for="stat in sessionStats" :key="stat.label">
          <el-card shadow="never" class="stat-card">
            <div class="stat-value">{{ stat.value ?? '-' }}</div>
            <div class="stat-label">{{ stat.label }}</div>
          </el-card>
        </el-col>
      </el-row>

      <el-card class="timeline-card">
        <template #header>
          <span>Event Timeline ({{ events.length }} events)</span>
        </template>
        <EventTimeline :events="events" />
      </el-card>
    </template>
  </div>
</template>

<style scoped>
.session-detail { padding: 8px; }
.view-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.session-header { margin-bottom: 16px; }
.session-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
.session-title h2 { margin: 0; }
.session-meta {
  display: flex;
  gap: 24px;
  color: #909399;
  font-size: 13px;
  margin-top: 8px;
}
.session-score {
  position: absolute;
  top: 16px;
  right: 20px;
  font-size: 28px;
  font-weight: 700;
}
.stats-row { margin-bottom: 16px; }
.stat-card { text-align: center; }
.stat-value { font-size: 20px; font-weight: 700; }
.stat-label { font-size: 12px; color: #909399; margin-top: 4px; }
.timeline-card { margin-top: 8px; }
</style>
