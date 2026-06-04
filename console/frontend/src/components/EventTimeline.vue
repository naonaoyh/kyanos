<script setup>
import { ref, computed, watch, nextTick } from 'vue'

const props = defineProps({
  events: { type: Array, default: () => [] },
})

const activeFilter = ref('all') // 'all' | 'auth' | 'gga' | 'rtcm' | 'network' | 'close'
const timelineBody = ref(null)

const filteredEvents = computed(() => {
  if (activeFilter.value === 'all') return props.events
  return props.events.filter(e => e.event_type === activeFilter.value)
})

const eventCounts = computed(() => {
  const counts = { all: props.events.length }
  for (const e of props.events) {
    counts[e.event_type] = (counts[e.event_type] || 0) + 1
  }
  return counts
})

const filterOptions = [
  { key: 'all', label: 'All' },
  { key: 'rtcm', label: 'RTCM' },
  { key: 'gga', label: 'GGA' },
  { key: 'auth', label: 'Auth' },
  { key: 'network', label: 'Net' },
  { key: 'close', label: 'Close' },
]

// Auto-scroll to bottom when new events arrive
watch(() => props.events.length, async () => {
  await nextTick()
  if (timelineBody.value) {
    timelineBody.value.scrollTop = timelineBody.value.scrollHeight
  }
})

const classifyEvent = (type) => {
  switch (type) {
    case 'auth':
    case 'gga':
      return 'uplink'
    case 'rtcm':
      return 'downlink'
    default:
      return 'neutral'
  }
}

const eventIcon = (type) => {
  switch (type) {
    case 'auth': return 'Key'
    case 'gga': return 'Location'
    case 'rtcm': return 'Document'
    case 'network': return 'Connection'
    case 'close': return 'CircleClose'
    default: return 'InfoFilled'
  }
}

const eventColor = (evt) => {
  const dir = classifyEvent(evt.event_type)
  if (dir === 'uplink') return '#409eff'
  if (dir === 'downlink') return '#67c23a'
  return '#909399'
}

const isAnomaly = (evt) => {
  if (evt.event_type === 'rtcm' && evt.event_data && !evt.event_data.crc_valid) return true
  if (evt.event_type === 'close') return true
  if (evt.event_type === 'network' && evt.event_data?.retransmissions > 0) return true
  return false
}

const formatTime = (ns) => {
  const d = new Date(ns / 1e6)
  return d.toISOString().substring(11, 23)
}

const eventDataSummary = (evt) => {
  const d = evt.event_data
  if (!d) return ''
  switch (evt.event_type) {
    case 'auth':
      return `${d.method} ${d.success ? 'OK' : 'FAIL'} ${d.mountpoint || ''} ${d.username || ''}`
    case 'gga':
      return `fix=${d.fix_quality} sats=${d.num_satellites} hdop=${d.hdop}`
    case 'rtcm':
      return `msg ${d.message_type} ${d.size}B ${d.crc_valid ? 'CRC OK' : 'CRC FAIL'}`
    case 'network':
      return `retrans=${d.retransmissions} rtt=${d.avg_rtt_us}us resets=${d.tcp_resets}`
    case 'close':
      return `${d.reason} ${d.detail || ''}`
    default:
      return JSON.stringify(d)
  }
}
</script>

<template>
  <div class="event-timeline">
    <div class="timeline-controls">
      <el-radio-group v-model="activeFilter" size="small">
        <el-radio-button
          v-for="opt in filterOptions"
          :key="opt.key"
          :value="opt.key"
        >
          {{ opt.label }}
          <span class="count-badge" v-if="eventCounts[opt.key]">
            {{ eventCounts[opt.key] }}
          </span>
        </el-radio-button>
      </el-radio-group>
    </div>

    <div class="timeline-header">
      <div class="col-time">Time (UTC)</div>
      <div class="col-uplink">
        <span class="direction-badge uplink">▲ Uplink</span>
      </div>
      <div class="col-downlink">
        <span class="direction-badge downlink">▼ Downlink</span>
      </div>
    </div>

    <div class="timeline-body" ref="timelineBody">
      <div
        v-for="(evt, i) in filteredEvents"
        :key="i"
        class="timeline-row"
        :class="{ anomaly: isAnomaly(evt) }"
      >
        <div class="col-time">{{ formatTime(evt.timestamp_ns) }}</div>
        <div class="col-uplink" v-if="classifyEvent(evt.event_type) === 'uplink'">
          <span class="event-pill" :style="{ borderColor: eventColor(evt) }">
            <el-icon :size="14"><component :is="eventIcon(evt.event_type)" /></el-icon>
            {{ eventDataSummary(evt) }}
          </span>
        </div>
        <div class="col-uplink" v-else></div>
        <div class="col-downlink" v-if="classifyEvent(evt.event_type) === 'downlink'">
          <span class="event-pill down" :style="{ borderColor: eventColor(evt) }">
            <el-icon :size="14"><component :is="eventIcon(evt.event_type)" /></el-icon>
            {{ eventDataSummary(evt) }}
          </span>
        </div>
        <div class="col-downlink" v-else-if="classifyEvent(evt.event_type) === 'neutral'">
          <span class="event-pill neutral" :style="{ borderColor: eventColor(evt) }">
            <el-icon :size="14"><component :is="eventIcon(evt.event_type)" /></el-icon>
            {{ eventDataSummary(evt) }}
          </span>
        </div>
        <div class="col-downlink" v-else></div>
      </div>

      <div v-if="filteredEvents.length === 0" class="empty-timeline">
        No events recorded for this session.
      </div>
    </div>
  </div>
</template>

<style scoped>
.event-timeline {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
}
.timeline-controls {
  margin-bottom: 12px;
}
.count-badge {
  font-size: 10px;
  margin-left: 3px;
  opacity: 0.7;
}
.timeline-header {
  display: grid;
  grid-template-columns: 140px 1fr 1fr;
  gap: 8px;
  padding: 8px 12px;
  background: #f5f7fa;
  border-radius: 4px;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  color: #606266;
  position: sticky;
  top: 0;
  z-index: 1;
}
.timeline-body {
  max-height: 500px;
  overflow-y: auto;
}
.timeline-row {
  display: grid;
  grid-template-columns: 140px 1fr 1fr;
  gap: 8px;
  padding: 4px 12px;
  border-bottom: 1px solid #f0f0f0;
  align-items: center;
  min-height: 32px;
}
.timeline-row:hover { background: #fafafa; }
.timeline-row.anomaly { background: #fff5f5; }
.timeline-row.anomaly:hover { background: #ffe8e8; }
.col-time { color: #909399; font-size: 12px; }
.direction-badge {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}
.direction-badge.uplink { background: #ecf5ff; color: #409eff; }
.direction-badge.downlink { background: #f0f9eb; color: #67c23a; }
.event-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border: 1px solid;
  border-radius: 12px;
  font-size: 12px;
  background: white;
}
.event-pill.down { background: #f0f9eb; }
.event-pill.neutral { background: #f5f7fa; }
.empty-timeline {
  text-align: center;
  color: #c0c4cc;
  padding: 40px;
}
</style>
