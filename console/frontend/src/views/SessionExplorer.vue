<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { listSessions, listTasks, deleteSession } from '../api'
import { useWebSocket } from '../composables/useWebSocket'
import { ElMessage, ElMessageBox } from 'element-plus'
import { classifySession } from '../utils/sessionFlags'
import { sessionRowStyle, scoreColor, flagLabel, sessionRowClass } from '../utils/sessionColors'
import { computeFilterMatches, filterColor, disabledFilterColor, filterLabel } from '../utils/filterMatcher'

const sessions = ref([])
const tasks = ref([])
const loading = ref(false)
const router = useRouter()

const filters = ref({
  mountpoint: '',
  username: '',
  min_score: null,
  closed: null,
})

// ---- Session classification (reactive) ----
const classifications = computed(() => {
  const map = {}
  for (const s of sessions.value) map[s.session_id] = classifySession(s)
  return map
})

// ---- Filter statistics (reactive to tasks + sessions) ----
const activeFilters = computed(() => tasks.value.filter(t => t.status === 'running'))

const filterStats = computed(() => computeFilterMatches(activeFilters.value, sessions.value))

// ---- Helpers ----
const rowClassName = ({ row }) => {
  if (!row) return ''
  const flags = classifications.value[row.session_id]
  if (!flags) return ''
  if (flags.problematic) return 'row-problematic'
  if (flags.truncated) return 'row-truncated'
  if (flags.anomalous) return 'row-anomalous'
  return ''
}

const formatDuration = (ms) => {
  if (!ms) return '-'
  if (ms < 60000) return (ms / 1000).toFixed(1) + 's'
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return `${m}m${s}s`
}

const loadSessions = async () => {
  loading.value = true
  try {
    const params = {}
    if (filters.value.mountpoint) params.mountpoint = filters.value.mountpoint
    if (filters.value.username) params.username = filters.value.username
    if (filters.value.min_score != null) params.min_score = filters.value.min_score
    if (filters.value.closed != null) params.closed = filters.value.closed
    const [sResp, tResp] = await Promise.all([
      listSessions(params),
      listTasks(),
    ])
    sessions.value = sResp.data.items || []
    tasks.value = tResp.data.items || []
  } catch (e) {
    console.error('Failed to load sessions:', e)
  } finally {
    loading.value = false
  }
}

const goDetail = (id) => { router.push(`/sessions/${id}`) }

const handleDelete = async (id) => {
  try {
    await ElMessageBox.confirm(`Delete session ${id}?`, 'Confirm', { type: 'warning', confirmButtonText: 'Delete' })
    await deleteSession(id)
    sessions.value = sessions.value.filter(s => s.session_id !== id)
    ElMessage.success('Deleted')
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error('Failed to delete')
  }
}

// ---- WebSocket (unchanged mechanics, added stats reactive sync) ----
const wsUrl = () => {
  const p = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${p}//${window.location.host}/api/v1/ws/sessions`
}
useWebSocket(wsUrl, {
  onMessage(msg) {
    if (!msg.data) return
    const session = msg.data
    if (msg.type === 'session_list_closed') {
      const idx = sessions.value.findIndex(s => s.session_id === session.session_id)
      if (idx !== -1) sessions.value[idx] = { ...sessions.value[idx], ...session, closed: true }
    } else if (msg.type === 'session_list_deleted') {
      sessions.value = sessions.value.filter(s => s.session_id !== session.session_id)
    } else if (msg.type === 'session_list_updated') {
      const idx = sessions.value.findIndex(s => s.session_id === session.session_id)
      if (idx !== -1) sessions.value[idx] = { ...sessions.value[idx], ...session }
      else sessions.value.unshift(session)
    }
  },
  autoReconnect: true,
  reconnectInterval: 5000,
})

onMounted(loadSessions)
</script>

<template>
  <div class="session-explorer">
    <div class="view-header">
      <h2>Session Explorer</h2>
    </div>

    <!-- Search filters -->
    <el-form :inline="true" class="filter-bar" @submit.prevent="loadSessions">
      <el-form-item label="Mountpoint">
        <el-input v-model="filters.mountpoint" placeholder="MOUNT-A" clearable />
      </el-form-item>
      <el-form-item label="Username">
        <el-input v-model="filters.username" placeholder="user001" clearable />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="loadSessions"><el-icon><Search /></el-icon> Filter</el-button>
      </el-form-item>
    </el-form>

    <!-- Active filter statistics -->
    <div class="filter-stats" v-if="activeFilters.length > 0">
      <div
        v-for="(f, idx) in activeFilters"
        :key="f.id"
        class="filter-stat-item"
        :style="{ borderColor: filterStats.get(f.id) ? filterColor(f.id, idx, filterStats.get(f.id).matchRate).dot : disabledFilterColor().dot }"
      >
        <span
          class="filter-dot-stat"
          :style="{ backgroundColor: filterStats.get(f.id) ? filterColor(f.id, idx, filterStats.get(f.id).matchRate).dot : disabledFilterColor().dot }"
        />
        <span class="filter-stat-label">{{ filterLabel(f) }}</span>
        <span
          class="filter-stat-rate"
          :style="{ color: filterStats.get(f.id) ? filterColor(f.id, idx, filterStats.get(f.id).matchRate).accent : '#c0c4cc' }"
        >
          {{ filterStats.get(f.id) ? (filterStats.get(f.id).matchRate * 100).toFixed(0) + '%' : '—' }}
        </span>
        <span class="filter-stat-count">{{ filterStats.get(f.id)?.matchCount || 0 }} of {{ sessions.length }}</span>
      </div>
    </div>

    <!-- Session table -->
    <el-table
      :data="sessions"
      v-loading="loading"
      stripe
      :row-class-name="rowClassName"
      class="session-table"
    >
      <el-table-column label="Flags" width="90" align="center">
        <template #default="{ row }">
          <div class="flag-chips">
            <span
              v-if="classifications[row.session_id]?.problematic"
              class="flag-chip problematic"
              :title="flagLabel('problematic').title"
            >NO-RTCM</span>
            <span
              v-else-if="classifications[row.session_id]?.truncated"
              class="flag-chip truncated"
              :title="flagLabel('truncated').title"
            >TRUNC</span>
            <span
              v-else-if="classifications[row.session_id]?.anomalous"
              class="flag-chip anomalous"
              :title="flagLabel('anomalous').title"
            >ANOM</span>
          </div>
        </template>
      </el-table-column>

      <el-table-column prop="session_id" label="Session ID" min-width="180" show-overflow-tooltip />
      <el-table-column prop="mountpoint" label="Mountpoint" width="130" />
      <el-table-column prop="username" label="User" width="110" />
      <el-table-column prop="server_pod" label="Pod" width="130" />

      <el-table-column label="Filters" width="80" align="center">
        <template #default="{ row }">
          <div class="filter-indicators" v-if="activeFilters.length > 0">
            <span
              v-for="(f, idx) in activeFilters"
              :key="f.id"
              class="filter-dot"
              :class="{ matched: filterStats.get(f.id)?.matches?.has(row.session_id), unmatched: !filterStats.get(f.id)?.matches?.has(row.session_id) }"
              :style="{ backgroundColor: filterStats.get(f.id) ? filterColor(f.id, idx, filterStats.get(f.id).matchRate).dot : disabledFilterColor().dot }"
            />
          </div>
        </template>
      </el-table-column>

      <el-table-column prop="score" label="Score" width="85" align="center">
        <template #default="{ row }">
          <span class="score-badge" :style="scoreColor(row.score)">{{ row.score }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="duration_ms" label="Duration" width="95" align="center">
        <template #default="{ row }">{{ formatDuration(row.duration_ms) }}</template>
      </el-table-column>
      <el-table-column prop="closed" label="Status" width="85" align="center">
        <template #default="{ row }">
          <el-tag :type="row.closed ? 'info' : 'success'" size="small">{{ row.closed ? 'Closed' : 'Active' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Actions" width="85" align="center">
        <template #default="{ row }">
          <el-button size="small" circle @click.stop="goDetail(row.session_id)"><el-icon><View /></el-icon></el-button>
          <el-button size="small" type="danger" circle style="margin-left:4px" @click.stop="handleDelete(row.session_id)"><el-icon><Delete /></el-icon></el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<style scoped>
.session-explorer { padding: 8px; }
.view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
h2 { margin: 0; }
.filter-bar { margin-bottom: 10px; }

/* ---- Filter statistics ---- */
.filter-stats { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
.filter-stat-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 14px;
  border: 1px solid;
  font-size: 12px;
  transition: border-color 0.6s ease;
}
.filter-dot-stat {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  transition: background-color 0.6s ease;
}
.filter-stat-label { font-weight: 600; color: #303133; }
.filter-stat-rate { font-weight: 700; transition: color 0.4s ease; }
.filter-stat-count { color: #909399; font-size: 11px; }

/* ---- Row coloring (CSS classes applied by rowClassName) ---- */
:deep(.row-problematic) {
  transition: background-color 0.4s ease, border-left-color 0.4s ease;
  border-left: 3px solid hsl(350, 75%, 53%) !important;
  background: hsla(350, 75%, 53%, 0.04) !important;
}
:deep(.row-truncated) {
  transition: background-color 0.4s ease, border-left-color 0.4s ease;
  border-left: 3px solid hsl(30, 80%, 60%) !important;
  background: hsla(30, 80%, 60%, 0.04) !important;
}
:deep(.row-anomalous) {
  transition: background-color 0.4s ease, border-left-color 0.4s ease;
  border-left: 3px solid hsl(40, 90%, 50%) !important;
  background: hsla(40, 90%, 50%, 0.04) !important;
}

/* ---- Flag chips ---- */
.flag-chips { display: flex; gap: 3px; justify-content: center; }
.flag-chip {
  font-size: 10px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 3px;
  letter-spacing: 0.3px;
  transition: opacity 0.3s ease, transform 0.2s ease;
  cursor: default;
}
.flag-chip.problematic { background: hsl(350, 75%, 53%); color: white; }
.flag-chip.truncated   { background: hsl(30, 80%, 55%); color: white; }
.flag-chip.anomalous   { background: hsl(40, 90%, 45%); color: white; }

/* ---- Filter dots ---- */
.filter-indicators { display: flex; gap: 4px; justify-content: center; }
.filter-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  transition: background-color 0.6s ease, opacity 0.6s ease, transform 0.3s ease;
}
.filter-dot.matched { opacity: 1; transform: scale(1.15); }
.filter-dot.unmatched { opacity: 0.25; }

/* ---- Score badge ---- */
.score-badge { font-weight: 700; font-size: 14px; transition: color 0.5s ease; }

/* ---- Table ---- */
.session-table { cursor: default; }
</style>
