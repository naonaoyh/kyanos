<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { listSessions, deleteSession } from '../api'
import { useWebSocket } from '../composables/useWebSocket'
import { ElMessage, ElMessageBox } from 'element-plus'

const sessions = ref([])
const loading = ref(false)
const router = useRouter()

const filters = ref({
  mountpoint: '',
  username: '',
  min_score: null,
  closed: null,
})

const scoreColor = (score) => {
  if (score >= 80) return 'success'
  if (score >= 60) return 'warning'
  return 'danger'
}

const formatTime = (ns) => {
  if (!ns) return '-'
  return new Date(ns / 1e6).toLocaleString()
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
    const { data } = await listSessions(params)
    sessions.value = data.items || []
  } catch (e) {
    console.error('Failed to load sessions:', e)
  } finally {
    loading.value = false
  }
}

const goDetail = (id) => {
  router.push(`/sessions/${id}`)
}

const handleDelete = async (id) => {
  try {
    await ElMessageBox.confirm(
      `Delete session ${id}? This cannot be undone.`,
      'Confirm',
      { type: 'warning', confirmButtonText: 'Delete', cancelButtonText: 'Cancel' }
    )
    await deleteSession(id)
    sessions.value = sessions.value.filter(s => s.session_id !== id)
    ElMessage.success(`Session ${id} deleted`)
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error('Failed to delete session')
  }
}

// WebSocket for real-time session list updates
const wsUrl = () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/api/v1/ws/sessions`
}

useWebSocket(wsUrl, {
  onMessage(msg) {
    if (!msg.data) return
    const session = msg.data

    if (msg.type === 'session_list_closed') {
      const idx = sessions.value.findIndex(s => s.session_id === session.session_id)
      if (idx !== -1) {
        sessions.value[idx] = { ...sessions.value[idx], ...session, closed: true }
      }
    } else if (msg.type === 'session_list_deleted') {
      sessions.value = sessions.value.filter(s => s.session_id !== session.session_id)
    } else if (msg.type === 'session_list_updated') {
      const idx = sessions.value.findIndex(s => s.session_id === session.session_id)
      if (idx !== -1) {
        sessions.value[idx] = { ...sessions.value[idx], ...session }
      } else {
        sessions.value.unshift(session)
      }
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

    <el-form :inline="true" class="filter-bar" @submit.prevent="loadSessions">
      <el-form-item label="Mountpoint">
        <el-input v-model="filters.mountpoint" placeholder="MOUNT-A" clearable />
      </el-form-item>
      <el-form-item label="Username">
        <el-input v-model="filters.username" placeholder="user001" clearable />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="loadSessions">
          <el-icon><Search /></el-icon> Filter
        </el-button>
      </el-form-item>
    </el-form>

    <el-table
      :data="sessions"
      v-loading="loading"
      stripe
      class="session-table"
    >
      <el-table-column prop="session_id" label="Session ID" min-width="200" show-overflow-tooltip />
      <el-table-column prop="mountpoint" label="Mountpoint" width="140" />
      <el-table-column prop="username" label="User" width="120" />
      <el-table-column prop="server_pod" label="Server Pod" width="140" />
      <el-table-column prop="score" label="Score" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="scoreColor(row.score)" size="small">{{ row.score }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="duration_ms" label="Duration" width="100" align="center">
        <template #default="{ row }">{{ formatDuration(row.duration_ms) }}</template>
      </el-table-column>
      <el-table-column prop="closed" label="Status" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="row.closed ? 'info' : 'success'" size="small">
            {{ row.closed ? 'Closed' : 'Active' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Actions" width="80" align="center">
        <template #default="{ row }">
          <el-tooltip content="Delete session" placement="top">
            <el-button size="small" type="danger" :icon="Delete" circle @click.stop="handleDelete(row.session_id)" />
          </el-tooltip>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<style scoped>
.session-explorer { padding: 8px; }
.view-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
h2 { margin: 0; }
.filter-bar { margin-bottom: 16px; }
.clickable-row { cursor: pointer; }
</style>
