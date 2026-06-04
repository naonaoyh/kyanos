<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { listSessions } from '../api'

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
      @row-click="(row) => goDetail(row.session_id)"
      class="session-table"
      row-class-name="clickable-row"
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
.session-table { cursor: pointer; }
</style>
