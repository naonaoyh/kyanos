<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { listSessions } from '../api'

const sessions = ref([])
const loading = ref(false)
const lastUpdated = ref(null)
const previousAlertCount = ref(0)
const hasNewAlerts = ref(false)
let pollTimer = null

const alerts = computed(() => {
  const result = []
  for (const s of sessions.value) {
    if (s.issues) {
      for (const issue of s.issues) {
        result.push({
          session_id: s.session_id,
          mountpoint: s.mountpoint,
          username: s.username,
          server_pod: s.server_pod,
          score: s.score,
          ...issue,
        })
      }
    }
    if (s.score < 60 && (!s.issues || s.issues.length === 0)) {
      result.push({
        session_id: s.session_id,
        mountpoint: s.mountpoint,
        username: s.username,
        server_pod: s.server_pod,
        score: s.score,
        category: 'overall',
        severity: s.score < 40 ? 'critical' : 'warning',
        description: `Low diagnostic score: ${s.score}/100`,
      })
    }
  }
  return result
})

const alertSummary = computed(() => {
  const critical = alerts.value.filter(a => a.severity === 'critical' || a.severity === 'error').length
  const warning = alerts.value.filter(a => a.severity === 'warning').length
  return { critical, warning, total: alerts.value.length }
})

watch(() => alerts.value.length, (newCount) => {
  if (previousAlertCount.value > 0 && newCount > previousAlertCount.value) {
    hasNewAlerts.value = true
    setTimeout(() => { hasNewAlerts.value = false }, 5000)
  }
  previousAlertCount.value = newCount
})

const severityType = (sev) => {
  switch (sev) {
    case 'critical':
    case 'error':
      return 'danger'
    case 'warning':
      return 'warning'
    default:
      return 'info'
  }
}

const loadSessions = async () => {
  try {
    const { data } = await listSessions({ limit: 500 })
    sessions.value = data.items || []
    lastUpdated.value = new Date()
  } catch (e) {
    console.error('Failed to load sessions:', e)
  }
}

onMounted(async () => {
  loading.value = true
  await loadSessions()
  loading.value = false
  pollTimer = setInterval(loadSessions, 15000)
})

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<template>
  <div class="alerts-view">
    <div class="view-header">
      <h2>Alerts &amp; Anomalies</h2>
      <div class="header-right">
        <transition name="fade">
          <el-tag v-if="hasNewAlerts" type="danger" size="small" effect="dark" class="new-alert-badge">
            New alerts
          </el-tag>
        </transition>
        <span class="last-updated" v-if="lastUpdated">
          Updated: {{ lastUpdated.toLocaleTimeString() }}
        </span>
      </div>
    </div>

    <div class="alert-summary" v-if="alerts.length > 0">
      <el-tag type="danger" size="small" v-if="alertSummary.critical">
        {{ alertSummary.critical }} Critical
      </el-tag>
      <el-tag type="warning" size="small" v-if="alertSummary.warning">
        {{ alertSummary.warning }} Warning
      </el-tag>
      <el-tag type="info" size="small">
        {{ alertSummary.total }} Total
      </el-tag>
    </div>

    <el-empty v-if="!loading && alerts.length === 0" description="No alerts" />

    <el-table v-else :data="alerts" v-loading="loading" stripe>
      <el-table-column prop="severity" label="Severity" width="100">
        <template #default="{ row }">
          <el-tag :type="severityType(row.severity)" size="small">
            {{ row.severity }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="category" label="Category" width="120" />
      <el-table-column prop="description" label="Description" min-width="300" show-overflow-tooltip />
      <el-table-column prop="session_id" label="Session" width="200" show-overflow-tooltip />
      <el-table-column prop="mountpoint" label="Mountpoint" width="120" />
      <el-table-column prop="server_pod" label="Pod" width="120" />
      <el-table-column prop="score" label="Score" width="80" align="center" />
    </el-table>
  </div>
</template>

<style scoped>
.alerts-view { padding: 8px; }
.view-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.view-header h2 { margin: 0; }
.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.last-updated { font-size: 12px; color: #909399; }
.new-alert-badge {
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}
.alert-summary {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.5s;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
}
</style>
