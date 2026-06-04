<script setup>
import { ref, onMounted, computed } from 'vue'
import { listSessions } from '../api'

const sessions = ref([])
const loading = ref(false)

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
    // Also flag sessions with low scores.
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

onMounted(async () => {
  loading.value = true
  try {
    // Fetch all closed sessions to find issues.
    const { data } = await listSessions({ limit: 500 })
    sessions.value = data.items || []
  } catch (e) {
    console.error('Failed to load sessions:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="alerts-view">
    <h2>Alerts &amp; Anomalies</h2>

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
h2 { margin: 0 0 16px 0; }
</style>
