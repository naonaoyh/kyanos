<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { getSessionReport } from '../api'

const route = useRoute()
const report = ref(null)
const loading = ref(false)
const rawHtml = ref('')

const verdictType = (v) => {
  const map = { HEALTHY: 'success', DEGRADED: 'warning', POOR: 'warning', CRITICAL: 'danger' }
  return map[v] || 'info'
}

const statusIcon = (s) => {
  if (s === 'pass') return 'CircleCheckFilled'
  if (s === 'warn') return 'WarningFilled'
  return 'CircleCloseFilled'
}

const statusColor = (s) => {
  if (s === 'pass') return '#67c23a'
  if (s === 'warn') return '#e6a23c'
  return '#f56c6c'
}

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await getSessionReport(route.params.id, 'json')
    report.value = data
  } catch (e) {
    console.error('Failed to load report:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="report-view" v-loading="loading">
    <template v-if="report">
      <div class="report-header">
        <h2>Diagnostic Report</h2>
        <el-tag :type="verdictType(report.verdict)" size="large" effect="dark">
          {{ report.verdict }} — Score: {{ report.score }}/100
        </el-tag>
      </div>

      <el-descriptions :column="2" border class="report-meta">
        <el-descriptions-item label="Session ID">{{ report.session_id }}</el-descriptions-item>
        <el-descriptions-item label="Mountpoint">{{ report.mountpoint }}</el-descriptions-item>
        <el-descriptions-item label="Username">{{ report.username }}</el-descriptions-item>
        <el-descriptions-item label="NTRIP Version">{{ report.ntrip_version }}</el-descriptions-item>
        <el-descriptions-item label="Client">{{ report.client_addr }}</el-descriptions-item>
        <el-descriptions-item label="Server Pod">{{ report.server_pod }}</el-descriptions-item>
        <el-descriptions-item label="Node">{{ report.node_name }}</el-descriptions-item>
        <el-descriptions-item label="Duration">{{ report.duration }}</el-descriptions-item>
      </el-descriptions>

      <h3 style="margin-top: 24px;">Diagnostic Dimensions</h3>

      <el-card
        v-for="dim in report.dimensions"
        :key="dim.name"
        class="dimension-card"
        shadow="hover"
      >
        <div class="dim-header">
          <div>
            <el-icon :color="statusColor(dim.status)" :size="18">
              <component :is="statusIcon(dim.status)" />
            </el-icon>
            <strong>{{ dim.name }}</strong>
          </div>
          <el-tag
            :type="dim.status === 'pass' ? 'success' : dim.status === 'warn' ? 'warning' : 'danger'"
            size="small"
          >
            {{ dim.score }}/{{ dim.max_score }}
          </el-tag>
        </div>

        <el-row :gutter="12" class="metrics-row">
          <el-col :span="6" v-for="(value, key) in dim.metrics" :key="key">
            <div class="metric">
              <span class="metric-key">{{ key }}</span>
              <span class="metric-value">{{ value }}</span>
            </div>
          </el-col>
        </el-row>

        <div v-if="dim.findings && dim.findings.length" class="findings">
          <div v-for="(f, i) in dim.findings" :key="i" class="finding">
            <el-icon><Warning /></el-icon> {{ f }}
          </div>
        </div>
      </el-card>

      <template v-if="report.issues && report.issues.length">
        <h3 style="margin-top: 24px;">Issues</h3>
        <el-alert
          v-for="(issue, i) in report.issues"
          :key="i"
          :title="`[${issue.category}] ${issue.description}`"
          :type="issue.severity === 'error' ? 'error' : 'warning'"
          :closable="false"
          show-icon
          class="issue-alert"
        />
      </template>
    </template>
  </div>
</template>

<style scoped>
.report-view { padding: 8px; max-width: 900px; }
.report-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.report-header h2 { margin: 0; }
.dimension-card { margin-bottom: 12px; }
.dim-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  font-size: 15px;
}
.metrics-row { margin-bottom: 8px; }
.metric {
  font-size: 13px;
  padding: 4px 0;
}
.metric-key { color: #909399; margin-right: 4px; }
.metric-value { font-weight: 600; }
.findings { margin-top: 8px; }
.finding {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #b45309;
  font-size: 13px;
  padding: 2px 0;
}
.issue-alert { margin-bottom: 8px; }
</style>
