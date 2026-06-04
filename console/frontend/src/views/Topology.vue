<script setup>
import { ref, onMounted } from 'vue'
import { getTopology } from '../api'

const nodes = ref([])
const loading = ref(false)

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await getTopology()
    nodes.value = data.nodes || []
  } catch (e) {
    console.error('Failed to load topology:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="topology-view">
    <h2>Cluster Topology</h2>

    <el-skeleton :loading="loading" :rows="6" animated>
      <template #default>
        <el-empty v-if="nodes.length === 0" description="No agents connected" />

        <el-row :gutter="16" v-else>
          <el-col
            v-for="node in nodes"
            :key="node.name"
            :xs="24" :sm="12" :md="8" :lg="6"
          >
            <el-card shadow="hover" class="node-card">
              <template #header>
                <div class="node-header">
                  <el-icon :size="20">
                    <component :is="node.connected ? 'CircleCheckFilled' : 'CircleCloseFilled'" />
                  </el-icon>
                  <span class="node-name">{{ node.name }}</span>
                  <el-tag
                    :type="node.connected ? 'success' : 'danger'"
                    size="small"
                  >
                    {{ node.connected ? 'Online' : 'Offline' }}
                  </el-tag>
                </div>
              </template>

              <div class="node-stats">
                <div class="stat" v-if="node.agent_version">
                  <span class="stat-label">Agent</span>
                  <span class="stat-value">{{ node.agent_version }}</span>
                </div>
                <div class="stat">
                  <span class="stat-label">Pods</span>
                  <span class="stat-value">{{ node.pod_count || 0 }}</span>
                </div>
                <div class="stat">
                  <span class="stat-label">Sessions</span>
                  <span class="stat-value">{{ node.active_sessions || 0 }}</span>
                </div>
              </div>

              <div class="pod-list" v-if="node.pods && node.pods.length">
                <el-divider content-position="left">Managed Pods</el-divider>
                <el-tag
                  v-for="pod in node.pods"
                  :key="pod"
                  size="small"
                  type="info"
                  class="pod-tag"
                >
                  {{ pod }}
                </el-tag>
              </div>
            </el-card>
          </el-col>
        </el-row>
      </template>
    </el-skeleton>
  </div>
</template>

<style scoped>
.topology-view { padding: 8px; }
.node-card { margin-bottom: 16px; }
.node-header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.node-name { font-weight: 600; flex: 1; }
.node-stats {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 8px;
  text-align: center;
}
.stat-label { display: block; font-size: 12px; color: #909399; }
.stat-value { display: block; font-size: 18px; font-weight: 700; }
.pod-list { margin-top: 8px; }
.pod-tag { margin: 2px; }
</style>
