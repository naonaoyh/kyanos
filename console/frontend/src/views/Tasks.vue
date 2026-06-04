<script setup>
import { ref, onMounted } from 'vue'
import { listTasks, createTask, stopTask } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'

const tasks = ref([])
const loading = ref(false)
const showCreate = ref(false)

const form = ref({
  target_pod: '',
  target_namespace: 'gnss-production',
  duration_seconds: 3600,
  mountpoints: '',
  usernames: '',
  export_pcap: false,
  export_parsed: true,
})

const statusType = (s) => {
  const map = { running: 'success', stopped: 'info', completed: 'primary', failed: 'danger', pending: 'warning' }
  return map[s] || 'info'
}

const loadTasks = async () => {
  loading.value = true
  try {
    const { data } = await listTasks()
    tasks.value = data.items || []
  } catch (e) {
    ElMessage.error('Failed to load tasks')
  } finally {
    loading.value = false
  }
}

const handleCreate = async () => {
  try {
    const payload = {
      ...form.value,
      mountpoints: form.value.mountpoints ? form.value.mountpoints.split(',').map(s => s.trim()) : [],
      usernames: form.value.usernames ? form.value.usernames.split(',').map(s => s.trim()) : [],
    }
    const { data } = await createTask(payload)
    ElMessage.success(`Task ${data.task_id} created`)
    showCreate.value = false
    loadTasks()
  } catch (e) {
    ElMessage.error('Failed to create task: ' + (e.response?.data?.error || e.message))
  }
}

const handleStop = async (taskId) => {
  try {
    await ElMessageBox.confirm(`Stop task ${taskId}?`, 'Confirm', { type: 'warning' })
    await stopTask(taskId)
    ElMessage.success(`Task ${taskId} stopped`)
    loadTasks()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('Failed to stop task')
  }
}

onMounted(loadTasks)
</script>

<template>
  <div class="tasks-view">
    <div class="view-header">
      <h2>Capture Tasks</h2>
      <el-button type="primary" @click="showCreate = true">
        <el-icon><Plus /></el-icon> New Task
      </el-button>
    </div>

    <el-table :data="tasks" v-loading="loading" stripe>
      <el-table-column prop="id" label="Task ID" min-width="180" />
      <el-table-column prop="target_pod" label="Target Pod" width="160" />
      <el-table-column prop="target_namespace" label="Namespace" width="140" />
      <el-table-column prop="node_name" label="Node" width="120" />
      <el-table-column prop="status" label="Status" width="110">
        <template #default="{ row }">
          <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="session_count" label="Sessions" width="90" align="center" />
      <el-table-column prop="duration_seconds" label="Duration" width="100" align="center">
        <template #default="{ row }">
          {{ row.duration_seconds ? (row.duration_seconds / 60).toFixed(0) + 'm' : '-' }}
        </template>
      </el-table-column>
      <el-table-column label="Actions" width="100" align="center">
        <template #default="{ row }">
          <el-button
            v-if="row.status === 'running'"
            type="danger"
            size="small"
            link
            @click="handleStop(row.id)"
          >
            Stop
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="showCreate" title="Create Capture Task" width="520px">
      <el-form :model="form" label-width="130px">
        <el-form-item label="Target Pod">
          <el-input v-model="form.target_pod" placeholder="ds-pod-7" />
        </el-form-item>
        <el-form-item label="Namespace">
          <el-input v-model="form.target_namespace" />
        </el-form-item>
        <el-form-item label="Duration (s)">
          <el-input-number v-model="form.duration_seconds" :min="60" :max="86400" :step="600" />
        </el-form-item>
        <el-form-item label="Mountpoints">
          <el-input v-model="form.mountpoints" placeholder="MOUNT-A, MOUNT-B (comma-separated)" />
        </el-form-item>
        <el-form-item label="Usernames">
          <el-input v-model="form.usernames" placeholder="user001 (comma-separated)" />
        </el-form-item>
        <el-form-item label="Export PCAP">
          <el-switch v-model="form.export_pcap" />
        </el-form-item>
        <el-form-item label="Export Parsed">
          <el-switch v-model="form.export_parsed" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">Cancel</el-button>
        <el-button type="primary" @click="handleCreate">Create</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.tasks-view { padding: 8px; }
.view-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
h2 { margin: 0; }
</style>
