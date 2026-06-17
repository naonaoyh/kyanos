<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { listTasks, createTask, stopTask, updateTaskFilter } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'

const tasks = ref([])
const loading = ref(false)
const showCreate = ref(false)
const showFilter = ref(false)
const editingTask = ref(null)
const filterForm = ref({ mountpoints: '', usernames: '' })

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

// ---- Task lifecycle ----

const loadTasks = async () => {
  loading.value = true
  try {
    const { data } = await listTasks()
    tasks.value = data.items || []
    syncWebSockets()
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
    await loadTasks()
  } catch (e) {
    ElMessage.error('Failed to create task: ' + (e.response?.data?.error || e.message))
  }
}

const handleStop = async (taskId) => {
  try {
    await ElMessageBox.confirm(`Stop task ${taskId}?`, 'Confirm', { type: 'warning' })
    await stopTask(taskId)
    ElMessage.success(`Task ${taskId} stopped`)
    await loadTasks()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('Failed to stop task')
  }
}

// Restart: re-create with the same parameters as a stopped/completed/failed task.
const handleRestart = async (task) => {
  try {
    await ElMessageBox.confirm(
      `Restart task ${task.id}? A new task will be created with the same parameters.`,
      'Confirm Restart',
      { type: 'info' }
    )
    const payload = {
      target_pod: task.target_pod,
      target_namespace: task.target_namespace || 'gnss-production',
      duration_seconds: task.duration_seconds || 3600,
      mountpoints: (task.ntrip_filter && task.ntrip_filter.mountpoints) || [],
      usernames: (task.ntrip_filter && task.ntrip_filter.usernames) || [],
      export_pcap: task.export_pcap || false,
      export_parsed: task.export_parsed !== false,
    }
    const { data } = await createTask(payload)
    ElMessage.success(`Task ${data.task_id} created (restart of ${task.id})`)
    await loadTasks()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error('Failed to restart task: ' + (e.response?.data?.error || e.message))
  }
}

// Toggle: stop if running; restart if not running.
const handleToggle = async (task) => {
  if (task.status === 'running') {
    await handleStop(task.id)
  } else {
    await handleRestart(task)
  }
}

// ---- Filter management ----

const openFilterEditor = (task) => {
  editingTask.value = task
  const m = (task.ntrip_filter && task.ntrip_filter.mountpoints) || []
  const u = (task.ntrip_filter && task.ntrip_filter.usernames) || []
  filterForm.value = { mountpoints: m.join(', '), usernames: u.join(', ') }
  showFilter.value = true
}

const handleFilterUpdate = async () => {
  if (!editingTask.value) return
  const id = editingTask.value.id
  const mountpoints = filterForm.value.mountpoints
    ? filterForm.value.mountpoints.split(',').map(s => s.trim()).filter(Boolean)
    : []
  const usernames = filterForm.value.usernames
    ? filterForm.value.usernames.split(',').map(s => s.trim()).filter(Boolean)
    : []
  try {
    await updateTaskFilter(id, { mountpoints, usernames })
    // Update local task model so the table reflects the change immediately.
    const idx = tasks.value.findIndex(t => t.id === id)
    if (idx !== -1) {
      tasks.value[idx].ntrip_filter = { mountpoints, usernames }
    }
    ElMessage.success(`Filter updated for task ${id}`)
    showFilter.value = false
  } catch (e) {
    ElMessage.error('Failed to update filter: ' + (e.response?.data?.error || e.message))
  }
}

// ---- WebSocket (unchanged) ----
const sockets = {}

const syncWebSockets = () => {
  Object.keys(sockets).forEach(id => {
    if (!tasks.value.find(t => t.id === id && t.status === 'running')) closeTaskWS(id)
  })
  tasks.value.forEach(t => { if (t.status === 'running') connectTaskWS(t.id) })
}

const connectTaskWS = (taskId) => {
  if (sockets[taskId]) return
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = `${protocol}//${window.location.host}/api/v1/ws/tasks/${taskId}`
  const ws = new WebSocket(url)
  sockets[taskId] = ws
  ws.onopen = () => {}
  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'task_status' && msg.data) {
        const idx = tasks.value.findIndex(t => t.id === msg.data.id)
        if (idx !== -1) tasks.value[idx] = msg.data
        if (msg.data.status !== 'running') closeTaskWS(msg.data.id)
      }
    } catch (e) { console.error('WS parse', e) }
  }
  ws.onclose = () => { delete sockets[taskId] }
  ws.onerror = () => { ws.close() }
}

const closeTaskWS = (taskId) => {
  if (sockets[taskId]) { sockets[taskId].close(); delete sockets[taskId] }
}

const closeAllTaskWS = () => {
  Object.keys(sockets).forEach(closeTaskWS)
}

onMounted(loadTasks)
onUnmounted(closeAllTaskWS)
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
      <el-table-column prop="target_pod" label="Pod" width="140" />
      <el-table-column label="Filter" min-width="180">
        <template #default="{ row }">
          <span v-if="row.ntrip_filter && (row.ntrip_filter.mountpoints?.length || row.ntrip_filter.usernames?.length)" class="filter-summary">
            <template v-if="row.ntrip_filter.mountpoints?.length">
              🏔️ {{ row.ntrip_filter.mountpoints.join(', ') }}
            </template>
            <template v-if="row.ntrip_filter.mountpoints?.length && row.ntrip_filter.usernames?.length"> &middot; </template>
            <template v-if="row.ntrip_filter.usernames?.length">
              👤 {{ row.ntrip_filter.usernames.join(', ') }}
            </template>
          </span>
          <span v-else class="no-filter">(all traffic)</span>
        </template>
      </el-table-column>
      <el-table-column prop="status" label="Status" width="100">
        <template #default="{ row }">
          <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="session_count" label="Sessions" width="90" align="center" />
      <el-table-column prop="duration_seconds" label="Duration" width="90" align="center">
        <template #default="{ row }">
          {{ row.duration_seconds ? (row.duration_seconds / 60).toFixed(0) + 'm' : '-' }}
        </template>
      </el-table-column>
      <el-table-column label="Actions" width="200" align="center">
        <template #default="{ row }">
          <div class="action-btns">
            <template v-if="row.status === 'running'">
              <el-tooltip content="Edit filter" placement="top">
                <el-button size="small" circle @click.stop="openFilterEditor(row)">
                  <el-icon><Edit /></el-icon>
                </el-button>
              </el-tooltip>
              <el-tooltip content="Stop capture" placement="top">
                <el-button size="small" type="danger" circle @click.stop="handleStop(row.id)">
                  <el-icon><VideoPause /></el-icon>
                </el-button>
              </el-tooltip>
            </template>
            <template v-else>
              <el-tooltip content="Restart with same parameters" placement="top">
                <el-button size="small" type="primary" circle @click.stop="handleRestart(row)">
                  <el-icon><VideoPlay /></el-icon>
                </el-button>
              </el-tooltip>
            </template>
            <el-tooltip :content="row.status === 'running' ? 'Disable' : 'Enable'" placement="top">
              <el-switch
                :model-value="row.status === 'running'"
                size="small"
                @click.stop
                @change="() => handleToggle(row)"
              />
            </el-tooltip>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- Create dialog -->
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

    <!-- Filter editor dialog -->
    <el-dialog v-model="showFilter" title="Edit Filter" width="460px">
      <template v-if="editingTask">
        <p class="filter-task-id">Task <code>{{ editingTask.id }}</code></p>
      </template>
      <el-form :model="filterForm" label-width="130px">
        <el-form-item label="Mountpoints">
          <el-input v-model="filterForm.mountpoints" placeholder="MOUNT-A, MOUNT-B (comma-separated)" />
        </el-form-item>
        <el-form-item label="Usernames">
          <el-input v-model="filterForm.usernames" placeholder="user001 (comma-separated)" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showFilter = false">Cancel</el-button>
        <el-button type="primary" @click="handleFilterUpdate">Save</el-button>
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
.action-btns {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}
.filter-summary { font-size: 12px; color: #606266; }
.no-filter { font-size: 12px; color: #c0c4cc; }
.filter-task-id { margin-bottom: 12px; font-size: 13px; }
.filter-task-id code { background: #f5f7fa; padding: 2px 6px; border-radius: 3px; }
</style>
