<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { getHealth, setTUIMode } from './api'

const health = ref(null)
const tuiEnabled = ref(true)
let healthTimer = null

const fetchHealth = async () => {
  try {
    const { data } = await getHealth()
    health.value = data
  } catch {
    // Backend not available during dev — ignore.
  }
}

const toggleTUI = async () => {
  try {
    tuiEnabled.value = !tuiEnabled.value
    await setTUIMode(tuiEnabled.value)
  } catch {
    // Revert on error
    tuiEnabled.value = !tuiEnabled.value
  }
}

onMounted(() => {
  fetchHealth()
  healthTimer = setInterval(fetchHealth, 10000)
})

onUnmounted(() => {
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
})
</script>

<template>
  <el-container class="app-container">
    <el-aside width="220px" class="app-aside">
      <div class="logo">
        <el-icon :size="24"><Monitor /></el-icon>
        <span class="logo-text">Kyanos Console</span>
      </div>
      <el-menu
        :default-active="$route.path"
        router
        class="nav-menu"
      >
        <el-menu-item index="/topology">
          <el-icon><Connection /></el-icon>
          <span>Cluster Topology</span>
        </el-menu-item>
        <el-menu-item index="/tasks">
          <el-icon><List /></el-icon>
          <span>Tasks</span>
        </el-menu-item>
        <el-menu-item index="/sessions">
          <el-icon><DataLine /></el-icon>
          <span>Session Explorer</span>
        </el-menu-item>
        <el-menu-item index="/alerts">
          <el-icon><Bell /></el-icon>
          <span>Alerts</span>
        </el-menu-item>
      </el-menu>
      <div class="tui-toggle" @click="toggleTUI">
        <el-icon><Monitor /></el-icon>
        <span>TUI {{ tuiEnabled ? 'ON' : 'OFF' }}</span>
        <el-switch
          v-model="tuiEnabled"
          size="small"
          @click.stop
          @change="toggleTUI"
        />
      </div>
      <div class="health-bar" v-if="health">
        <el-tag type="success" size="small">
          {{ health.connected_agents }} agents
        </el-tag>
        <el-tag type="info" size="small">
          {{ health.active_sessions }} sessions
        </el-tag>
      </div>
    </el-aside>

    <el-main class="app-main">
      <router-view />
    </el-main>
  </el-container>
</template>

<style>
html, body, #app {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
.app-container {
  height: 100vh;
}
.app-aside {
  background: #1a1a2e;
  color: #e0e0e0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px 20px;
  font-size: 16px;
  font-weight: 700;
  color: #60a5fa;
  border-bottom: 1px solid #2d2d44;
}
.logo-text {
  white-space: nowrap;
}
.nav-menu {
  flex: 1;
  border-right: none;
  background: transparent;
  --el-menu-text-color: #c0c0c0;
  --el-menu-hover-text-color: #60a5fa;
  --el-menu-active-color: #60a5fa;
  --el-menu-hover-bg-color: rgba(96,165,250,0.1);
}
.nav-menu .el-menu-item.is-active {
  background: rgba(96,165,250,0.15);
  color: #60a5fa;
}
.tui-toggle {
  padding: 10px 16px;
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  font-size: 13px;
  color: #c0c0c0;
  border-top: 1px solid #2d2d44;
}
.tui-toggle:hover { color: #60a5fa; }
.health-bar {
  padding: 12px 16px;
  display: flex;
  gap: 8px;
  border-top: 1px solid #2d2d44;
}
.app-main {
  background: #f5f7fa;
  overflow-y: auto;
}
</style>
