import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
})

// --- Tasks ---

export const createTask = (data) => api.post('/tasks', data)
export const listTasks = () => api.get('/tasks')
export const getTask = (id) => api.get(`/tasks/${id}`)
export const stopTask = (id) => api.delete(`/tasks/${id}`)
export const updateTaskFilter = (id, data) => api.post(`/tasks/${id}/filter`, data)

// --- Sessions ---

export const listSessions = (params = {}) => api.get('/sessions', { params })
export const getSession = (id) => api.get(`/sessions/${id}`)
export const getSessionEvents = (id) => api.get(`/sessions/${id}/events`)
export const getSessionReport = (id, format = 'json') =>
  api.get(`/sessions/${id}/report`, { params: { format } })
export const deleteSession = (id) => api.delete(`/sessions/${id}`)

// --- Agents & Topology ---

export const listAgents = () => api.get('/agents')
export const getAgentStatus = (node) => api.get(`/agents/${node}/status`)
export const getTopology = () => api.get('/topology')

// --- Health ---

export const getHealth = () => api.get('/health')

// --- Agent Control ---

export const setTUIMode = (enabled) => api.post('/agent/tui-mode', { enabled })

export default api
