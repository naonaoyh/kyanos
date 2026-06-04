import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    redirect: '/topology',
  },
  {
    path: '/topology',
    name: 'Topology',
    component: () => import('../views/Topology.vue'),
    meta: { title: 'Cluster Topology' },
  },
  {
    path: '/tasks',
    name: 'Tasks',
    component: () => import('../views/Tasks.vue'),
    meta: { title: 'Tasks' },
  },
  {
    path: '/sessions',
    name: 'Sessions',
    component: () => import('../views/SessionExplorer.vue'),
    meta: { title: 'Session Explorer' },
  },
  {
    path: '/sessions/:id',
    name: 'SessionDetail',
    component: () => import('../views/SessionDetail.vue'),
    meta: { title: 'Session Detail' },
    props: true,
  },
  {
    path: '/sessions/:id/report',
    name: 'Report',
    component: () => import('../views/Report.vue'),
    meta: { title: 'Diagnostic Report' },
    props: true,
  },
  {
    path: '/alerts',
    name: 'Alerts',
    component: () => import('../views/Alerts.vue'),
    meta: { title: 'Alerts' },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, from, next) => {
  document.title = `${to.meta.title || 'Kyanos'} - NTRIP Console`
  next()
})

export default router
