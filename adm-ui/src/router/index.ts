import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '',
    redirect: '/login',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('src/views/Login/login.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  //@ts-ignore
  routes,
})
export default router
