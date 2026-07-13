import { createRouter, createWebHistory } from 'vue-router'
import { isSignedIn } from '../auth/useAuth'
import LoginView from '../views/LoginView.vue'
import CallbackView from '../views/CallbackView.vue'
import ProfileView from '../views/ProfileView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: LoginView },
    { path: '/callback', name: 'callback', component: CallbackView },
    { path: '/profile', name: 'profile', component: ProfileView, meta: { requiresAuth: true } },
  ],
})

router.beforeEach(async (to) => {
  if (!to.meta.requiresAuth) {
    return true
  }
  // Same predicate the UI uses, so the nav bar and the guard can't disagree
  // about whether an expired session counts as signed in.
  return (await isSignedIn()) ? true : { name: 'home' }
})

export default router
