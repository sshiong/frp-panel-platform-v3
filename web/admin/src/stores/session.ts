import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '../api'

export const useSessionStore = defineStore('admin-session', () => {
  const authenticated = ref(false)
  const user = ref<{ username: string; role: string; must_change_password: boolean; must_change_username: boolean } | null>(null)
  const loading = ref(true)
  const error = ref('')
  const needsPasswordChange = computed(() => Boolean(user.value?.must_change_password))
  const needsUsernameChange = computed(() => Boolean(user.value?.must_change_username))

  async function restore() {
    loading.value = true
    try {
      const dashboard = await api<{ user: typeof user.value }>('/api/v1/dashboard')
      user.value = dashboard.user
      authenticated.value = true
    } catch { authenticated.value = false }
    finally { loading.value = false }
  }
  async function login(username: string, password: string) {
    error.value = ''
    try { const result = await api<{ user: typeof user.value }>('/api/v1/auth/admin-login', { method: 'POST', body: JSON.stringify({ username, password }) }); user.value = result.user; authenticated.value = true }
    catch (err) { error.value = err instanceof Error ? err.message : '登录失败'; throw err }
  }
  async function logout() { await api('/api/v1/auth/logout', { method: 'POST' }).catch(() => undefined); authenticated.value = false; user.value = null }
  function markCredentialsChanged(username?: string) { if (user.value) user.value = { ...user.value, username: username || user.value.username, must_change_password: false, must_change_username: false } }
  return { authenticated, user, loading, error, needsPasswordChange, needsUsernameChange, restore, login, logout, markCredentialsChanged }
})
