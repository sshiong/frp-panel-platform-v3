import { ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '../api'

export type Mapping = { id: string; name: string; proxy_type: 'tcp' | 'udp' | 'http'; lifecycle_status: string; desired_state: string; observed_state: string; revision: number; local_ip: string; local_port: number; remote_port?: number }
export type Domain = { id: string; mapping_id: string; hostname: string; normalized_domain: string; https_mode: string; http_redirect: boolean; status: string; revision: number }
export type Dashboard = { user: { username: string; must_change_password: boolean }; desired_config_version: number; applied_config_version: number; observed_client_status: string; mappings: Mapping[]; counts: { total_mappings: number; running: number; pending: number; offline: number; errors: number } }

export const useClientStore = defineStore('client', () => {
  const authenticated = ref(false); const loading = ref(true); const user = ref<{ username: string; must_change_password: boolean } | null>(null); const serverURL = ref(''); const csrf = ref(''); const dashboard = ref<Dashboard | null>(null); const domains = ref<Domain[]>([]); const localStatus = ref<Record<string, unknown>>({}); const error = ref('')
  async function restore() { try { const session = await api<{ user: typeof user.value; server_panel_url: string; csrf_token: string }>('/api/v1/session'); authenticated.value = true; user.value = session.user; serverURL.value = session.server_panel_url; csrf.value = session.csrf_token; sessionStorage.setItem('client_csrf', csrf.value); await refresh() } catch { authenticated.value = false } finally { loading.value = false } }
  async function login(payload: { server_panel_url: string; username: string; password: string }) { error.value = ''; const session = await api<{ user: typeof user.value; server_panel_url: string; csrf_token: string }>('/api/v1/login', { method: 'POST', body: JSON.stringify(payload) }); authenticated.value = true; user.value = session.user; serverURL.value = session.server_panel_url; csrf.value = session.csrf_token; sessionStorage.setItem('client_csrf', csrf.value); localStorage.setItem('last_server_panel_url', session.server_panel_url); await refresh() }
  async function logout() { await api('/api/v1/logout', { method: 'POST' }).catch(() => undefined); authenticated.value = false; user.value = null; dashboard.value = null; domains.value = []; csrf.value = ''; sessionStorage.removeItem('client_csrf') }
  async function refresh() { dashboard.value = await api<Dashboard>('/api/v1/dashboard'); const response = await api<{ items: Domain[] }>('/api/v1/domains'); domains.value = response.items; localStatus.value = await api('/api/v1/local-status') }
  return { authenticated, loading, user, serverURL, csrf, dashboard, domains, localStatus, error, restore, login, logout, refresh }
})
