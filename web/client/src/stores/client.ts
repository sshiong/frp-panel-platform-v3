import { ref } from 'vue'
import { defineStore } from 'pinia'
import { api, setCSRFToken, type CloudflareStatus, type Dashboard, type Domain, type LocalLoginRequest, type Operation, type SupervisorStatus, type UserSummary } from '../api'

export type { CertificateInfo, CloudflareStatus, Dashboard, Domain, Mapping, Operation, SupervisorStatus } from '../api'

export const useClientStore = defineStore('client', () => {
  const authenticated = ref(false); const loading = ref(true); const user = ref<UserSummary | null>(null); const serverURL = ref(''); const csrf = ref(''); const dashboard = ref<Dashboard | null>(null); const domains = ref<Domain[]>([]); const operations = ref<Operation[]>([]); const localStatus = ref<SupervisorStatus | null>(null); const cloudflare = ref<CloudflareStatus | null>(null); const error = ref('')
  async function restore() { try { const session = await api('get', '/api/v1/session'); authenticated.value = true; user.value = session.user; serverURL.value = session.server_panel_url; csrf.value = session.csrf_token; setCSRFToken(csrf.value); if (!user.value?.must_change_password) await refresh() } catch { authenticated.value = false; setCSRFToken('') } finally { loading.value = false } }
  async function inspectServer(serverPanelURL: string) { return api('post', '/api/v1/server/inspect', { body: { server_panel_url: serverPanelURL } }) }
  async function login(payload: LocalLoginRequest) { error.value = ''; const session = await api('post', '/api/v1/login', { body: payload }); authenticated.value = true; user.value = session.user; serverURL.value = session.server_panel_url; csrf.value = session.csrf_token; setCSRFToken(csrf.value); localStorage.setItem('last_server_panel_url', session.server_panel_url); return session }
  async function changePassword(currentPassword: string, newPassword: string) { await api('post', '/api/v1/password', { body: { current_password: currentPassword, new_password: newPassword } }); if (user.value) user.value = { ...user.value, must_change_password: false } }
  async function logout() { await api('post', '/api/v1/logout').catch(() => undefined); authenticated.value = false; user.value = null; dashboard.value = null; domains.value = []; operations.value = []; cloudflare.value = null; csrf.value = ''; setCSRFToken('') }
  async function resetFRPCredential(currentPassword: string) { await api('post', '/api/v1/frp-credential/reset', { body: { current_password: currentPassword } }); authenticated.value = false; user.value = null; dashboard.value = null; domains.value = []; operations.value = []; cloudflare.value = null; csrf.value = ''; setCSRFToken('') }
  async function refreshCloudflare() { cloudflare.value = await api('get', '/api/v1/cloudflare/status') }
  async function refresh() { const [nextDashboard, domainResponse, operationResponse, nextLocalStatus, nextCloudflare] = await Promise.all([api('get', '/api/v1/dashboard'), api('get', '/api/v1/domains'), api('get', '/api/v1/operations'), api('get', '/api/v1/local-status'), api('get', '/api/v1/cloudflare/status').catch(() => null)]); dashboard.value = nextDashboard; domains.value = domainResponse.items; operations.value = operationResponse.items; localStatus.value = nextLocalStatus; if (nextCloudflare) cloudflare.value = nextCloudflare }
  async function retryOperation(operationID: string) { await api('post', '/api/v1/operations/{id}/retry', { params: { path: { id: operationID } } }); await refresh() }
  return { authenticated, loading, user, serverURL, csrf, dashboard, domains, operations, localStatus, cloudflare, error, restore, inspectServer, login, changePassword, logout, resetFRPCredential, refresh, refreshCloudflare, retryOperation }
})
