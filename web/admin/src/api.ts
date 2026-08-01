export type Problem = { code?: string; detail?: string; status?: number }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const csrf = document.cookie.split(';').map(item => item.trim()).find(item => item.startsWith('frp_server_csrf='))?.slice('frp_server_csrf='.length) ?? ''
  const headers = new Headers({ 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}), ...(init.headers ?? {}) })
  if (['POST', 'PUT', 'DELETE'].includes((init.method ?? 'GET').toUpperCase()) && !headers.has('Idempotency-Key')) headers.set('Idempotency-Key', crypto.randomUUID())
  const response = await fetch(path, { credentials: 'include', ...init, headers })
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as Problem
    throw new Error(problem.detail || problem.code || `HTTP ${response.status}`)
  }
  return response.json() as Promise<T>
}
