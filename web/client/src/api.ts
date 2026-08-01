export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const csrf = sessionStorage.getItem('client_csrf') ?? ''
  const headers = new Headers({ 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(init.headers ?? {}) })
  if (['POST', 'PUT', 'DELETE'].includes((init.method ?? 'GET').toUpperCase()) && !headers.has('Idempotency-Key')) headers.set('Idempotency-Key', crypto.randomUUID())
  const response = await fetch(path, { credentials: 'include', ...init, headers })
  if (!response.ok) { const problem = await response.json().catch(() => ({})) as { detail?: string; code?: string }; throw new Error(problem.detail || problem.code || `HTTP ${response.status}`) }
  return response.json() as Promise<T>
}
