function requestID(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  const timestamp = BigInt(Date.now())
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp >> BigInt((5 - index) * 8)) & 0xff
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

// The local CSRF token is a browser-session value. Keep it only in this
// module's memory; the only browser storage permitted by the product contract
// is the non-sensitive last Server Panel URL.
let inMemoryCSRF = ''

export function setCSRFToken(value: string) {
  inMemoryCSRF = value
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const csrf = inMemoryCSRF
  const headers = new Headers({ 'Content-Type': 'application/json', 'X-FRP-Protocol-Version': 'v1', ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(init.headers ?? {}) })
  if (['POST', 'PUT', 'DELETE'].includes((init.method ?? 'GET').toUpperCase()) && !headers.has('Idempotency-Key')) headers.set('Idempotency-Key', requestID())
  const response = await fetch(path, { credentials: 'include', ...init, headers })
  if (!response.ok) { const problem = await response.json().catch(() => ({})) as { detail?: string; code?: string }; throw new Error(problem.detail || problem.code || `HTTP ${response.status}`) }
  return response.json() as Promise<T>
}
