import createClient from 'openapi-fetch'
import type { components, paths } from '../../../contracts/generated/server-api'

export type Problem = Partial<components['schemas']['Problem']>
export type UserSummary = components['schemas']['UserSummary']
export type UserRecord = components['schemas']['UserRecord']
export type Operation = components['schemas']['Operation']
export type AdminStats = components['schemas']['AdminStats']
export type CloudflareStatus = components['schemas']['CloudflareStatus']

export const serverAPI = createClient<paths>({ baseUrl: '' })

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

serverAPI.use({
  onRequest({ request }) {
    const csrf = document.cookie.split(';').map(item => item.trim()).find(item => item.startsWith('frp_server_csrf='))?.slice('frp_server_csrf='.length) ?? ''
    const headers = new Headers(request.headers)
    headers.set('X-FRP-Protocol-Version', 'v1')
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
    if (['POST', 'PUT', 'DELETE'].includes(request.method) && !headers.has('Idempotency-Key')) headers.set('Idempotency-Key', requestID())
    return new Request(request, { headers })
  },
})

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toLowerCase()
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
  const headers = new Headers(init.headers)
  const result = await serverAPI.request(method as never, path as never, {
    ...init,
    body,
    headers,
    credentials: 'include',
  } as never)
  if (!result.response.ok) {
    const problem = result.error as Problem | undefined
    throw new Error(problem?.detail || problem?.code || `HTTP ${result.response.status}`)
  }
  return result.data as T
}
