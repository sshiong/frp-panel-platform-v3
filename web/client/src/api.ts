import createClient from 'openapi-fetch'
import type { components, paths } from '../../../contracts/generated/client-api'

export type UserSummary = components['schemas']['UserSummary']
export type Mapping = components['schemas']['Mapping']
export type Domain = components['schemas']['Domain']
export type FRPCredentialStatus = components['schemas']['FRPCredentialStatus']
export type Dashboard = components['schemas']['Dashboard']
export type Operation = components['schemas']['Operation']
export type Problem = Partial<components['schemas']['Problem']>

export type CertificateInfo = components['schemas']['CertificateInfo']

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

export const clientAPI = createClient<paths>({ baseUrl: '' })

clientAPI.use({
  onRequest({ request }) {
    const headers = new Headers(request.headers)
    headers.set('X-FRP-Protocol-Version', 'v1')
    if (inMemoryCSRF) headers.set('X-CSRF-Token', inMemoryCSRF)
    if (['POST', 'PUT', 'DELETE'].includes(request.method) && !headers.has('Idempotency-Key')) headers.set('Idempotency-Key', requestID())
    return new Request(request, { headers })
  },
})

export class PanelAPIError extends Error {
  status: number
  code: string
  upgradeRequired: boolean
  clientVersion?: string
  minimumClientVersion?: string
  latestClientVersion?: string

  constructor(problem: { detail?: string; code?: string; status?: number; upgrade_required?: boolean; client_version?: string; minimum_client_version?: string; latest_client_version?: string }, fallbackStatus: number) {
    super(problem.detail || problem.code || `HTTP ${fallbackStatus}`)
    this.name = 'PanelAPIError'
    this.status = problem.status ?? fallbackStatus
    this.code = problem.code || ''
    this.upgradeRequired = problem.upgrade_required === true
    this.clientVersion = problem.client_version
    this.minimumClientVersion = problem.minimum_client_version
    this.latestClientVersion = problem.latest_client_version
  }
}

export function setCSRFToken(value: string) {
  inMemoryCSRF = value
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toLowerCase()
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body
  const headers = new Headers(init.headers)
  const result = await clientAPI.request(method as never, path as never, {
    ...init,
    body,
    headers,
    credentials: 'include',
  } as never)
  if (!result.response.ok) {
    const problem = result.error as Problem & { upgrade_required?: boolean; client_version?: string; minimum_client_version?: string; latest_client_version?: string } | undefined
    throw new PanelAPIError(problem ?? {}, result.response.status)
  }
  return result.data as T
}
