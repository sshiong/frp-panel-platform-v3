export type Problem = { code?: string; detail?: string; status?: number }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, { credentials: 'include', headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) }, ...init })
  if (!response.ok) {
    const problem = await response.json().catch(() => ({})) as Problem
    throw new Error(problem.detail || problem.code || `HTTP ${response.status}`)
  }
  return response.json() as Promise<T>
}
