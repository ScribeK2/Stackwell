export type Step = {
  id: number
  check: string
  target: string
  status: 'running' | 'ok' | 'failed'
  error?: string
  result?: { rcode: string; records: Record<string, string[]>; errors?: Record<string, string> }
  started_at: string
  compared_to?: number // id of the earlier Step this one is compared against
  changes?: Change[]
}

export type Change = { field: string; removed?: string[]; added?: string[] }

/** records.MX → MX, errors.CAA → CAA error, rcode → Response code */
export function fieldLabel(field: string): string {
  if (field.startsWith('records.')) return field.slice('records.'.length)
  if (field.startsWith('errors.')) return `${field.slice('errors.'.length)} error`
  return field === 'rcode' ? 'Response code' : field
}

export type Target = { value: string; kind: 'domain' | 'hostname' | 'ip' | 'email'; checks: string[] }

export type Case = {
  id: number
  title: string
  ticket_ref: string
  status: 'open' | 'resolved'
  targets: Target[]
  steps?: Step[]
}

export class ApiError extends Error {}

/** Calls the Stackwell API; throws ApiError with a message fit to show the rep. */
export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  let data: any
  try {
    res = await fetch(path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    data = await res.json()
  } catch {
    throw new ApiError('Stackwell is not responding.')
  }
  if (!res.ok) throw new ApiError(data?.error ?? `Request failed (${res.status})`)
  return data as T
}

export function caseName(c: Case): string {
  return c.title || c.targets[0]?.value || `Case #${c.id}`
}
