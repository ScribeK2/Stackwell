export type Step = {
  id: number
  check: string
  target: string
  options: Record<string, string>
  status: 'running' | 'ok' | 'failed' | 'cancelled'
  run_id?: number // the Playbook run that started it
  error?: string
  result?: any // shape is per Check; see lib/results/<check>.svelte
  started_at: string
  compared_to?: number // id of the earlier Step this one is compared against
  changes?: Change[]
}

export type Finding = {
  code: string
  severity: 'critical' | 'warning' | 'info' | 'ok'
  title: string
  message: string
  recommendation?: string
  target: string
  citations: number[]
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
  findings?: Finding[]
  suggestions?: Suggestion[]
  runs?: Run[]
}

export type Run = {
  id: number
  playbook: string
  label: string
  target: string
  boundary: string[] | null
  skipped: { entry: string; reason: string }[] | null
  total: number
  status: 'running' | 'done' | 'cancelled'
  started_at: string
}

export type PlaybookInfo = { name: string; label: string; description?: string; kinds: string[]; boundary: string[]; source: string }

export type Suggestion = { value: string; kind: Target['kind']; reason: string; from: number }

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

export type CheckOption = { key: string; label: string; choices?: string[]; default: string }
export type CheckInfo = { key: string; label: string; kinds: string[]; options: CheckOption[] }
