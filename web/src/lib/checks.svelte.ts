import { api, type CheckInfo } from './api'

// The Check registry as the server describes it (GET /api/checks).
class Checks {
  list = $state<CheckInfo[]>([])

  async load() {
    this.list = await api<CheckInfo[]>('GET', '/api/checks')
  }

  label(key: string): string {
    return this.list.find((c) => c.key === key)?.label ?? key
  }

  get(key: string): CheckInfo | undefined {
    return this.list.find((c) => c.key === key)
  }
}

export const checks = new Checks()

/** Options worth showing on a Step, as [label, value]: those that differ from the defaults. */
export function shownOptions(check: string, options: Record<string, string> = {}): [string, string][] {
  const info = checks.get(check)
  return Object.entries(options).flatMap(([k, v]): [string, string][] => {
    const o = info?.options.find((o) => o.key === k)
    return o?.default === v ? [] : [[(o?.label ?? k).toLowerCase(), v]]
  })
}
