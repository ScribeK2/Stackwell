<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Verdict = {
    zone: string
    delist: string
    state: 'listed' | 'clean' | 'refused' | 'unknown'
    codes?: string[]
    reason?: string
    error?: string
  }
  type Subject = { kind: 'ip' | 'domain'; source: string; lists: Record<string, Verdict> }
  const r = $derived(step.result as { subjects: Record<string, Subject>; resolve?: string; ipv6?: boolean })
  // Addresses first, then the domain.
  const subjects = $derived(
    Object.entries(r.subjects ?? {}).sort(([a, x], [b, y]) => (x.kind === y.kind ? a.localeCompare(b) : x.kind === 'ip' ? -1 : 1)),
  )
  const tone: Record<Verdict['state'], string> = {
    listed: 'border-crit/40 bg-crit/8 text-crit',
    clean: 'border-line text-ok',
    refused: 'border-line text-subtle',
    unknown: 'border-line text-subtle',
  }
  const mark: Record<Verdict['state'], string> = { listed: '✕', clean: '✓', refused: '–', unknown: '?' }
</script>

{#if r.ipv6}
  <p class="px-3.5 py-2 text-xs text-muted">DNS blocklist coverage for IPv6 is limited, so this address was not checked.</p>
{:else}
  {#if r.resolve}
    <p class="px-3.5 pt-2 text-xs text-warn">Mail host lookup failed: {r.resolve}</p>
  {/if}
  {#each subjects as [subject, s]}
    {@const lists = Object.entries(s.lists)}
    <div class="border-t border-line px-3.5 py-2 first:border-t-0">
      <div class="mb-1.5 flex items-baseline gap-2 text-xs">
        <span class="font-mono">{subject}</span>
        {#if s.source !== 'target'}<span class="text-subtle">{s.source}</span>{/if}
      </div>
      <div class="flex flex-wrap gap-1">
        {#each lists as [name, v]}
          <span
            class="rounded border px-1.5 py-0.5 text-[11px] {tone[v.state]}"
            title="{v.zone}: {v.state}{v.error ? ' — ' + v.error : ''}"
          >{mark[v.state]} {name}</span>
        {/each}
      </div>
      {#each lists.filter(([, v]) => v.state === 'listed') as [name, v]}
        <div class="mt-1.5 rounded border border-crit/30 bg-crit/5 px-2.5 py-1.5 text-xs">
          <div class="flex flex-wrap items-baseline gap-x-2">
            <span class="font-medium text-crit">{name}</span>
            <span class="font-mono text-subtle">{v.codes?.join(', ')}</span>
            <a class="ml-auto text-accent hover:underline" href={v.delist} target="_blank" rel="noopener noreferrer">Delist</a>
          </div>
          {#if v.reason}<div class="mt-0.5 break-words text-muted">{v.reason}</div>{/if}
        </div>
      {/each}
    </div>
  {/each}
{/if}
