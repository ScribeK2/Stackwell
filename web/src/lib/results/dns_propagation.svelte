<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Answer = {
    name: string
    location: string
    rcode?: string
    answers: Record<string, string[]>
    failed?: string[]
    error?: string
  }
  const r = $derived(step.result as { types: string[]; resolvers: Answer[]; disagree: string[] })

  // Per record type, resolvers grouped by the answer they gave, so agreement
  // reads as one line and a split shows exactly who sees what.
  type Group = { answer: string[]; who: Answer[] }
  const rows = $derived(
    r.types.map((type) => {
      const groups: Group[] = []
      for (const res of r.resolvers) {
        if (res.error || res.rcode === 'NXDOMAIN' || res.failed?.includes(type)) continue
        const answer = res.answers[type] ?? []
        const g = groups.find((g) => g.answer.join('\n') === answer.join('\n'))
        if (g) g.who.push(res)
        else groups.push({ answer, who: [res] })
      }
      groups.sort((a, b) => b.who.length - a.who.length)
      return { type, groups, split: r.disagree.includes(type) }
    }),
  )
  const silent = $derived(r.resolvers.filter((x) => x.error))
  const missing = $derived(r.resolvers.filter((x) => !x.error && x.rcode === 'NXDOMAIN'))
  const answered = $derived(r.resolvers.length - silent.length)
</script>

<div class="px-3.5 py-2.5 text-xs">
  <p class="mb-2 text-muted">
    {answered} of {r.resolvers.length} resolvers answered
    {#if r.disagree.length}· <span class="text-warn">disagreement on {r.disagree.join(', ')}</span>{:else}· all agree{/if}
  </p>

  {#if missing.length && missing.length < answered}
    <p class="mb-2 text-warn">
      Says the name does not exist: {missing.map((m) => m.name).join(', ')}
    </p>
  {/if}

  <dl class="divide-y divide-line">
    {#each rows as row (row.type)}
      <div class="flex gap-3 py-1.5">
        <dt class="w-14 shrink-0 font-medium {row.split ? 'text-warn' : 'text-subtle'}">{row.type}</dt>
        <dd class="min-w-0 flex-1 space-y-1.5">
          {#each row.groups as g}
            <div class={row.split ? 'rounded border border-line px-2 py-1' : ''}>
              <div class="font-mono break-all">
                {#each g.answer as v}<div>{v}</div>{:else}<span class="text-subtle">no records</span>{/each}
              </div>
              <div class="mt-0.5 text-subtle">
                {#if !row.split}
                  all {g.who.length} agree
                {:else}
                  {g.who.map((w) => `${w.name} (${w.location})`).join(', ')}
                {/if}
              </div>
            </div>
          {:else}
            <span class="text-subtle">no answers</span>
          {/each}
        </dd>
      </div>
    {/each}
  </dl>

  {#if silent.length}
    <p class="mt-2 text-subtle">No answer from {silent.map((s) => s.name).join(', ')}</p>
  {/if}
</div>
