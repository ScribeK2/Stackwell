<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Answer = {
    name: string
    location: string
    address: string
    rcode?: string
    answers: Record<string, string[]>
    failed?: string[]
    error?: string
  }
  const r = $derived(step.result as { types: string[]; resolvers: Answer[]; disagree: string[] })
</script>

<div class="overflow-x-auto">
  <table class="my-1.5 w-full text-xs">
    <thead>
      <tr class="text-left text-subtle">
        <th class="py-1 pl-3.5 font-medium">Resolver</th>
        {#each r.types as t}
          <th class="px-2 py-1 font-medium {r.disagree.includes(t) ? 'text-warn' : ''}">{t}{r.disagree.includes(t) ? ' ≠' : ''}</th>
        {/each}
      </tr>
    </thead>
    <tbody class="font-mono">
      {#each r.resolvers as res}
        <tr class="border-t border-line align-top">
          <th scope="row" class="py-1.5 pl-3.5 text-left font-sans font-normal">
            {res.name} <span class="block text-[11px] text-subtle">{res.location}</span>
          </th>
          {#if res.error}
            <td colspan={r.types.length} class="px-2 py-1.5 font-sans text-subtle">{res.error}</td>
          {:else if res.rcode === 'NXDOMAIN'}
            <td colspan={r.types.length} class="px-2 py-1.5 font-sans {r.disagree.includes('existence') ? 'bg-warn/8 text-warn' : 'text-subtle'}">Does not exist (NXDOMAIN)</td>
          {:else}
            {#each r.types as t}
              <td class="px-2 py-1.5 break-all {r.disagree.includes(t) ? 'bg-warn/8' : ''}">
                {#if res.failed?.includes(t)}
                  <span class="font-sans text-subtle">query failed</span>
                {:else}
                  {#each res.answers[t] ?? [] as v}<div>{v}</div>{:else}<span class="text-subtle">—</span>{/each}
                {/if}
              </td>
            {/each}
          {/if}
        </tr>
      {/each}
    </tbody>
  </table>
</div>
