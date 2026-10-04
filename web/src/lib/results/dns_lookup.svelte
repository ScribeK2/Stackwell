<script lang="ts">
  import Clamp from '../Clamp.svelte'
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  const order = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
  const r = $derived(step.result as { rcode: string; records: Record<string, string[]>; errors?: Record<string, string> })
</script>

{#if r.rcode !== 'NOERROR'}
  <p class="px-3.5 pt-3 text-warn">{r.rcode === 'NXDOMAIN' ? 'Domain does not exist (NXDOMAIN)' : r.rcode}</p>
{/if}
{#each Object.entries(r.errors ?? {}) as [type, msg]}
  <p class="px-3.5 pt-2 text-xs text-warn">{type} query failed: {msg}</p>
{/each}
<Clamp lines={12} rowHeight={24} inset>
<table class="my-1.5 w-full font-mono text-xs">
  <tbody>
    {#each order as type}
      {#each r.records[type] ?? [] as value, i}
        <tr class="align-top">
          <th scope="row" class="w-20 py-1 pl-3.5 text-left font-sans font-medium text-subtle">{i === 0 ? type : ''}</th>
          <td class="py-1 pr-3.5 break-all">{value}</td>
        </tr>
      {/each}
    {/each}
  </tbody>
</table>
</Clamp>
