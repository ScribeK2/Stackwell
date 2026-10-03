<script lang="ts">
  import type { Step } from '../api'
  let { step, rerun }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Port = { address: string; port: number; service: string; state: string; banner?: string }
  const r = $derived(step.result as { addresses: string[]; ports: Port[] })
  const multi = $derived(r.addresses.length > 1)
  const open = $derived(r.ports.filter((p) => p.state === 'open').length)
  const dot: Record<string, string> = { open: 'bg-ok', closed: 'bg-line-strong', filtered: 'bg-warn', 'no route': 'bg-subtle' }
</script>

<div class="flex items-center gap-3 px-3.5 pt-2 text-xs text-muted">
  {#if r.addresses.length}
    <span>Probed <span class="font-mono text-fg">{r.addresses.join(', ')}</span></span>
    <span class="text-subtle">{open} of {r.ports.length} open</span>
  {:else}
    <span>No A or AAAA record to probe.</span>
  {/if}
  {#if step.options.depth !== 'full'}
    <button class="ml-auto text-accent hover:underline" onclick={() => rerun({ depth: 'full' })}>Run full sweep</button>
  {/if}
</div>

{#if r.ports.length}
  <div class="overflow-x-auto">
    <table class="my-1.5 w-full text-xs">
      <thead>
        <tr class="text-left text-subtle">
          <th class="py-1 pl-3.5 font-medium">Port</th>
          {#if multi}<th class="px-2 py-1 font-medium">Address</th>{/if}
          <th class="px-2 py-1 font-medium">Service</th>
          <th class="px-2 py-1 font-medium">State</th>
          <th class="px-2 py-1 pr-3.5 font-medium">Banner</th>
        </tr>
      </thead>
      <tbody class="font-mono">
        {#each r.ports as p (p.address + ':' + p.port)}
          <tr class="border-t border-line">
            <td class="py-1 pl-3.5 tabular-nums">{p.port}</td>
            {#if multi}<td class="px-2 py-1 text-muted">{p.address}</td>{/if}
            <td class="px-2 py-1 font-sans">{p.service}</td>
            <td class="px-2 py-1 font-sans whitespace-nowrap {p.state === 'open' ? '' : 'text-muted'}">
              <span class="mr-1.5 inline-block size-1.5 rounded-full align-middle {dot[p.state] ?? 'bg-subtle'}"></span>{p.state}
            </td>
            <td class="px-2 py-1 pr-3.5 break-all text-muted">{p.banner ?? ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
