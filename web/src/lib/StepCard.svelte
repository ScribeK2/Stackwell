<script lang="ts">
  import { fieldLabel, type Step } from './api'

  let { step, earlier, onrerun }: { step: Step; earlier: boolean; onrerun: () => void } = $props()

  const checkLabels: Record<string, string> = { dns_lookup: 'DNS Lookup' }
  const recordOrder = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

  // Earlier runs start collapsed; the latest is always open.
  let expanded = $state(false)
  const open = $derived(!earlier || expanded)
  const time = $derived(new Date(step.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))
</script>

<article
  data-nav-item
  data-step-id={step.id}
  tabindex="-1"
  aria-label="{checkLabels[step.check] ?? step.check} {step.target} at {time}"
  class="overflow-hidden rounded-lg border bg-surface transition-colors focus-visible:border-accent focus-visible:outline-none {earlier ? 'border-line/70' : 'border-line'}"
>
  <header class="flex h-10 items-center gap-3 px-3.5 {open ? 'border-b border-line' : ''}">
    <button
      class="flex min-w-0 flex-1 items-center gap-2 text-left {earlier ? 'text-muted' : ''}"
      onclick={() => earlier && (expanded = !expanded)}
      aria-expanded={earlier ? expanded : undefined}
      disabled={!earlier}
    >
      <span class="font-medium">{checkLabels[step.check] ?? step.check}</span>
      <span class="truncate font-mono text-muted">{step.target}</span>
      {#if earlier}<span class="text-xs text-subtle">Earlier run</span>{/if}
    </button>
    <span class="font-mono text-xs text-subtle tabular-nums">{time}</span>
    <span class="flex w-16 items-center gap-1.5 text-xs text-muted">
      <span class="size-1.5 rounded-full {step.status === 'ok' ? 'bg-ok' : step.status === 'failed' ? 'bg-crit' : 'animate-pulse bg-subtle'}"></span>
      {step.status === 'running' ? 'Running' : step.status === 'ok' ? 'Done' : 'Failed'}
    </span>
    {#if !earlier}
      <button
        onclick={onrerun}
        disabled={step.status === 'running'}
        class="flex h-6 items-center rounded px-1.5 text-xs text-muted transition-colors hover:bg-raised hover:text-fg disabled:opacity-40"
        aria-label="Re-run {checkLabels[step.check] ?? step.check} on {step.target}">Re-run <span class="ml-1.5 text-subtle">R</span></button>
    {/if}
  </header>

  {#if open}
    {#if step.compared_to && step.status === 'ok'}
      {#if step.changes?.length}
        <div class="border-b border-line bg-accent-soft/40 px-3.5 py-2" aria-label="Changes since previous run">
          <p class="mb-1 text-xs font-medium text-accent">Changed since previous run</p>
          <dl class="space-y-1 font-mono text-xs">
            {#each step.changes as c (c.field)}
              <div class="flex gap-3">
                <dt class="w-20 shrink-0 font-sans font-medium text-subtle">{fieldLabel(c.field)}</dt>
                <dd class="min-w-0 break-all">
                  {#each c.removed ?? [] as v}<div class="text-crit"><span aria-label="removed">− </span>{v}</div>{/each}
                  {#each c.added ?? [] as v}<div class="text-ok"><span aria-label="added">+ </span>{v}</div>{/each}
                </dd>
              </div>
            {/each}
          </dl>
        </div>
      {:else}
        <p class="border-b border-line px-3.5 py-2 text-xs text-subtle">No changes since previous run</p>
      {/if}
    {/if}

    {#if step.status === 'failed'}
      <p class="px-3.5 py-3 text-crit">{step.error}</p>
    {:else if step.result}
      {#if step.result.rcode !== 'NOERROR'}
        <p class="px-3.5 pt-3 text-warn">{step.result.rcode === 'NXDOMAIN' ? 'Domain does not exist (NXDOMAIN)' : step.result.rcode}</p>
      {/if}
      {#each Object.entries(step.result.errors ?? {}) as [type, msg]}
        <p class="px-3.5 pt-2 text-xs text-warn">{type} query failed: {msg}</p>
      {/each}
      <table class="my-1.5 w-full font-mono text-xs">
        <tbody>
          {#each recordOrder as type}
            {#each step.result.records[type] ?? [] as value, i}
              <tr class="align-top">
                <th scope="row" class="w-20 py-1 pl-3.5 text-left font-sans font-medium text-subtle">{i === 0 ? type : ''}</th>
                <td class="py-1 pr-3.5 break-all">{value}</td>
              </tr>
            {/each}
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</article>
