<script lang="ts">
  import type { Component } from 'svelte'
  import { fieldLabel, type Step } from './api'
  import { checks, shownOptions } from './checks.svelte'
  import Generic from './results/Generic.svelte'

  type View = Component<{ step: Step; rerun: (options?: Record<string, string>) => void }>
  // A Check's result view is lib/results/<check key>.svelte; anything else uses Generic.
  const views = Object.fromEntries(
    Object.entries(import.meta.glob<{ default: View }>('./results/*.svelte', { eager: true })).map(([path, m]) => [
      path.slice('./results/'.length, -'.svelte'.length),
      m.default,
    ]),
  )

  let {
    step,
    earlier,
    onrerun,
    oncopy,
  }: { step: Step; earlier: boolean; onrerun: (options?: Record<string, string>) => void; oncopy: () => void } = $props()

  // Earlier runs start collapsed; the latest is always open.
  let expanded = $state(false)
  const open = $derived(!earlier || expanded)
  const time = $derived(new Date(step.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }))
  const label = $derived(checks.label(step.check))
  const View = $derived(views[step.check] ?? Generic)
</script>

<article
  data-nav-item
  data-step-id={step.id}
  tabindex="-1"
  aria-label="{label} {step.target} at {time}"
  class="overflow-hidden rounded-lg border bg-surface transition-colors focus-visible:border-accent focus-visible:outline-none {earlier ? 'border-line/70' : 'border-line'}"
>
  <header class="flex h-10 items-center gap-3 px-3.5 {open ? 'border-b border-line' : ''}">
    <button
      class="flex min-w-0 flex-1 items-center gap-2 text-left {earlier ? 'text-muted' : ''}"
      onclick={() => earlier && (expanded = !expanded)}
      aria-expanded={earlier ? expanded : undefined}
      disabled={!earlier}
    >
      <span class="font-medium">{label}</span>
      <span class="truncate font-mono text-muted">{step.target}</span>
      {#each shownOptions(step.check, step.options) as [k, v]}
        <span class="rounded bg-raised px-1.5 text-xs text-muted">{k}: {v}</span>
      {/each}
      {#if earlier}<span class="text-xs text-subtle">Earlier run</span>{/if}
    </button>
    <span class="font-mono text-xs text-subtle tabular-nums">{time}</span>
    <span class="flex w-16 items-center gap-1.5 text-xs text-muted">
      <span
        class="size-1.5 rounded-full {step.status === 'ok'
          ? 'bg-ok'
          : step.status === 'failed'
            ? 'bg-crit'
            : step.status === 'cancelled'
              ? 'bg-subtle'
              : 'animate-pulse bg-subtle'}"
      ></span>
      {{ running: 'Running', ok: 'Done', failed: 'Failed', cancelled: 'Cancelled' }[step.status]}
    </span>
    {#if step.status !== 'running'}
      <button
        onclick={oncopy}
        class="flex h-6 items-center rounded px-1.5 text-xs text-muted transition-colors hover:bg-raised hover:text-fg"
        aria-label="Copy {label} on {step.target}">Copy</button>
    {/if}
    {#if !earlier}
      <button
        onclick={() => onrerun()}
        disabled={step.status === 'running'}
        class="flex h-6 items-center rounded px-1.5 text-xs text-muted transition-colors hover:bg-raised hover:text-fg disabled:opacity-40"
        aria-label="Re-run {label} on {step.target}">Re-run <span class="ml-1.5 text-subtle">R</span></button>
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

    {#if step.status === 'cancelled'}
      <p class="px-3.5 py-3 text-subtle">Cancelled before it finished.</p>
    {:else if step.status === 'failed'}
      <p class="px-3.5 py-3 text-crit">{step.error}</p>
    {:else if step.result}
      <View {step} rerun={onrerun} />
    {/if}
  {/if}
</article>
