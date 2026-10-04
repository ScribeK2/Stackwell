<script lang="ts">
  import type { Run, Step } from './api'

  let { run, steps, oncancel }: { run: Run; steps: Step[]; oncancel: () => void } = $props()

  const mine = $derived(steps.filter((s) => s.run_id === run.id))
  const finished = $derived(mine.filter((s) => s.status !== 'running').length + (run.skipped?.length ?? 0))
  const failed = $derived(mine.filter((s) => s.status === 'failed').length)
  let showBoundary = $state(false)
</script>

<article aria-label="{run.label} run on {run.target}" class="rounded-lg border border-line bg-surface">
  <header class="flex h-10 items-center gap-3 px-3.5">
    <span class="font-medium">{run.label}</span>
    <span class="truncate font-mono text-muted">{run.target}</span>
    <span class="ml-auto flex items-center gap-2 text-xs text-muted">
      {#if run.status === 'running'}
        <span class="h-1 w-24 overflow-hidden rounded-full bg-raised" aria-hidden="true">
          <span class="block h-full origin-left bg-accent transition-[scale] duration-200 ease-out" style="scale: {finished / run.total} 1"></span>
        </span>
        <span class="tabular-nums">{finished}/{run.total}</span>
        <button onclick={oncancel} class="rounded px-1.5 py-0.5 text-muted transition-colors hover:bg-raised hover:text-crit">Cancel</button>
      {:else}
        <span class="size-1.5 rounded-full {run.status === 'done' ? (failed ? 'bg-warn' : 'bg-ok') : 'bg-subtle'}"></span>
        {run.status === 'done' ? (failed ? `Done, ${failed} failed` : 'Done') : 'Cancelled'}
      {/if}
    </span>
  </header>
  {#if run.skipped?.length || run.boundary?.length}
    <div class="space-y-1 border-t border-line px-3.5 py-2 text-xs">
      {#each run.skipped ?? [] as s}
        <p class="text-muted"><span class="text-subtle">Skipped {s.entry}:</span> {s.reason}</p>
      {/each}
      {#if run.boundary?.length}
        <button onclick={() => (showBoundary = !showBoundary)} aria-expanded={showBoundary} class="text-subtle hover:text-fg">
          {showBoundary ? '▾' : '▸'} What this can't see ({run.boundary?.length})
        </button>
        {#if showBoundary}
          <ul class="list-disc space-y-0.5 pl-5 text-muted">
            {#each run.boundary ?? [] as b}<li>{b}</li>{/each}
          </ul>
        {/if}
      {/if}
    </div>
  {/if}
</article>
