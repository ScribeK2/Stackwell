<script lang="ts">
  import type { Suggestion } from './api'
  import Kbd from './Kbd.svelte'

  let {
    suggestions,
    onaccept,
    ondismiss,
  }: { suggestions: Suggestion[]; onaccept: (s: Suggestion) => void; ondismiss: (s: Suggestion) => void } = $props()

  // Keys on a focused suggestion: Enter/a adds it, x/Delete dismisses it,
  // arrows move between them. Focus then moves to a neighbour, so a run of
  // suggestions can be triaged without the mouse.
  function onkeydown(e: KeyboardEvent, s: Suggestion, i: number) {
    const items = [...(e.currentTarget as HTMLElement).parentElement!.parentElement!.querySelectorAll<HTMLElement>('[data-suggestion]')]
    const focusNear = () => queueMicrotask(() => (items[i + 1] ?? items[i - 1])?.focus())
    if (e.key === 'Enter' || e.key === 'a') {
      onaccept(s)
      focusNear()
    } else if (e.key === 'x' || e.key === 'Delete' || e.key === 'Backspace') {
      ondismiss(s)
      focusNear()
    } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      items[i + 1]?.focus()
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      items[i - 1]?.focus()
    } else {
      return
    }
    e.preventDefault()
    e.stopPropagation()
  }
</script>

<div class="mt-2 flex flex-wrap items-center gap-1.5" aria-label="Suggested Targets" role="group">
  <span class="mr-0.5 text-xs text-subtle">Suggested <Kbd key="s" /></span>
  {#each suggestions as s, i (s.value)}
    <span class="flex h-6 items-center rounded-md border border-dashed border-line-strong text-xs">
      <button
        data-suggestion
        onclick={() => onaccept(s)}
        onkeydown={(e) => onkeydown(e, s, i)}
        title="{s.reason} — Enter adds, x dismisses"
        aria-label="Add {s.value} ({s.reason})"
        class="flex h-full items-center gap-1.5 rounded-l-md pr-1.5 pl-2 text-muted transition-colors hover:bg-raised hover:text-fg focus-visible:bg-raised focus-visible:text-fg focus-visible:outline-offset-0"
      >
        <span aria-hidden="true">+</span><span class="font-mono">{s.value}</span>
        <span class="text-subtle">{s.reason.replace(/ (of|for) .*/, '')}</span>
      </button>
      <button
        onclick={() => ondismiss(s)}
        aria-label="Dismiss {s.value}"
        class="flex h-full items-center rounded-r-md px-1.5 text-subtle transition-colors hover:bg-raised hover:text-fg">×</button>
    </span>
  {/each}
</div>
