<!--
  Caps a block of result content at about `lines` text lines, with a fade and
  a "Show all (N lines)" toggle. Content that fits renders exactly as before,
  with no toggle. Copying a Step uses the server's text, so it always gets
  the full values.
-->
<script lang="ts">
  import type { Snippet } from 'svelte'

  // lines: how many rows to show; rowHeight: one row's height in px as the
  // view lays it out (16 for plain text-xs lines, more for padded table rows);
  // inset: the content is flush to the card, so pad the toggle like the rows.
  let {
    lines = 8,
    rowHeight = 16,
    inset = false,
    children,
  }: { lines?: number; rowHeight?: number; inset?: boolean; children: Snippet } = $props()
  let inner: HTMLDivElement
  let height = $state(0)
  let expanded = $state(false)

  // The inner block is never capped, so it reports the content's full height
  // whenever that changes (new results, a window resize).
  $effect(() => {
    const ro = new ResizeObserver(() => (height = inner.scrollHeight))
    ro.observe(inner)
    return () => ro.disconnect()
  })

  const cap = $derived(lines * rowHeight)
  // A little slack, so content just over the cap isn't hidden behind a toggle.
  const overflowing = $derived(height > cap * 1.25)
</script>

<div class="relative overflow-hidden" style:max-height={overflowing && !expanded ? `${cap}px` : null}>
  <div bind:this={inner}>{@render children()}</div>
  {#if overflowing && !expanded}
    <div class="pointer-events-none absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-surface"></div>
  {/if}
</div>
{#if overflowing}
  <button
    onclick={() => (expanded = !expanded)}
    aria-expanded={expanded}
    class="mt-0.5 mb-1 rounded px-1 text-xs font-sans text-accent hover:underline {inset ? 'ml-2.5' : ''}"
  >
    {expanded ? 'Show less' : `Show all (${Math.round(height / rowHeight)} ${rowHeight === 16 ? 'lines' : 'rows'})`}
  </button>
{/if}
