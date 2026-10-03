<script lang="ts">
  import type { Component } from 'svelte'
  import type { Evidence } from './api'

  type View = Component<{ evidence: Evidence }>
  // An analyser's view is lib/evidence/<kind>.svelte.
  const views = Object.fromEntries(
    Object.entries(import.meta.glob<{ default: View }>('./evidence/*.svelte', { eager: true })).map(([path, m]) => [
      path.slice('./evidence/'.length, -'.svelte'.length),
      m.default,
    ]),
  )
  const labels: Record<string, string> = { email_headers: 'Email headers', mail_log: 'Mail log' }

  let { evidence }: { evidence: Evidence } = $props()
  let showRaw = $state(false)
  const View = $derived(views[evidence.kind])
</script>

<article
  data-evidence-id={evidence.id}
  tabindex="-1"
  aria-label="{labels[evidence.kind] ?? evidence.kind} #{evidence.id}"
  class="overflow-hidden rounded-lg border border-line bg-surface focus-visible:border-accent focus-visible:outline-none"
>
  <header class="flex h-10 items-center gap-3 border-b border-line px-3.5">
    <span class="font-medium">{labels[evidence.kind] ?? evidence.kind}</span>
    <span class="text-xs text-subtle">pasted {new Date(evidence.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
    <button onclick={() => (showRaw = !showRaw)} aria-expanded={showRaw} class="ml-auto rounded px-1.5 text-xs text-muted hover:bg-raised hover:text-fg">
      {showRaw ? 'Hide' : 'Show'} pasted text
    </button>
  </header>
  {#if View && evidence.analysis}<View {evidence} />{/if}
  {#if showRaw}
    <pre class="max-h-72 overflow-auto border-t border-line px-3.5 py-2 font-mono text-[11px] whitespace-pre-wrap text-muted">{evidence.raw}</pre>
  {/if}
</article>
