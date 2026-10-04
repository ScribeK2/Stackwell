<script lang="ts">
  import { api, ApiError, caseName, type Case } from './api'
  import { keymap } from './keymap.svelte'

  type Listed = Case & { last_active_at: string; matched_by?: string }
  let { onopen, onpurged }: { onopen: (id: number) => void; onpurged: () => void } = $props()

  let dialog: HTMLDialogElement
  let search: HTMLInputElement
  let q = $state('')
  let resolved = $state(false)
  let cases = $state<Listed[]>([])
  let selected = $state(0)
  let error = $state('')

  $effect(() => {
    if (keymap.historyOpen && !dialog.open) {
      dialog.showModal()
      search.focus()
      preview = null
    } else if (!keymap.historyOpen && dialog.open) dialog.close()
  })

  // Re-query as the rep types; only the latest answer is shown, and Enter
  // waits for it rather than opening a Case from the previous list.
  let latest = 0
  let pending = $state(false)
  let reload = $state(0)
  $effect(() => {
    void reload
    if (!keymap.historyOpen) return
    const params = new URLSearchParams()
    if (q.trim()) params.set('q', q.trim())
    if (resolved) params.set('resolved', '1')
    const req = ++latest
    pending = true
    const t = setTimeout(
      () =>
        api<Listed[]>('GET', `/api/cases?${params}`).then(
          (cs) => req === latest && ((cases = cs), (selected = 0), (pending = false)),
          () => req === latest && (pending = false),
        ),
      q ? 120 : 0,
    )
    return () => clearTimeout(t)
  })

  function open(c: Listed | undefined) {
    if (!c) return
    keymap.historyOpen = false
    onopen(c.id)
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') selected = Math.min(cases.length - 1, selected + 1)
    else if (e.key === 'ArrowUp') selected = Math.max(0, selected - 1)
    else if (e.key === 'Enter') !pending && open(cases[selected])
    else return
    e.preventDefault()
  }

  const ago = (t: string) => {
    const d = (Date.now() - new Date(t).getTime()) / 86400000
    return d < 1 ? 'today' : d < 2 ? 'yesterday' : `${Math.floor(d)} days ago`
  }

  // Purge: preview first, then an explicit second step.
  let days = $state(90)
  let preview = $state<number | null>(null)
  let cutoff = '' // from the preview: confirm deletes exactly what it counted
  async function purge(confirm: boolean) {
    error = ''
    try {
      const r = await api<{ would_delete?: number; deleted?: number; cutoff?: string }>('POST', '/api/cases/purge', {
        older_than_days: days,
        confirm,
        cutoff: confirm ? cutoff : undefined,
      })
      if (confirm) {
        preview = null
        onpurged()
        reload++ // the same search again
      } else {
        preview = r.would_delete ?? 0
        cutoff = r.cutoff ?? ''
      }
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err)
    }
  }
</script>

<dialog
  bind:this={dialog}
  aria-label="Cases"
  onclose={() => (keymap.historyOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.historyOpen = false)}
  class="mx-auto mt-[8vh] w-[min(680px,calc(100vw-32px))] animate-pop overflow-hidden rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <div class="flex items-center gap-3 border-b border-line px-4">
    <input
      bind:this={search}
      bind:value={q}
      {onkeydown}
      aria-label="Search Cases"
      placeholder="Search by Target, ticket, title or Finding…"
      autocomplete="off"
      spellcheck="false"
      class="h-12 min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-subtle focus-visible:outline-none"
    />
    <label class="flex shrink-0 items-center gap-1.5 text-xs text-muted">
      <input type="checkbox" bind:checked={resolved} class="accent-[var(--color-accent)]" /> Show resolved
    </label>
  </div>

  <ul class="max-h-[50vh] overflow-y-auto p-1.5" role="listbox" aria-label="Cases found">
    {#each cases as c, i (c.id)}
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <li
        role="option"
        aria-selected={i === selected}
        onclick={() => open(c)}
        onmousemove={() => (selected = i)}
        class="cursor-default rounded-md px-2.5 py-2 {i === selected ? 'bg-raised' : ''}"
      >
        <div class="flex items-baseline gap-2">
          <span class="truncate font-medium">{caseName(c)}</span>
          {#if c.ticket_ref}<span class="font-mono text-xs text-muted">{c.ticket_ref}</span>{/if}
          {#if c.status === 'resolved'}<span class="rounded bg-ok/10 px-1.5 text-[11px] text-ok">Resolved</span>{/if}
          <span class="ml-auto shrink-0 text-xs text-subtle">{ago(c.last_active_at)}</span>
        </div>
        <div class="mt-0.5 flex gap-2 text-xs">
          <span class="truncate font-mono text-subtle">{c.targets.map((t) => t.value).join(', ')}</span>
          {#if c.matched_by}<span class="ml-auto shrink-0 text-accent">{c.matched_by}</span>{/if}
        </div>
      </li>
    {:else}
      <li class="px-2.5 py-8 text-center text-sm text-subtle">{q ? 'No Cases match' : 'No Cases yet'}</li>
    {/each}
  </ul>

  <footer class="flex flex-wrap items-center gap-2 border-t border-line px-4 py-2.5 text-xs text-muted">
    <span>Delete Cases not touched for</span>
    <input
      type="number"
      min="1"
      bind:value={days}
      oninput={() => (preview = null)}
      aria-label="Days"
      class="w-16 rounded border border-line bg-transparent px-1.5 py-0.5 text-fg outline-none focus:border-accent"
    />
    <span>days</span>
    {#if preview === null}
      <button onclick={() => purge(false)} class="rounded-md border border-line px-2 py-0.5 hover:border-line-strong hover:text-fg">Check</button>
    {:else if preview === 0}
      <span class="text-subtle">Nothing that old.</span>
    {:else}
      <button onclick={() => purge(true)} class="rounded-md bg-crit px-2 py-0.5 font-medium text-white hover:opacity-90">
        Delete {preview} {preview === 1 ? 'Case' : 'Cases'} for good
      </button>
      <button onclick={() => (preview = null)} class="px-1 hover:text-fg">Cancel</button>
    {/if}
    {#if error}<span role="alert" class="text-crit">{error}</span>{/if}
  </footer>
</dialog>
