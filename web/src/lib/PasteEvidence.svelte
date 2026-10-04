<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError, type Case } from './api'
  import { keymap } from './keymap.svelte'

  let { caseID, onpasted }: { caseID: number | undefined; onpasted: (c: Case) => void } = $props()

  let dialog: HTMLDialogElement
  let area: HTMLTextAreaElement
  let kinds = $state<{ kind: string; label: string }[]>([])
  let kind = $state('')
  let raw = $state('')
  let error = $state('')

  onMount(() => api<{ kind: string; label: string }[]>('GET', '/api/evidence/kinds').then((k) => ((kinds = k), (kind ||= k[0]?.kind ?? ''))))

  $effect(() => {
    if (keymap.evidenceOpen && !dialog.open) {
      error = ''
      dialog.showModal()
      area.focus()
    } else if (!keymap.evidenceOpen && dialog.open) dialog.close()
  })

  async function save(e: SubmitEvent) {
    e.preventDefault()
    if (caseID === undefined) return
    error = ''
    try {
      onpasted(await api<Case>('POST', `/api/cases/${caseID}/evidence`, { kind, raw }))
      raw = ''
      keymap.evidenceOpen = false
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err)
    }
  }
</script>

<dialog
  bind:this={dialog}
  aria-label="Paste Evidence"
  onclose={() => (keymap.evidenceOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.evidenceOpen = false)}
  class="mx-auto mt-[8vh] w-[min(760px,calc(100vw-32px))] animate-pop rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <form onsubmit={save}>
    <header class="flex h-11 items-center gap-3 border-b border-line px-4">
      <h2 class="font-medium">Paste Evidence</h2>
      <select bind:value={kind} aria-label="Kind" class="rounded-md border border-line bg-surface px-1.5 py-0.5 text-xs">
        {#each kinds as k}<option value={k.kind}>{k.label[0].toUpperCase() + k.label.slice(1)}</option>{/each}
      </select>
      <button disabled={!raw.trim()} class="ml-auto h-7 rounded-md bg-accent px-3 text-xs font-medium text-white hover:opacity-90 disabled:opacity-40">
        Add to Case
      </button>
    </header>
    <textarea
      bind:this={area}
      bind:value={raw}
      aria-label="Pasted text"
      spellcheck="false"
      placeholder={kind === 'mail_log'
        ? 'Paste Postfix / Dovecot log lines here, e.g. copied from Graylog. Wrapped lines are fine.'
        : 'Paste the full message headers here (in Gmail: Show original; in Outlook: View message source).'}
      class="block h-[50vh] w-full resize-none bg-transparent px-4 py-3 font-mono text-xs outline-none placeholder:font-sans placeholder:text-subtle focus-visible:outline-none"
      onkeydown={(e) => e.key === 'Enter' && (e.ctrlKey || e.metaKey) && e.currentTarget.form?.requestSubmit()}
    ></textarea>
    {#if error}<p role="alert" class="border-t border-line px-4 py-2 text-xs text-crit">{error}</p>{/if}
  </form>
</dialog>
