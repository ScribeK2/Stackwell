<script lang="ts">
  import { api } from './api'
  import { copyText, copyWriteup } from './copy.svelte'
  import Kbd from './Kbd.svelte'
  import { keymap } from './keymap.svelte'

  let { caseID }: { caseID: number | undefined } = $props()

  let dialog: HTMLDialogElement
  let format = $state<'markdown' | 'text'>('markdown')
  let text = $state('')

  $effect(() => {
    if (keymap.writeupOpen && !dialog.open) dialog.showModal()
    else if (!keymap.writeupOpen && dialog.open) dialog.close()
  })

  // Cleared on every open, Case or format change; only the latest request's
  // answer is shown, so Copy never takes another Case's or format's text.
  let latest = 0
  $effect(() => {
    if (!keymap.writeupOpen || caseID === undefined) return
    const req = ++latest
    text = ''
    api<{ text: string }>('GET', `/api/cases/${caseID}/writeup?format=${format}`).then(
      (r) => req === latest && (text = r.text),
      () => req === latest && (text = 'Could not build the Write-up.'),
    )
  })

  // The global shortcuts are paused while a dialog is open, so the dialog
  // takes c and C itself.
  function onkeydown(e: KeyboardEvent) {
    if (caseID === undefined || e.ctrlKey || e.metaKey || e.altKey) return
    if (e.key === 'c' || e.key === 'C') {
      e.preventDefault()
      copyWriteup(caseID, e.key === 'c' ? 'markdown' : 'text')
    }
  }
</script>

<dialog
  bind:this={dialog}
  aria-label="Write-up"
  onclose={() => (keymap.writeupOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.writeupOpen = false)}
  {onkeydown}
  class="mx-auto mt-[8vh] w-[min(760px,calc(100vw-32px))] animate-pop rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <header class="flex h-11 items-center gap-2 border-b border-line px-4">
    <h2 class="font-medium">Write-up</h2>
    <div class="ml-3 flex rounded-md border border-line p-0.5 text-xs" role="radiogroup" aria-label="Format">
      {#each [['markdown', 'Markdown'], ['text', 'Plain text']] as [value, label]}
        <button
          role="radio"
          aria-checked={format === value}
          onclick={() => (format = value as 'markdown' | 'text')}
          class="rounded px-2 py-0.5 {format === value ? 'bg-raised text-fg' : 'text-muted hover:text-fg'}">{label}</button>
      {/each}
    </div>
    <button
      disabled={!text}
      onclick={() => copyText(text, format === 'markdown' ? 'Write-up (Markdown)' : 'Write-up (plain text)')}
      class="ml-auto flex h-7 items-center gap-2 rounded-md bg-accent px-2.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-40"
    >
      Copy <Kbd key={format === 'markdown' ? 'c' : 'C'} />
    </button>
  </header>
  <pre class="max-h-[65vh] overflow-auto px-4 py-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">{text}</pre>
</dialog>
