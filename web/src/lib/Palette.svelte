<script lang="ts">
  import Kbd from './Kbd.svelte'
  import { keymap, type Action } from './keymap.svelte'

  let dialog: HTMLDialogElement
  let query = $state('')
  let selected = $state(0)

  const matches = $derived.by(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean)
    return keymap.actions.filter((a) => {
      if (a.id === 'palette') return false // don't list itself
      const hay = `${a.title} ${a.group}`.toLowerCase()
      return words.every((w) => hay.includes(w))
    })
  })

  $effect(() => {
    if (keymap.paletteOpen && !dialog.open) {
      query = ''
      selected = 0
      dialog.showModal()
    } else if (!keymap.paletteOpen && dialog.open) {
      dialog.close()
    }
  })

  $effect(() => {
    query // reset selection whenever the query changes
    selected = 0
  })

  function run(a: Action | undefined) {
    if (!a) return
    keymap.paletteOpen = false
    // Let the dialog close and focus return before the action moves it.
    queueMicrotask(a.run)
  }

  function onkeydown(e: KeyboardEvent) {
    const n = matches.length
    if (e.key === 'ArrowDown' || (e.ctrlKey && e.key === 'n')) {
      selected = n ? (selected + 1) % n : 0
    } else if (e.key === 'ArrowUp' || (e.ctrlKey && e.key === 'p')) {
      selected = n ? (selected - 1 + n) % n : 0
    } else if (e.key === 'Enter') {
      run(matches[selected])
    } else {
      return
    }
    e.preventDefault()
  }
</script>

<dialog
  bind:this={dialog}
  aria-label="Command palette"
  onclose={() => (keymap.paletteOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.paletteOpen = false)}
  class="mx-auto mt-[14vh] w-[min(560px,calc(100vw-32px))] animate-pop overflow-hidden rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <input
    bind:value={query}
    {onkeydown}
    role="combobox"
    aria-expanded="true"
    aria-controls="palette-list"
    aria-activedescendant={matches[selected] ? `palette-${matches[selected].id}` : undefined}
    aria-label="Search actions"
    placeholder="Type a command…"
    autocomplete="off"
    spellcheck="false"
    class="h-12 w-full border-b border-line bg-transparent px-4 text-sm outline-none placeholder:text-subtle focus-visible:outline-none"
  />
  <ul id="palette-list" role="listbox" class="max-h-80 overflow-y-auto p-1.5">
    {#each matches as action, i (action.id)}
      <!-- Options are driven from the combobox input; click is the mouse path. -->
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <li
        id="palette-{action.id}"
        role="option"
        aria-selected={i === selected}
        onclick={() => run(action)}
        onmousemove={() => (selected = i)}
        class="flex h-9 cursor-default items-center justify-between rounded-md px-2.5 {i === selected ? 'bg-raised text-fg' : 'text-muted'}"
      >
        <span>{action.title} <span class="ml-1.5 text-subtle">{action.group}</span></span>
        {#if action.keys?.length}<Kbd key={action.keys[0]} />{/if}
      </li>
    {:else}
      <li class="px-2.5 py-6 text-center text-subtle">No matching commands</li>
    {/each}
  </ul>
</dialog>
