<script lang="ts">
  import Kbd from './Kbd.svelte'
  import { keymap } from './keymap.svelte'

  let dialog: HTMLDialogElement

  const groups = $derived.by(() => {
    const byGroup = new Map<string, typeof keymap.actions>()
    for (const a of keymap.actions) {
      if (!a.keys?.length) continue
      byGroup.set(a.group, [...(byGroup.get(a.group) ?? []), a])
    }
    return [...byGroup]
  })

  $effect(() => {
    if (keymap.helpOpen && !dialog.open) dialog.showModal()
    else if (!keymap.helpOpen && dialog.open) dialog.close()
  })
</script>

<dialog
  bind:this={dialog}
  aria-label="Keyboard shortcuts"
  onclose={() => (keymap.helpOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.helpOpen = false)}
  onkeydown={(e) => e.key === '?' && (keymap.helpOpen = false)}
  class="mx-auto mt-[14vh] w-[min(480px,calc(100vw-32px))] rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <header class="flex h-11 items-center justify-between border-b border-line px-4">
    <h2 class="font-medium">Keyboard shortcuts</h2>
    <button onclick={() => (keymap.helpOpen = false)} class="rounded px-1.5 text-muted hover:text-fg" aria-label="Close">
      <Kbd key="Esc" />
    </button>
  </header>
  <div class="space-y-4 p-4">
    {#each groups as [group, actions]}
      <section>
        <h3 class="mb-1.5 text-[11px] font-medium tracking-wide text-subtle uppercase">{group}</h3>
        <dl class="space-y-1">
          {#each actions as a (a.id)}
            <div class="flex items-center justify-between">
              <dt class="text-muted">{a.title}</dt>
              <dd class="flex gap-1.5">{#each a.keys ?? [] as k}<Kbd key={k} />{/each}</dd>
            </div>
          {/each}
        </dl>
      </section>
    {/each}
  </div>
</dialog>
