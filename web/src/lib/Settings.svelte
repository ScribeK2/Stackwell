<script lang="ts">
  import { api, ApiError } from './api'
  import { keymap } from './keymap.svelte'

  type Settings = {
    secrets_backend: 'keyring' | 'file'
    secrets_location: string
    secrets: { name: string; hint: string; backend: string; available: boolean }[]
  }

  let dialog: HTMLDialogElement
  let settings = $state<Settings | null>(null)
  let error = $state('')
  let name = $state('')
  let value = $state('')
  let replacing = $state<string | null>(null)
  let replacement = $state('') // separate from the add form's value

  $effect(() => {
    if (keymap.settingsOpen && !dialog.open) {
      dialog.showModal()
      load()
    } else if (!keymap.settingsOpen && dialog.open) {
      dialog.close()
    }
  })

  async function attempt(fn: () => Promise<Settings>) {
    error = ''
    try {
      settings = await fn()
      return true
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e)
      return false
    }
  }

  const load = () => attempt(() => api<Settings>('GET', '/api/settings'))

  // Values leave their field as soon as they're sent; only a hint comes back.
  const put = (secret: string, v: string) =>
    attempt(() => api<Settings>('PUT', `/api/settings/secrets/${encodeURIComponent(secret.trim())}`, { value: v }))

  async function add(e: SubmitEvent) {
    e.preventDefault()
    const v = value
    value = ''
    if (await put(name, v)) name = ''
  }

  async function replace(e: SubmitEvent, secret: string) {
    e.preventDefault()
    const v = replacement
    replacement = ''
    if (await put(secret, v)) replacing = null
  }

  const remove = (secret: string) => attempt(() => api<Settings>('DELETE', `/api/settings/secrets/${encodeURIComponent(secret)}`))
</script>

<dialog
  bind:this={dialog}
  aria-label="Settings"
  onclose={() => (keymap.settingsOpen = false)}
  onclick={(e) => e.target === dialog && (keymap.settingsOpen = false)}
  class="mx-auto mt-[12vh] w-[min(560px,calc(100vw-32px))] animate-pop rounded-xl bg-surface p-0 text-fg shadow-pop"
>
  <header class="flex h-11 items-center justify-between border-b border-line px-4">
    <h2 class="font-medium">Settings</h2>
    <button onclick={() => (keymap.settingsOpen = false)} class="rounded px-1.5 text-xs text-muted hover:text-fg" aria-label="Close">Esc</button>
  </header>

  <section class="space-y-3 p-4" aria-labelledby="secrets-heading">
    <div>
      <h3 id="secrets-heading" class="font-medium">Secrets</h3>
      <p class="mt-0.5 text-xs text-muted">API keys and passwords some Checks need. Values are never shown again after you save them.</p>
    </div>

    {#if settings}
      <p class="flex items-center gap-2 rounded-md border border-line bg-raised px-2.5 py-1.5 text-xs">
        <span class="size-1.5 rounded-full {settings.secrets_backend === 'keyring' ? 'bg-ok' : 'bg-warn'}"></span>
        {#if settings.secrets_backend === 'keyring'}
          Stored in your system keyring
        {:else}
          Stored in a file only you can read: <span class="truncate font-mono text-muted">{settings.secrets_location}</span>
        {/if}
      </p>

      <ul class="divide-y divide-line rounded-md border border-line" aria-label="Saved secrets">
        {#each settings.secrets as s (s.name)}
          <li class="flex items-center gap-3 px-2.5 py-2">
            <span class="font-mono text-xs">{s.name}</span>
            {#if replacing === s.name}
              <form onsubmit={(e) => replace(e, s.name)} class="ml-auto flex gap-1.5">
                <input
                  type="password"
                  bind:value={replacement}
                  aria-label="New value for {s.name}"
                  autocomplete="off"
                  class="w-44 rounded border border-line bg-transparent px-2 py-0.5 text-xs outline-none focus:border-accent"
                />
                <button class="rounded px-2 text-xs text-accent hover:bg-raised">Save</button>
                <button type="button" onclick={() => ((replacing = null), (replacement = ''))} class="rounded px-2 text-xs text-muted hover:bg-raised">Cancel</button>
              </form>
            {:else}
              <span class="font-mono text-xs text-subtle" aria-label="masked value">{s.hint}</span>
              {#if !s.available}
                <span class="text-xs text-warn" title="Save it again to store it where secrets are kept now">
                  in the {s.backend === 'keyring' ? 'system keyring' : 'secrets file'}, not reachable now
                </span>
              {/if}
              <span class="ml-auto flex gap-1">
                <button onclick={() => (replacing = s.name)} class="rounded px-2 py-0.5 text-xs text-muted hover:bg-raised hover:text-fg">Replace</button>
                <button onclick={() => remove(s.name)} aria-label="Delete {s.name}" class="rounded px-2 py-0.5 text-xs text-muted hover:bg-raised hover:text-crit">Delete</button>
              </span>
            {/if}
          </li>
        {:else}
          <li class="px-2.5 py-3 text-center text-xs text-subtle">No secrets saved</li>
        {/each}
      </ul>

      <form onsubmit={add} class="flex gap-1.5" aria-label="Add a secret">
        <input
          bind:value={name}
          aria-label="Secret name"
          placeholder="name, e.g. ipinfo_token"
          autocomplete="off"
          spellcheck="false"
          class="w-44 rounded-md border border-line bg-transparent px-2 py-1 font-mono text-xs outline-none placeholder:font-sans placeholder:text-subtle focus:border-accent"
        />
        <input
          type="password"
          bind:value
          aria-label="Secret value"
          placeholder="value"
          autocomplete="off"
          class="min-w-0 flex-1 rounded-md border border-line bg-transparent px-2 py-1 text-xs outline-none placeholder:text-subtle focus:border-accent"
        />
        <button disabled={!name.trim() || !value} class="rounded-md border border-line px-3 text-xs hover:border-line-strong disabled:opacity-40">Save</button>
      </form>
    {/if}
    {#if error}<p role="alert" class="text-xs text-crit">{error}</p>{/if}
  </section>
</dialog>
