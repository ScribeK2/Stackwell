<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from './api'
  import { toast } from './copy.svelte'
  import Kbd from './Kbd.svelte'
  import { register } from './keymap.svelte'

  type Update = { current: string; latest?: string; available: boolean; can_install?: boolean; download_url?: string }
  let update = $state<Update | null>(null)
  let installing = $state(false)

  onMount(() => void api<Update>('GET', '/api/update').then((u) => (update = u), () => {}))

  async function install() {
    if (!update?.available || installing) return
    if (!update.can_install) {
      window.open(update.download_url, '_blank', 'noopener')
      return
    }
    installing = true
    try {
      await api('POST', '/api/update/install')
      toast.show(`Installing ${update.latest}; Stackwell will restart`)
      // The new version comes back on the same address: wait for it, then reload.
      const want = update.latest
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 500))
        const h = await api<{ version: string }>('GET', '/api/health').catch(() => null)
        if (h?.version === want) return location.reload()
      }
      toast.show('The update is installed; restart Stackwell to use it')
    } catch (e) {
      toast.show(e instanceof ApiError ? e.message : String(e))
    } finally {
      installing = false
    }
  }

  $effect(() => {
    if (!update?.available) return
    return register({ id: 'update', title: `Update Stackwell to ${update.latest}`, group: 'General', keys: ['U'], run: install })
  })
</script>

{#if update?.available}
  <button
    onclick={install}
    disabled={installing}
    title={update.can_install ? `Download, verify and restart into ${update.latest}` : 'Opens the release page to download it'}
    class="flex h-7 items-center gap-2 rounded-md bg-accent-soft px-2.5 text-xs font-medium text-accent transition-colors hover:bg-accent hover:text-white disabled:opacity-60"
  >
    {installing ? 'Updating…' : update.can_install ? `Update to ${update.latest}` : `Download ${update.latest}`}
    {#if update.can_install && !installing}<Kbd key="U" />{/if}
  </button>
{/if}
