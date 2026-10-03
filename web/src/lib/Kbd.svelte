<script lang="ts">
  import { keyLabel } from './keymap.svelte'
  let { key }: { key: string } = $props()
</script>

<span class="inline-flex gap-0.5">
  {#each keyLabel(key) as part}
    <kbd
      class="inline-flex h-[18px] min-w-[18px] items-center justify-center rounded border border-line bg-raised px-1 font-sans text-[11px] font-medium text-muted"
      >{part}</kbd>
  {/each}
</span>
