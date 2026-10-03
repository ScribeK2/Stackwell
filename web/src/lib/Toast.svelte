<script lang="ts">
  import { toast } from './copy.svelte'
</script>

<div aria-live="polite" class="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex justify-center">
  {#if toast.message}
    <p class="animate-pop rounded-lg bg-fg px-3 py-1.5 text-xs font-medium text-bg shadow-pop">{toast.message}</p>
  {/if}
</div>
