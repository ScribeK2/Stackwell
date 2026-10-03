<script lang="ts">
  import Value from './Value.svelte'
  let { value }: { value: unknown } = $props()
</script>

{#if Array.isArray(value)}
  {#if value.every((v) => v === null || typeof v !== 'object')}
    <span class="break-all">{value.join(', ') || '—'}</span>
  {:else}
    <ol class="space-y-1.5">{#each value as v}<li><Value value={v} /></li>{/each}</ol>
  {/if}
{:else if value && typeof value === 'object'}
  <dl class="space-y-1">
    {#each Object.entries(value) as [k, v]}
      <div class="flex gap-3">
        <dt class="w-32 shrink-0 font-sans font-medium text-subtle">{k}</dt>
        <dd class="min-w-0 flex-1"><Value value={v} /></dd>
      </div>
    {/each}
  </dl>
{:else}
  <span class="break-all">{String(value ?? '—')}</span>
{/if}
