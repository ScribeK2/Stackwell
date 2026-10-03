<!-- Fallback for a Check without its own view: the result as a nested list. -->
<script lang="ts">
  import type { Step } from '../api'
  import Value from './Value.svelte'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()
</script>

<div class="px-3.5 py-2.5 font-mono text-xs"><Value value={step.result} /></div>
