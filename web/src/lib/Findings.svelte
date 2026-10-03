<script lang="ts">
  import type { Finding, Step } from './api'
  import { checks } from './checks.svelte'

  let { findings, steps }: { findings: Finding[]; steps: Step[] } = $props()

  const tone = {
    critical: { dot: 'bg-crit', text: 'text-crit', label: 'Critical' },
    warning: { dot: 'bg-warn', text: 'text-warn', label: 'Warning' },
    info: { dot: 'bg-accent', text: 'text-accent', label: 'Info' },
    ok: { dot: 'bg-ok', text: 'text-ok', label: 'OK' },
  }
  const problems = $derived(findings.filter((f) => f.severity !== 'ok'))
  const fine = $derived(findings.filter((f) => f.severity === 'ok'))

  function cite(id: number) {
    const s = steps.find((s) => s.id === id)
    if (!s) return `Step ${id}`
    const t = new Date(s.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    return `${checks.label(s.check)} at ${t}`
  }

  function goTo(id: number) {
    const el = document.querySelector<HTMLElement>(`[data-step-id="${id}"]`)
    el?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    el?.focus({ preventScroll: true })
  }
</script>

<section aria-label="Findings" class="mt-6">
  <h2 class="mb-2 flex items-center gap-2 text-xs font-medium tracking-wide text-subtle uppercase">
    Findings
    {#if problems.length}<span class="rounded bg-raised px-1.5 py-px font-mono text-[11px] tracking-normal text-muted normal-case">{problems.length}</span>{/if}
  </h2>
  <ul class="overflow-hidden rounded-lg border border-line bg-surface">
    {#each problems as f (f.code + f.target + f.citations.join())}
      <li class="border-b border-line px-3.5 py-3 last:border-b-0">
        <div class="flex items-baseline gap-2">
          <span class="flex shrink-0 items-center gap-1.5 text-xs font-medium {tone[f.severity].text}">
            <span class="size-1.5 rounded-full {tone[f.severity].dot}"></span>{tone[f.severity].label}
          </span>
          <span class="font-medium">{f.title}</span>
          <span class="truncate font-mono text-xs text-muted">{f.target}</span>
        </div>
        <p class="mt-1 text-muted">{f.message}</p>
        {#if f.recommendation}<p class="mt-1"><span class="text-subtle">→</span> {f.recommendation}</p>{/if}
        <p class="mt-1.5 flex gap-2 text-xs">
          {#each f.citations as id}
            <button onclick={() => goTo(id)} class="text-subtle underline decoration-line underline-offset-2 hover:text-fg">{cite(id)}</button>
          {/each}
        </p>
      </li>
    {/each}
    {#if fine.length}
      <li class="flex flex-wrap gap-x-4 gap-y-1 px-3.5 py-2.5 text-xs">
        {#each fine as f (f.code + f.target)}
          <button onclick={() => goTo(f.citations[0])} class="flex items-center gap-1.5 text-muted hover:text-fg" title={f.message}>
            <span class="size-1.5 rounded-full bg-ok"></span>{f.title}<span class="font-mono text-subtle">{f.target}</span>
          </button>
        {/each}
      </li>
    {/if}
  </ul>
</section>
