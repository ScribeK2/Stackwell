<script lang="ts">
  import { onMount } from 'svelte'
  import Help from './lib/Help.svelte'
  import Kbd from './lib/Kbd.svelte'
  import Palette from './lib/Palette.svelte'
  import { handleKey, keymap, moveInList, navList, register } from './lib/keymap.svelte'

  type Step = {
    id: number
    check: string
    target: string
    status: 'running' | 'ok' | 'failed'
    error?: string
    result?: { rcode: string; records: Record<string, string[]>; errors?: Record<string, string> }
  }
  type Case = { id: number; targets: string[]; steps: Step[] }

  const checkLabels: Record<string, string> = { dns_lookup: 'DNS Lookup' }
  const recordOrder = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

  let input = $state('')
  let targetEl: HTMLInputElement
  let current = $state<Case | null>(null)
  let error = $state('')
  // Latest event per Step id; a Step can finish before the POST that started it returns.
  // ponytail: grows for the page's lifetime, bound it when Cases get long-lived tabs
  const seen = new Map<number, Step>()

  onMount(() =>
    register(
      { id: 'palette', title: 'Command palette', group: 'General', keys: ['mod+k', ':'], global: true, run: () => (keymap.paletteOpen = true) },
      { id: 'help', title: 'Show keyboard shortcuts', group: 'General', keys: ['?'], run: () => (keymap.helpOpen = true) },
      { id: 'focus-target', title: 'Focus target field', group: 'Case', keys: ['/'], run: () => targetEl.focus() },
      { id: 'next', title: 'Next item', group: 'Navigation', keys: ['j'], run: () => moveInList(1) },
      { id: 'prev', title: 'Previous item', group: 'Navigation', keys: ['k'], run: () => moveInList(-1) },
    ),
  )

  onMount(() => {
    const es = new EventSource('/api/events')
    // On (re)connect, events may have been missed: re-fetch the open Case.
    es.onopen = async () => {
      if (!current) return
      const res = await fetch(`/api/cases/${current.id}`)
      if (res.ok) current = await res.json()
    }
    es.onmessage = (e) => {
      const { case_id, step } = JSON.parse(e.data) as { case_id: number; step: Step }
      seen.set(step.id, step)
      if (!current || current.id !== case_id) return
      const i = current.steps.findIndex((s) => s.id === step.id)
      if (i === -1) current.steps.push(step)
      else current.steps[i] = step
    }
    return () => es.close()
  })

  async function submit(e: SubmitEvent) {
    e.preventDefault()
    const target = input.trim()
    if (!target) return
    error = ''
    let res: Response, body: any
    try {
      res = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      })
      body = await res.json()
    } catch {
      error = 'Stackwell is not responding.'
      return
    }
    if (!res.ok) {
      error = body.error
      return
    }
    current = { ...body, steps: body.steps.map((s: Step) => seen.get(s.id) ?? s) }
    input = ''
  }
</script>

<svelte:window onkeydown={handleKey} />

<div class="flex min-h-dvh flex-col">
  <header class="sticky top-0 z-10 flex h-11 items-center gap-3 border-b border-line bg-bg/85 px-4 backdrop-blur">
    <span class="flex items-center gap-2 font-semibold tracking-tight">
      <svg viewBox="0 0 16 16" class="size-4 text-accent" aria-hidden="true">
        <path d="M3 5h10M3 8h10M3 11h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" fill="none" />
      </svg>
      Stackwell
    </span>
    {#if current}
      <span class="text-subtle">/</span>
      <span class="truncate text-muted">Case #{current.id}</span>
    {/if}
    <div class="ml-auto flex items-center gap-1">
      <button
        onclick={() => (keymap.paletteOpen = true)}
        class="flex h-7 items-center gap-2 rounded-md border border-line px-2 text-muted transition-colors hover:border-line-strong hover:text-fg"
      >
        Commands <Kbd key="mod+k" />
      </button>
      <button
        onclick={() => (keymap.helpOpen = true)}
        aria-label="Keyboard shortcuts"
        class="flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-raised hover:text-fg">?</button>
    </div>
  </header>

  <main class="mx-auto w-full max-w-4xl flex-1 px-4 py-8 sm:px-6">
    <form onsubmit={submit} class="group relative">
      <label for="target" class="sr-only">Target</label>
      <svg viewBox="0 0 16 16" class="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-subtle" aria-hidden="true">
        <circle cx="7" cy="7" r="4.5" stroke="currentColor" stroke-width="1.5" fill="none" />
        <path d="m10.5 10.5 3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
      </svg>
      <input
        id="target"
        bind:this={targetEl}
        bind:value={input}
        placeholder="Enter a domain, host or IP"
        autocomplete="off"
        spellcheck="false"
        class="h-11 w-full rounded-lg border border-line bg-surface pr-12 pl-10 font-mono text-sm shadow-xs transition-colors outline-none placeholder:font-sans placeholder:text-subtle hover:border-line-strong focus:border-accent focus:ring-3 focus:ring-accent-soft focus-visible:outline-none"
      />
      <span class="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 group-focus-within:hidden"><Kbd key="/" /></span>
    </form>
    {#if error}<p role="alert" class="mt-2 text-crit">{error}</p>{/if}

    {#if current}
      <section class="mt-8" aria-label="Steps">
        <h1 class="mb-3 flex items-baseline gap-2">
          <span class="font-medium">Case #{current.id}</span>
          <span class="font-mono text-muted">{current.targets.join(', ')}</span>
        </h1>
        <div use:navList class="space-y-3">
          {#each current.steps as step (step.id)}
            <article
              data-nav-item
              tabindex="-1"
              aria-label="{checkLabels[step.check] ?? step.check} {step.target}"
              class="overflow-hidden rounded-lg border border-line bg-surface transition-colors focus-visible:border-accent focus-visible:outline-none"
            >
              <header class="flex h-10 items-center justify-between border-b border-line px-3.5">
                <span class="font-medium">
                  {checkLabels[step.check] ?? step.check}
                  <span class="ml-1 font-mono font-normal text-muted">{step.target}</span>
                </span>
                <span class="flex items-center gap-1.5 text-xs text-muted">
                  <span
                    class="size-1.5 rounded-full {step.status === 'ok' ? 'bg-ok' : step.status === 'failed' ? 'bg-crit' : 'animate-pulse bg-subtle'}"
                  ></span>
                  {step.status === 'running' ? 'Running' : step.status === 'ok' ? 'Done' : 'Failed'}
                </span>
              </header>
              {#if step.status === 'failed'}
                <p class="px-3.5 py-3 text-crit">{step.error}</p>
              {:else if step.result}
                {#if step.result.rcode !== 'NOERROR'}
                  <p class="px-3.5 pt-3 text-warn">{step.result.rcode === 'NXDOMAIN' ? 'Domain does not exist (NXDOMAIN)' : step.result.rcode}</p>
                {/if}
                {#each Object.entries(step.result.errors ?? {}) as [type, msg]}
                  <p class="px-3.5 pt-2 text-xs text-warn">{type} query failed: {msg}</p>
                {/each}
                <table class="my-1.5 w-full font-mono text-xs">
                  <tbody>
                    {#each recordOrder as type}
                      {#each step.result.records[type] ?? [] as value, i}
                        <tr class="align-top">
                          <th scope="row" class="w-20 py-1 pl-3.5 text-left font-sans font-medium text-subtle">{i === 0 ? type : ''}</th>
                          <td class="py-1 pr-3.5 break-all">{value}</td>
                        </tr>
                      {/each}
                    {/each}
                  </tbody>
                </table>
              {/if}
            </article>
          {/each}
        </div>
      </section>
    {:else}
      <p class="mt-16 text-center text-subtle">
        Type a target and press <Kbd key="Enter" /> to start a Case. <Kbd key="?" /> for shortcuts.
      </p>
    {/if}
  </main>
</div>

<Palette />
<Help />
