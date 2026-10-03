<script lang="ts">
  import { onMount } from 'svelte'

  type Step = {
    id: number
    check: string
    target: string
    status: 'running' | 'ok' | 'failed'
    error?: string
    result?: { rcode: string; records: Record<string, string[]>; errors?: Record<string, string> }
  }
  type Case = { id: number; targets: string[]; steps: Step[] }

  const recordOrder = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

  let input = $state('')
  let current = $state<Case | null>(null)
  let error = $state('')
  // Latest event per Step id; a Step can finish before the POST that started it returns.
  // ponytail: grows for the page's lifetime, bound it when Cases get long-lived tabs
  const seen = new Map<number, Step>()

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

<main class="mx-auto max-w-4xl px-6 py-10">
  <form onsubmit={submit}>
    <label for="target" class="sr-only">Target</label>
    <input
      id="target"
      bind:value={input}
      placeholder="Domain, host, IP…"
      autocomplete="off"
      spellcheck="false"
      class="w-full rounded-md border border-zinc-300 bg-transparent px-3 py-2 font-mono text-sm outline-none focus:border-zinc-500 dark:border-zinc-700 dark:focus:border-zinc-400"
    />
  </form>
  {#if error}<p role="alert" class="mt-2 text-sm text-red-500">{error}</p>{/if}

  {#if current}
    <section class="mt-8">
      <h1 class="text-sm text-zinc-500">Case #{current.id} · {current.targets.join(', ')}</h1>
      {#each current.steps as step (step.id)}
        <article class="mt-4 rounded-md border border-zinc-200 dark:border-zinc-800">
          <header class="flex items-center justify-between border-b border-zinc-200 px-3 py-2 text-sm dark:border-zinc-800">
            <span class="font-medium">DNS Lookup <span class="font-mono text-zinc-500">{step.target}</span></span>
            <span
              class:text-zinc-500={step.status === 'running'}
              class:text-emerald-500={step.status === 'ok'}
              class:text-red-500={step.status === 'failed'}>{step.status}</span>
          </header>
          {#if step.status === 'failed'}
            <p class="px-3 py-2 text-sm text-red-500">{step.error}</p>
          {:else if step.result}
            {#if step.result.rcode !== 'NOERROR'}
              <p class="px-3 py-2 text-sm text-amber-500">{step.result.rcode}</p>
            {/if}
            {#each Object.entries(step.result.errors ?? {}) as [type, msg]}
              <p class="px-3 py-1 text-xs text-amber-500">{type} query failed: {msg}</p>
            {/each}
            <table class="w-full font-mono text-xs">
              <tbody>
                {#each recordOrder as type}
                  {#each step.result.records[type] ?? [] as value, i}
                    <tr class="border-t border-zinc-100 first:border-t-0 dark:border-zinc-900">
                      <th scope="row" class="w-16 px-3 py-1 text-left font-normal text-zinc-500">{i === 0 ? type : ''}</th>
                      <td class="px-3 py-1 break-all">{value}</td>
                    </tr>
                  {/each}
                {/each}
              </tbody>
            </table>
          {/if}
        </article>
      {/each}
    </section>
  {/if}
</main>
