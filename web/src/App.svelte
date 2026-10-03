<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError, caseName, type Case, type PlaybookInfo, type Step, type Suggestion } from './lib/api'
  import Findings from './lib/Findings.svelte'
  import Help from './lib/Help.svelte'
  import Kbd from './lib/Kbd.svelte'
  import { checks } from './lib/checks.svelte'
  import Palette from './lib/Palette.svelte'
  import Settings from './lib/Settings.svelte'
  import RunCard from './lib/RunCard.svelte'
  import StepCard from './lib/StepCard.svelte'
  import Suggestions from './lib/Suggestions.svelte'
  import { handleKey, keymap, moveInList, navList, register, type Action } from './lib/keymap.svelte'

  let input = $state('')
  let targetEl: HTMLInputElement
  let current = $state<Case | null>(null)
  let recent = $state<Case[]>([])
  let error = $state('')
  // Latest event per Step id; a Step can finish before the POST that started it returns.
  // ponytail: grows for the page's lifetime, bound it when Cases get long-lived tabs
  const seen = new Map<number, Step>()

  // The server's copy wins once finished: comparisons can settle after the
  // event (an older overlapping run finishing late). A cached event only
  // fills in a Step the server still reports as running.
  // Steps already re-read once because the response predated their finish;
  // never more than once each, so a server that lags can't cause a fetch loop.
  const reread = new Set<number>()

  function show(c: Case | null) {
    let stale = false
    current = c && {
      ...c,
      steps: (c.steps ?? []).map((s) => {
        const known = s.status === 'running' && seen.get(s.id)
        if (known && known.status !== 'running' && !reread.has(s.id)) {
          reread.add(s.id)
          stale = true
        }
        return known || s
      }),
    }
    // A Step finished before this response was built: its Findings aren't in it yet.
    if (c && stale) refresh(c.id)
  }

  async function refresh(id: number) {
    const fresh = await api<Case>('GET', `/api/cases/${id}`).catch(() => null)
    if (fresh && current?.id === id) show(fresh) // the rep may have switched meanwhile
  }

  async function attempt(fn: () => Promise<void>) {
    error = ''
    try {
      await fn()
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e)
    }
  }

  // Submissions run one after another, so a second Target typed before the
  // first Case exists joins that Case instead of starting another.
  let queue = Promise.resolve()

  // Bumped whenever the rep starts or switches Cases. Work queued before a bump
  // still lands on the Case it was meant for, but never repaints the screen.
  let epoch = 0

  // Runs a change on the Case that was open when the rep acted, in queue order.
  function onCase(fn: (id: number) => Promise<Case>) {
    const id = current?.id
    const at = epoch
    if (id === undefined) return
    queue = queue.then(() =>
      attempt(async () => {
        const c = await fn(id)
        if (epoch === at) show(c)
      }),
    )
  }

  // Accepting a suggestion is adding it as a Target (which runs its auto Checks).
  const accept = (s: Suggestion) => onCase((id) => api<Case>('POST', `/api/cases/${id}/targets`, { target: s.value }))
  const dismiss = (s: Suggestion) =>
    onCase((id) => api<Case>('POST', `/api/cases/${id}/suggestions/dismiss`, { value: s.value }))

  // Clears the screen at once and queues behind any submission, so a Target
  // typed straight after n lands in the new Case, not the old one.
  function newCase() {
    epoch++
    show(null)
    targetEl.focus()
    queue = queue.then(() => attempt(() => api('PUT', '/api/active', { case_id: null })))
  }

  function switchTo(id: number) {
    const at = ++epoch
    queue = queue.then(() =>
      attempt(async () => {
        const r = await api<{ case: Case }>('PUT', '/api/active', { case_id: id })
        if (epoch === at) show(r.case) // a later switch or new Case wins
      }),
    )
  }

  const edit = (fields: Partial<Pick<Case, 'title' | 'ticket_ref' | 'status'>>) =>
    onCase((id) => api<Case>('PATCH', `/api/cases/${id}`, fields))

  // Newest first; a Step is "earlier" once a newer Step of the same Check and Target exists.
  const steps = $derived.by(() => {
    const newest = new Set<string>()
    return [...(current?.steps ?? [])].reverse().map((step) => {
      const key = `${step.check} ${step.target}`
      const earlier = newest.has(key)
      newest.add(key)
      return { step, earlier }
    })
  })

  const runCheck = (check: string, target: string, options?: Record<string, string>) =>
    onCase((id) => api<Case>('POST', `/api/cases/${id}/steps`, { check, target, options }))

  // A re-run repeats the Step exactly, options included, unless a view asks for others.
  const rerun = (step: Step, options?: Record<string, string>) => runCheck(step.check, step.target, options ?? step.options)

  function rerunFocused() {
    const id = Number((document.activeElement as HTMLElement | null)?.closest<HTMLElement>('[data-step-id]')?.dataset.stepId)
    const step = current?.steps?.find((s) => s.id === id)
    if (step && step.status !== 'running') rerun(step)
  }


  function submit(e: SubmitEvent) {
    e.preventDefault()
    const value = input.trim()
    if (!value) return
    input = ''
    const at = epoch
    const typedOn = current?.id
    queue = queue.then(() =>
      attempt(async () => {
        // Same epoch: the current Case, which may have been created by an
        // earlier Target in this run. Otherwise the Case it was typed on.
        const id = epoch === at ? current?.id : typedOn
        try {
          const c =
            id === undefined
              ? await api<Case>('POST', '/api/cases', { target: value })
              : await api<Case>('POST', `/api/cases/${id}/targets`, { target: value })
          if (epoch === at) show(c)
        } catch (err) {
          if (!input && epoch === at) input = value // give it back so the rep can fix it
          throw err
        }
      }),
    )
  }

  onMount(() =>
    register(
      { id: 'palette', title: 'Command palette', group: 'General', keys: ['mod+k', ':'], global: true, run: () => (keymap.paletteOpen = true) },
      { id: 'settings', title: 'Settings', group: 'General', keys: [','], run: () => (keymap.settingsOpen = true) },
      { id: 'help', title: 'Show keyboard shortcuts', group: 'General', keys: ['?'], run: () => (keymap.helpOpen = true) },
      { id: 'new-case', title: 'New Case', group: 'Case', keys: ['n'], run: newCase },
      {
        id: 'focus-suggestions',
        title: 'Go to suggested Targets',
        group: 'Case',
        keys: ['s'],
        run: () => document.querySelector<HTMLElement>('[data-suggestion]')?.focus(),
      },
      { id: 'focus-target', title: 'Add a Target', group: 'Case', keys: ['/'], run: () => targetEl.focus() },
      { id: 'rerun', title: 'Re-run focused Step', group: 'Case', keys: ['r'], run: rerunFocused },
      { id: 'next', title: 'Next item', group: 'Navigation', keys: ['j'], run: () => moveInList(1) },
      { id: 'prev', title: 'Previous item', group: 'Navigation', keys: ['k'], run: () => moveInList(-1) },
    ),
  )

  // Resolve/Reopen for the open Case.
  $effect(() => {
    if (!current) return
    const resolved = current.status === 'resolved'
    return register({
      id: 'toggle-status',
      title: resolved ? 'Reopen Case' : 'Resolve Case',
      group: 'Case',
      run: () => edit({ status: resolved ? 'open' : 'resolved' }),
    })
  })

  onMount(() => void checks.load().catch(() => {}))

  let playbooks = $state<PlaybookInfo[]>([])
  // Re-read when the palette opens: the server re-reads the team's folder,
  // so Playbooks a team just pulled in show up without a restart.
  $effect(() => {
    void keymap.paletteOpen
    api<{ playbooks: PlaybookInfo[] }>('GET', '/api/playbooks').then((r) => (playbooks = r.playbooks), () => {})
  })

  const runPlaybook = (playbook: string, target: string) =>
    onCase((id) => api<Case>('POST', `/api/cases/${id}/runs`, { playbook, target }))
  const cancelRun = (run: number) => onCase((id) => api<Case>('POST', `/api/cases/${id}/runs/${run}/cancel`))

  // Playbooks for each Target they apply to, and Cancel for running ones.
  $effect(() => {
    const actions: Action[] = []
    for (const t of current?.targets ?? []) {
      for (const p of playbooks.filter((p) => p.kinds.includes(t.kind))) {
        actions.push({
          id: `playbook-${p.name}-${t.value}`,
          title: `Run ${p.label} Playbook on ${t.value}`,
          group: p.source === 'built-in' ? 'Playbook' : 'Team Playbook',
          run: () => runPlaybook(p.name, t.value),
        })
      }
    }
    for (const r of (current?.runs ?? []).filter((r) => r.status === 'running')) {
      actions.push({ id: `cancel-run-${r.id}`, title: `Cancel ${r.label} on ${r.target}`, group: 'Playbook', run: () => cancelRun(r.id) })
    }
    return register(...actions)
  })

  // Every applicable Check on every Target of the open Case, one entry per
  // choice of a Check's first select option.
  $effect(() => {
    const actions: Action[] = []
    for (const t of current?.targets ?? []) {
      for (const c of checks.list.filter((c) => t.checks.includes(c.key))) {
        const select = c.options.find((o) => o.choices?.length)
        for (const choice of select?.choices ?? [undefined]) {
          const suffix = choice && choice !== select!.default ? ` (${select!.label.toLowerCase()}: ${choice})` : ''
          actions.push({
            id: `run-${c.key}-${choice ?? ''}-${t.value}`,
            title: `Run ${c.label}${suffix} on ${t.value}`,
            group: 'Run',
            run: () => runCheck(c.key, t.value, choice ? { [select!.key]: choice } : undefined),
          })
        }
      }
    }
    return register(...actions)
  })

  // Each suggestion can be added or dismissed from the palette too.
  $effect(() =>
    register(
      ...(current?.suggestions ?? []).flatMap((s): Action[] => [
        { id: `accept-${s.value}`, title: `Add ${s.value}`, group: s.reason, run: () => accept(s) },
        { id: `dismiss-${s.value}`, title: `Dismiss suggestion ${s.value}`, group: s.reason, run: () => dismiss(s) },
      ]),
    ),
  )

  // Recent Cases appear in the palette, searchable by title, Target or ticket reference.
  // Kept fresh ahead of time (not only when the palette opens), so a rep who
  // types straight into the palette finds the Case already listed.
  $effect(() => {
    void [keymap.paletteOpen, current?.id, current?.title, current?.ticket_ref, current?.status]
    api<Case[]>('GET', '/api/cases').then((cs) => (recent = cs), () => {})
  })
  $effect(() => {
    const actions: Action[] = recent
      .filter((c) => c.id !== current?.id)
      .slice(0, 8)
      .map((c) => ({
        id: `case-${c.id}`,
        title: `${caseName(c)}${c.ticket_ref ? ` ${c.ticket_ref}` : ''}`,
        group: c.status === 'resolved' ? 'Resolved Case' : 'Switch Case',
        run: () => switchTo(c.id),
      }))
    return register(...actions)
  })

  onMount(() => {
    api<{ case: Case | null }>('GET', '/api/active').then((r) => show(r.case), () => {})
    const es = new EventSource('/api/events')
    // On (re)connect, events may have been missed: re-fetch the open Case.
    es.onopen = () => current && refresh(current.id)
    es.onmessage = (e) => {
      const { case_id, step } = JSON.parse(e.data) as { case_id: number; step?: Step }
      if (!step) {
        // A Playbook run changed status: its record lives on the Case.
        if (current?.id === case_id) refresh(case_id)
        return
      }
      seen.set(step.id, step)
      if (!current?.steps || current.id !== case_id) return
      const i = current.steps.findIndex((s) => s.id === step.id)
      if (i === -1) current.steps.push(step)
      else current.steps[i] = step
      // A finished run can change how other runs compare: re-read the Case.
      if (step.status !== 'running') refresh(case_id)
    }
    return () => es.close()
  })

  // Inline fields save on Enter or blur; Escape reverts.
  function inlineField(node: HTMLInputElement, field: 'title' | 'ticket_ref') {
    const save = () => current && node.value.trim() !== current[field] && edit({ [field]: node.value })
    const onkey = (e: KeyboardEvent) => {
      if (e.key === 'Enter') node.blur()
      if (e.key === 'Escape' && current) {
        node.value = current[field]
        node.blur()
      }
    }
    node.addEventListener('blur', save)
    node.addEventListener('keydown', onkey)
    return { destroy: () => (node.removeEventListener('blur', save), node.removeEventListener('keydown', onkey)) }
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
      <span class="truncate text-muted">{caseName(current)}</span>
    {/if}
    <div class="ml-auto flex items-center gap-1">
      <button
        onclick={newCase}
        class="flex h-7 items-center gap-2 rounded-md px-2 text-muted transition-colors hover:bg-raised hover:text-fg"
      >
        New Case <Kbd key="n" />
      </button>
      <button
        onclick={() => (keymap.paletteOpen = true)}
        class="flex h-7 items-center gap-2 rounded-md border border-line px-2 text-muted transition-colors hover:border-line-strong hover:text-fg"
      >
        Commands <Kbd key="mod+k" />
      </button>
      <button
        onclick={() => (keymap.settingsOpen = true)}
        aria-label="Settings"
        class="flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-raised hover:text-fg"
      >
        <svg viewBox="0 0 16 16" class="size-4" aria-hidden="true">
          <path d="M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
          <circle cx="10" cy="4.5" r="1.5" stroke="currentColor" stroke-width="1.4" fill="none" />
          <circle cx="6" cy="11.5" r="1.5" stroke="currentColor" stroke-width="1.4" fill="none" />
        </svg>
      </button>
      <button
        onclick={() => (keymap.helpOpen = true)}
        aria-label="Keyboard shortcuts"
        class="flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-raised hover:text-fg">?</button>
    </div>
  </header>

  <main class="mx-auto w-full max-w-4xl flex-1 px-4 py-8 sm:px-6">
    {#if current}
      <section aria-label="Case details" class="mb-6">
        <div class="flex items-center gap-3">
          <input
            aria-label="Case title"
            value={current.title}
            use:inlineField={'title'}
            placeholder={current.targets[0]?.value ?? 'Untitled Case'}
            class="min-w-0 flex-1 rounded-md bg-transparent px-1.5 py-1 -ml-1.5 text-lg font-semibold tracking-tight outline-none placeholder:text-fg hover:bg-raised focus:bg-raised focus-visible:outline-none"
          />
          <input
            aria-label="Ticket reference"
            value={current.ticket_ref}
            use:inlineField={'ticket_ref'}
            placeholder="Ticket ref"
            class="w-32 rounded-md border border-line bg-transparent px-2 py-1 font-mono text-xs outline-none placeholder:font-sans placeholder:text-subtle hover:border-line-strong focus:border-accent focus-visible:outline-none"
          />
          <button
            onclick={() => edit({ status: current?.status === 'resolved' ? 'open' : 'resolved' })}
            class="flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors {current.status === 'resolved'
              ? 'border-ok/40 text-ok hover:bg-ok/10'
              : 'border-line text-muted hover:border-line-strong hover:text-fg'}"
          >
            {#if current.status === 'resolved'}
              <svg viewBox="0 0 16 16" class="size-3.5" aria-hidden="true"><path d="m3.5 8.5 3 3 6-7" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round" /></svg>
              Resolved
            {:else}
              Resolve
            {/if}
          </button>
        </div>
        <ul class="mt-2 flex flex-wrap gap-1.5" aria-label="Targets">
          {#each current.targets as t (t.value)}
            <li class="flex h-6 items-center gap-1.5 rounded-md border border-line bg-surface px-2 font-mono text-xs">
              {t.value}<span class="font-sans text-[10px] font-medium tracking-wide text-subtle uppercase">{t.kind}</span>
            </li>
          {/each}
        </ul>
        {#if current.suggestions?.length}
          <Suggestions suggestions={current.suggestions} onaccept={accept} ondismiss={dismiss} />
        {/if}
      </section>
    {/if}

    <form onsubmit={submit} class="group relative">
      <label for="target" class="sr-only">Target</label>
      <svg viewBox="0 0 16 16" class="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-subtle" aria-hidden="true">
        {#if current}
          <path d="M8 3.5v9M3.5 8h9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        {:else}
          <circle cx="7" cy="7" r="4.5" stroke="currentColor" stroke-width="1.5" fill="none" />
          <path d="m10.5 10.5 3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
        {/if}
      </svg>
      <input
        id="target"
        bind:this={targetEl}
        bind:value={input}
        placeholder={current ? 'Add a Target to this Case' : 'Enter a domain, host, IP or email to start a Case'}
        autocomplete="off"
        spellcheck="false"
        class="h-11 w-full rounded-lg border border-line bg-surface pr-12 pl-10 font-mono text-sm shadow-xs transition-colors outline-none placeholder:font-sans placeholder:text-subtle hover:border-line-strong focus:border-accent focus:ring-3 focus:ring-accent-soft focus-visible:outline-none"
      />
      <span class="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 group-focus-within:hidden"><Kbd key="/" /></span>
    </form>
    {#if error}<p role="alert" class="mt-2 text-crit">{error}</p>{/if}

    {#if current?.runs?.length}
      <section aria-label="Playbook runs" class="mt-6 space-y-2">
        {#each [...current.runs].reverse().slice(0, 3) as run (run.id)}
          <RunCard {run} steps={current.steps ?? []} oncancel={() => cancelRun(run.id)} />
        {/each}
      </section>
    {/if}

    {#if current?.findings?.length}
      <Findings findings={current.findings} steps={current.steps ?? []} />
    {/if}

    {#if current}
      <section class="mt-6" aria-label="Steps">
        <div use:navList class="space-y-3">
          {#each steps as { step, earlier } (step.id)}
            <StepCard {step} {earlier} onrerun={(options) => rerun(step, options)} />
          {:else}
            <p class="py-6 text-center text-subtle">No Checks apply to these Targets yet.</p>
          {/each}
        </div>
      </section>
    {:else}
      <p class="mt-16 text-center text-subtle">
        Type a Target and press <Kbd key="Enter" /> to start a Case. <Kbd key="?" /> for shortcuts.
      </p>
    {/if}
  </main>
</div>

<Palette />
<Help />
<Settings />
