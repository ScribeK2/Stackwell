<script lang="ts">
  import Clamp from '../Clamp.svelte'
  import type { Step } from '../api'
  let { step, rerun }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Term = { qualifier?: string; name: string; value?: string; lookup?: boolean; void?: boolean; target?: Node }
  type Node = { domain: string; record?: string; terms?: Term[]; error?: string }
  type Spf = {
    records: string[]
    tree?: Node
    all?: string
    lookups: number
    void_lookups: number
    truncated: boolean
    errors: string[]
    failed: string[]
    error?: string
  }
  type Key = { selector: string; cname?: string; record: string; key_type: string; bits?: number; revoked: boolean; error?: string }
  type Dkim = { checked: string[]; custom: string[]; keys: Key[]; failed: string[] }
  type Dmarc = {
    records: string[]
    policy?: string
    subdomain_policy?: string
    pct: number
    rua: string[]
    ruf: string[]
    adkim?: string
    aspf?: string
    error?: string
  }
  const r = $derived(step.result as { scope: string; spf?: Spf; dkim?: Dkim; dmarc?: Dmarc })

  let more = $state('')
  function checkMore(e: SubmitEvent) {
    e.preventDefault()
    const extra = [step.options.selectors ?? '', more].join(' ').trim()
    if (more.trim()) rerun({ scope: step.options.scope, selectors: extra })
  }

  const allTone: Record<string, string> = { '-all': 'text-ok', '~all': 'text-muted', '?all': 'text-warn', '+all': 'text-crit' }
  const alignment = (v?: string) => (v === 's' ? 'strict' : 'relaxed')
</script>

{#snippet tree(node: Node, depth: number)}
  {#each node.terms ?? [] as t}
    <div style:padding-left="{depth * 14}px" class="py-0.5">
      <span class={t.name === 'all' ? allTone[(t.qualifier || '+') + 'all'] : t.void ? 'text-warn' : ''}>
        {t.qualifier ?? ''}{t.name}{t.value ? (t.name === 'redirect' || t.name === 'exp' ? '=' : t.value.startsWith('/') ? '' : ':') + t.value : ''}
      </span>
      {#if t.lookup}<span class="ml-1.5 font-sans text-[11px] text-subtle">lookup{t.void ? ', void' : ''}</span>{/if}
      {#if t.target?.error}<span class="ml-1.5 font-sans text-crit">{t.target.error}</span>{/if}
    </div>
    {#if t.target && !t.target.error}{@render tree(t.target, depth + 1)}{/if}
  {/each}
{/snippet}

<div class="divide-y divide-line text-xs">
  {#if r.spf}
    {@const s = r.spf}
    <section class="px-3.5 py-2.5">
      <h3 class="mb-1.5 flex items-baseline gap-3 font-medium">
        SPF
        {#if s.tree}
          <span class="font-normal text-subtle">
            <span class={s.lookups > 10 ? 'text-crit' : ''}>{s.truncated ? '30+' : s.lookups}/10 lookups</span>
            · <span class={s.void_lookups > 2 ? 'text-crit' : ''}>{s.void_lookups} void</span>
            {#if s.all}· <span class="font-mono {allTone[s.all]}">{s.all}</span>{/if}
          </span>
        {/if}
      </h3>
      {#if s.error}
        <p class="text-warn">Lookup failed: {s.error}</p>
      {:else if s.records.length === 0}
        <p class="text-subtle">No SPF record.</p>
      {:else if s.records.length > 1}
        <p class="mb-1 text-crit">{s.records.length} SPF records; only one is allowed.</p>
        {#each s.records as rec}<p class="font-mono break-all">{rec}</p>{/each}
      {:else if s.tree}
        <div class="mb-1.5 font-mono break-all text-muted"><Clamp lines={3}>{s.tree.record}</Clamp></div>
        <div class="font-mono break-all"><Clamp lines={12} rowHeight={20}>{@render tree(s.tree, 0)}</Clamp></div>
      {/if}
      {#each s.errors as e}<p class="mt-1 text-crit">{e}</p>{/each}
      {#each s.failed as f}<p class="mt-1 text-warn">No answer: {f}</p>{/each}
    </section>
  {/if}

  {#if r.dkim}
    {@const d = r.dkim}
    <section class="px-3.5 py-2.5">
      <h3 class="mb-1.5 font-medium">DKIM <span class="font-normal text-subtle">· {d.checked.length} selectors checked</span></h3>
      {#if d.keys.length}
        <table class="mb-2 w-full">
          <tbody>
            {#each d.keys as k}
              <tr class="align-top">
                <th scope="row" class="w-32 py-1 pr-2 text-left font-mono font-normal">{k.selector}</th>
                <td class="py-1">
                  {#if k.revoked}
                    <span class="text-muted">revoked (empty p=)</span>
                  {:else if k.error}
                    <span class="text-warn">{k.key_type}: {k.error}</span>
                  {:else}
                    <span class={k.bits && k.bits < 1024 ? 'text-crit' : k.bits && k.bits < 2048 ? 'text-warn' : ''}>
                      {k.key_type.toUpperCase()}{k.bits ? ` ${k.bits}-bit` : ''}
                    </span>
                  {/if}
                  {#if k.cname}<span class="ml-1.5 text-subtle">via <span class="font-mono">{k.cname}</span></span>{/if}
                  <p class="mt-0.5 line-clamp-1 font-mono break-all text-subtle" title={k.record}>{k.record}</p>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="mb-2 text-subtle">No DKIM key at any checked selector.</p>
      {/if}
      {#if d.failed.length}<p class="mb-2 text-warn">No answer for: <span class="font-mono">{d.failed.join(', ')}</span></p>{/if}
      <details class="mb-2 text-subtle">
        <summary class="cursor-pointer hover:text-fg">Selectors checked</summary>
        <p class="mt-1 font-mono">{d.checked.join(' ')}</p>
      </details>
      <form onsubmit={checkMore} class="flex items-center gap-2">
        <label for="dkim-more-{step.id}" class="text-muted">Check more DKIM selectors</label>
        <input
          id="dkim-more-{step.id}"
          bind:value={more}
          placeholder="e.g. s2024, mta1"
          spellcheck="false"
          autocomplete="off"
          class="h-6 w-48 rounded border border-line bg-surface px-1.5 font-mono placeholder:text-subtle"
        />
        <button
          type="submit"
          disabled={!more.trim() || step.status === 'running'}
          class="flex h-6 items-center rounded px-1.5 text-muted transition-colors hover:bg-raised hover:text-fg disabled:opacity-40"
        >Check</button>
      </form>
    </section>
  {/if}

  {#if r.dmarc}
    {@const m = r.dmarc}
    <section class="px-3.5 py-2.5">
      <h3 class="mb-1.5 font-medium">DMARC</h3>
      {#if m.error}
        <p class="text-warn">Lookup failed: {m.error}</p>
      {:else if m.records.length === 0}
        <p class="text-subtle">No DMARC record at <span class="font-mono">_dmarc.{step.target}</span>.</p>
      {:else if m.records.length > 1}
        <p class="mb-1 text-warn">{m.records.length} DMARC records; receivers ignore them all.</p>
        {#each m.records as rec}<p class="font-mono break-all">{rec}</p>{/each}
      {:else}
        <p class="mb-1.5 font-mono break-all text-muted">{m.records[0]}</p>
        <table class="w-full">
          <tbody>
            {#each [
              ['Policy', m.policy || '—', m.policy === 'none' || !m.policy ? 'text-warn' : 'text-ok'],
              ['Subdomains', m.subdomain_policy || `${m.policy || '—'} (inherited)`, ''],
              ['Applied to', `${m.pct}%`, m.pct < 100 ? 'text-warn' : ''],
              ['Alignment', `DKIM ${alignment(m.adkim)}, SPF ${alignment(m.aspf)}`, ''],
              ['Aggregate reports', m.rua.join(', ') || 'none', m.rua.length ? '' : 'text-subtle'],
              ['Failure reports', m.ruf.join(', ') || 'none', m.ruf.length ? '' : 'text-subtle'],
            ] as [label, value, tone]}
              <tr class="align-top">
                <th scope="row" class="w-32 py-0.5 pr-2 text-left font-normal text-subtle">{label}</th>
                <td class="py-0.5 font-mono break-all {tone}">{value}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>
