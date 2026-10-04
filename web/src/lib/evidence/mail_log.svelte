<script lang="ts">
  import type { Evidence } from '../api'
  let { evidence }: { evidence: Evidence } = $props()

  type Recipient = {
    to: string
    relay_host?: string
    relay_ip?: string
    local: boolean
    dsn?: string
    status?: string
    reply?: string
    reason?: string
    attempts: number
  }
  type Message = { queue_id: string; time?: string; from?: string; client_host?: string; recipients: Recipient[]; verdict: string }
  type Rejection = { client_host?: string; client_ip: string; from?: string; to?: string; reply: string; reason?: string }
  const a = $derived(evidence.analysis as { messages: Message[]; rejections: Rejection[]; unparsed: number })

  const tone: Record<string, string> = { delivered: 'bg-ok', deferred: 'bg-warn', bounced: 'bg-crit', incomplete: 'bg-subtle' }
  const counts = $derived(
    a.messages.reduce<Record<string, number>>((c, m) => ((c[m.verdict] = (c[m.verdict] ?? 0) + 1), c), {}),
  )
  // Big logs: render a page at a time so the Case stays responsive.
  const page = 100
  let limit = $state(page)
  const shown = $derived(a.messages.slice(0, limit))
  let open = $state<Record<string, boolean>>({})
</script>

<div class="space-y-3 px-3.5 py-3 text-xs">
  <p class="flex flex-wrap gap-x-3 gap-y-1 text-muted">
    {#each ['delivered', 'deferred', 'bounced', 'incomplete'] as v}
      {#if counts[v]}<span class="flex items-center gap-1.5"><span class="size-1.5 rounded-full {tone[v]}"></span>{counts[v]} {v}</span>{/if}
    {/each}
    {#if a.rejections.length}<span class="flex items-center gap-1.5"><span class="size-1.5 rounded-full bg-warn"></span>{a.rejections.length} refused at our server</span>{/if}
    {#if a.unparsed}<span class="text-subtle">{a.unparsed} unrecognised lines</span>{/if}
  </p>

  {#if a.messages.length}
    <ul class="divide-y divide-line rounded-md border border-line" aria-label="Messages">
      {#each shown as m (m.queue_id)}
        <li class="px-2.5 py-1.5">
          <button class="flex w-full items-baseline gap-2 text-left" onclick={() => (open[m.queue_id] = !open[m.queue_id])} aria-expanded={!!open[m.queue_id]}>
            <span class="size-1.5 shrink-0 translate-y-[-1px] rounded-full {tone[m.verdict]}" title={m.verdict}></span>
            <span class="font-mono text-subtle">{m.queue_id}</span>
            <span class="min-w-0 truncate font-mono">{m.from ?? '?'} → {m.recipients.map((r) => r.to).join(', ') || '?'}</span>
            <span class="ml-auto shrink-0 text-muted">{m.verdict}</span>
          </button>
          {#each m.recipients as r}
            {#if r.status !== 'sent' || open[m.queue_id]}
              <p class="mt-0.5 pl-3.5 {r.status === 'bounced' ? 'text-crit' : r.status === 'deferred' ? 'text-warn' : 'text-muted'}">
                <span class="font-mono">{r.to}</span>
                {#if r.relay_host}<span class="text-subtle">via {r.local ? 'local delivery' : r.relay_host}</span>{/if}
                {#if r.reason}— {r.reason}{/if}
                {#if r.attempts > 1}<span class="text-subtle">(after {r.attempts} attempts)</span>{/if}
              </p>
              {#if open[m.queue_id] && r.reply}<p class="pl-3.5 font-mono text-[11px] break-all text-subtle">{r.dsn} {r.reply}</p>{/if}
            {/if}
          {/each}
        </li>
      {/each}
    </ul>
    {#if a.messages.length > limit}
      <button onclick={() => (limit += page * 5)} class="text-muted hover:text-fg">Show more ({a.messages.length - limit} not shown)</button>
    {/if}
  {/if}

  {#if a.rejections.length}
    <ul class="space-y-1" aria-label="Refused at our server">
      {#each a.rejections as r}
        <li>
          <span class="font-mono text-warn">{r.client_host ?? ''}[{r.client_ip}]</span>
          <span class="text-muted">{r.from ?? '?'} → {r.to ?? '?'}: {r.reason ?? r.reply}</span>
        </li>
      {/each}
    </ul>
  {/if}
</div>
