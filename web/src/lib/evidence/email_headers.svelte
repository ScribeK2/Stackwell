<script lang="ts">
  import type { Evidence } from '../api'
  let { evidence }: { evidence: Evidence } = $props()

  const a = $derived(evidence.analysis)
  const verdict = (v?: string) => (v === 'pass' ? 'text-ok' : v === 'fail' ? 'text-crit' : v ? 'text-warn' : 'text-subtle')
  const when = (t?: string) => (t ? new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' }) : '')
  const delay = (s?: number) => (s === undefined ? '' : s < 60 ? `+${Math.round(s)}s` : s < 3600 ? `+${Math.round(s / 60)}m` : `+${(s / 3600).toFixed(1)}h`)
  const yes = (b?: boolean) => (b === undefined ? '—' : b ? 'aligned' : 'not aligned')
</script>

<div class="space-y-3 px-3.5 py-3 text-xs">
  <dl class="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-0.5">
    {#each [['From', a.headers.from], ['Subject', a.headers.subject], ['Date', a.headers.date], ['Return-Path', a.headers.return_path]] as [k, v]}
      {#if v}<dt class="text-subtle">{k}</dt><dd class="truncate font-mono">{v}</dd>{/if}
    {/each}
  </dl>

  <div class="flex flex-wrap gap-1.5">
    {#each [['SPF', a.auth.spf], ['DKIM', a.auth.dkim], ['DMARC', a.auth.dmarc]] as [k, v]}
      <span class="rounded border border-line px-1.5 py-0.5"><span class="text-subtle">{k}</span> <span class="font-medium {verdict(v)}">{v ?? 'no verdict'}</span></span>
    {/each}
    {#if a.spam.flagged}<span class="rounded border border-warn/40 px-1.5 py-0.5 text-warn">Flagged as spam</span>{/if}
    {#if a.spam.score !== undefined}<span class="rounded border border-line px-1.5 py-0.5 text-muted">Spam score {a.spam.score}</span>{/if}
    {#if a.spam.scl !== undefined}<span class="rounded border border-line px-1.5 py-0.5 text-muted">SCL {a.spam.scl}</span>{/if}
  </div>

  <p class="text-muted">
    From ↔ bounce domain: <span class={a.alignment.from_return_path_aligned === false ? 'text-warn' : ''}>{yes(a.alignment.from_return_path_aligned)}</span>
    · From ↔ DKIM: <span class={a.alignment.dkim_aligned === false ? 'text-warn' : ''}>{yes(a.alignment.dkim_aligned)}</span>
  </p>

  {#if a.hops.length}
    <ol class="space-y-1 border-l border-line pl-3" aria-label="Received chain">
      {#each a.hops as h}
        <li class="relative">
          <span class="absolute top-1.5 -left-[15px] size-1.5 rounded-full {h.from_ip && h.from_ip === a.delivering_ip ? 'bg-accent' : 'bg-line-strong'}"></span>
          <span class="font-mono">{h.from_host ?? '?'}</span>
          {#if h.from_ip}<span class="font-mono text-subtle">[{h.from_ip}]</span>{/if}
          <span class="text-subtle">→</span> <span class="font-mono">{h.by_host ?? '?'}</span>
          {#if h.with}<span class="text-subtle">{h.with}</span>{/if}
          <span class="float-right tabular-nums {h.delay_s > 600 ? 'text-warn' : 'text-subtle'}">{when(h.at)} {delay(h.delay_s)}</span>
          {#if h.from_ip && h.from_ip === a.delivering_ip}
            <span class="ml-1 text-accent" title="Recorded by the recipient's own server">delivered</span>
          {:else if h.from_ip && h.from_ip === a.origin_ip}
            <span class="ml-1 text-subtle" title="Lines this far down are written by the sender and can be forged">earliest, can be forged</span>
          {/if}
        </li>
      {/each}
    </ol>
  {/if}
</div>
