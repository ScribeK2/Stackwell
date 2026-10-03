<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Cert = {
    subject: string
    issuer: string
    sans?: string[]
    not_before: string
    not_after: string
    self_signed: boolean
    key: string
    signature: string
  }
  const r = $derived(
    step.result as {
      version: string
      cipher: string
      chain: Cert[]
      hostname_match: boolean
      verified: boolean
      trust: string
      verify_error?: string
    },
  )
  const day = (s: string) => s.slice(0, 10)
  // Worked out now rather than stored, so re-runs don't differ by date alone.
  const daysLeft = (notAfter: string) => Math.floor((Date.parse(notAfter) - Date.now()) / 86_400_000)
  const left = (d: number) => (d < 0 ? 'text-crit' : d <= 14 ? 'text-warn' : d <= 30 ? 'text-muted' : 'text-ok')
  const oldProtocol = $derived(r.version === 'TLS 1.0' || r.version === 'TLS 1.1')
</script>

<dl class="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1 px-3.5 pt-3 text-xs">
  <dt class="text-subtle">Protocol</dt>
  <dd class="font-mono {oldProtocol ? 'text-warn' : ''}">{r.version} <span class="text-subtle">· {r.cipher}</span></dd>
  <dt class="text-subtle">Hostname</dt>
  <dd class={r.hostname_match ? 'text-ok' : 'text-crit'}>{r.hostname_match ? `Matches ${step.target}` : `Doesn't cover ${step.target}`}</dd>
  <dt class="text-subtle">Verification</dt>
  <dd class={r.verified ? 'text-ok' : 'text-crit'}>
    {#if r.verified}Trusted{:else}<span class="font-mono break-all">{r.verify_error}</span>{/if}
  </dd>
</dl>

<div class="overflow-x-auto">
  <table class="my-1.5 w-full text-xs">
    <thead>
      <tr class="text-left text-subtle">
        <th class="py-1 pl-3.5 font-medium">Certificate</th>
        <th class="px-2 py-1 font-medium">Valid</th>
        <th class="px-2 py-1 font-medium">Key</th>
      </tr>
    </thead>
    <tbody class="font-mono">
      {#each r.chain as c, i}
        {@const d = daysLeft(c.not_after)}
        <tr class="border-t border-line align-top">
          <td class="py-1.5 pl-3.5">
            <div class="break-all">{c.subject || '(no CN)'}</div>
            <div class="font-sans text-[11px] text-subtle">
              {i === 0 ? 'Leaf' : 'Chain'} · issued by {c.issuer || '(no CN)'}{#if c.self_signed}
                · <span class={i === 0 ? 'text-crit' : ''}>self-signed</span>{/if}
            </div>
            {#if c.sans?.length}
              <div class="mt-0.5 text-[11px] break-all text-muted">{c.sans.join(', ')}</div>
            {/if}
          </td>
          <td class="px-2 py-1.5 whitespace-nowrap">
            {day(c.not_before)} → {day(c.not_after)}
            <div class="text-[11px] {left(d)}">{d < 0 ? `expired ${-d}d ago` : `${d}d left`}</div>
          </td>
          <td class="px-2 py-1.5 pr-3.5 whitespace-nowrap">
            {c.key}<div class="text-[11px] text-subtle">{c.signature}</div>
          </td>
        </tr>
      {/each}
      {#if r.trust === 'missing_intermediate'}
        <tr class="border-t border-line">
          <td colspan="3" class="bg-crit/8 py-1.5 pl-3.5 font-sans text-crit">Intermediate certificate not sent by the server</td>
        </tr>
      {/if}
    </tbody>
  </table>
</div>
