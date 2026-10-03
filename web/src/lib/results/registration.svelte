<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  const r = $derived(
    step.result as {
      domain: string
      source: 'rdap' | 'whois'
      registered: boolean
      registrar?: string
      statuses: string[]
      created?: string
      updated?: string
      expires?: string
      nameservers: string[]
      dnssec?: boolean
      rdap_error?: string
    },
  )
  const problems = ['clientHold', 'serverHold', 'redemptionPeriod', 'pendingDelete', 'pendingRestore']
  const date = (s?: string) => {
    if (!s) return '—'
    const d = new Date(s)
    return isNaN(d.getTime()) ? s : d.toISOString().slice(0, 10)
  }
  const expired = $derived(!!r.expires && new Date(r.expires).getTime() < Date.now())
</script>

<p class="px-3.5 pt-3 text-xs text-subtle">
  {r.domain} via {r.source === 'rdap' ? 'RDAP' : 'WHOIS'}
  {#if r.rdap_error}<span title={r.rdap_error}> (RDAP unavailable: {r.rdap_error})</span>{/if}
</p>
{#if !r.registered}
  <p class="px-3.5 pt-2 pb-3 text-crit">Not registered</p>
{:else}
  <table class="my-1.5 w-full text-xs">
    <tbody>
      <tr class="align-top">
        <th scope="row" class="w-28 py-1 pl-3.5 text-left font-medium text-subtle">Registrar</th>
        <td class="py-1 pr-3.5">{r.registrar || '—'}</td>
      </tr>
      <tr class="align-top">
        <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">Status</th>
        <td class="py-1 pr-3.5 font-mono">
          {#each r.statuses as s}<div class={problems.includes(s) ? 'text-crit' : ''}>{s}</div>{:else}<span class="text-subtle">—</span>{/each}
        </td>
      </tr>
      <tr class="align-top">
        <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">Created</th>
        <td class="py-1 pr-3.5 font-mono">{date(r.created)}</td>
      </tr>
      <tr class="align-top">
        <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">Updated</th>
        <td class="py-1 pr-3.5 font-mono">{date(r.updated)}</td>
      </tr>
      <tr class="align-top">
        <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">Expires</th>
        <td class="py-1 pr-3.5 font-mono {expired ? 'text-crit' : ''}">{date(r.expires)}</td>
      </tr>
      <tr class="align-top">
        <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">Nameservers</th>
        <td class="py-1 pr-3.5 font-mono">
          {#each r.nameservers as ns}<div>{ns}</div>{:else}<span class="text-subtle">—</span>{/each}
        </td>
      </tr>
      {#if r.dnssec !== undefined}
        <tr class="align-top">
          <th scope="row" class="py-1 pl-3.5 text-left font-medium text-subtle">DNSSEC</th>
          <td class="py-1 pr-3.5">{r.dnssec ? 'Signed' : 'Unsigned'}</td>
        </tr>
      {/if}
    </tbody>
  </table>
{/if}
