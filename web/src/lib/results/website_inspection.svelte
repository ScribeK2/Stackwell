<script lang="ts">
  import type { Step } from '../api'
  let { step }: { step: Step; rerun: (options?: Record<string, string>) => void } = $props()

  type Hop = { url: string; status: number; location?: string }
  type Header = { present: boolean; value?: string; via?: string }
  type Result = {
    url: string
    final_url?: string
    status?: number
    time_ms: number
    server?: string
    content_type?: string
    chain: Hop[] | null
    redirect_loop: boolean
    too_many_redirects: boolean
    https_error?: string
    error?: string
    http_to_https?: boolean
    headers?: Record<string, Header>
    wordpress: { detected: boolean; evidence: string[]; version?: string; critical_error: boolean; maintenance: boolean }
  }
  const r = $derived(step.result as Result)
  const headerOrder = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Permissions-Policy',
  ]
  const tone = (s: number) => (s >= 500 ? 'text-crit' : s >= 400 ? 'text-warn' : s >= 300 ? 'text-muted' : 'text-ok')
</script>

<div class="px-3.5 pt-3 text-xs">
  {#if r.https_error}
    <p class="text-warn">HTTPS failed ({r.https_error}); inspected over plain HTTP.</p>
  {/if}
  {#if r.error}
    <p class="text-crit">{r.url} could not be loaded: {r.error}</p>
  {:else}
    <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1">
      <span class="font-mono text-sm font-medium {tone(r.status ?? 0)}">{r.status}</span>
      <span class="font-mono break-all">{r.final_url}</span>
      <span class="text-muted">{r.time_ms} ms</span>
      {#if r.server}<span class="text-subtle">Server <span class="font-mono text-muted">{r.server}</span></span>{/if}
      {#if r.content_type}<span class="font-mono text-subtle">{r.content_type}</span>{/if}
    </div>
    {#if r.http_to_https !== undefined}
      <p class="mt-1 {r.http_to_https ? 'text-subtle' : 'text-warn'}">
        http:// {r.http_to_https ? 'redirects to HTTPS' : 'does not redirect to HTTPS'}
      </p>
    {/if}
  {/if}
</div>

{#if (r.chain?.length ?? 0) > 1 || r.redirect_loop || r.too_many_redirects}
  <h4 class="px-3.5 pt-3 text-xs font-medium text-subtle">
    Redirects
    {#if r.redirect_loop}<span class="text-crit">· loop</span>{:else if r.too_many_redirects}<span class="text-warn">· stopped after {r.chain?.length} hops</span>{/if}
  </h4>
  <table class="my-1 w-full font-mono text-xs">
    <tbody>
      {#each r.chain ?? [] as hop}
        <tr class="align-top">
          <td class="w-12 py-0.5 pl-3.5 {tone(hop.status)}">{hop.status}</td>
          <td class="py-0.5 pr-3.5 break-all">
            {hop.url}{#if hop.location}<span class="text-subtle"> → {hop.location}</span>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if r.headers}
  <h4 class="px-3.5 pt-3 text-xs font-medium text-subtle">Security headers</h4>
  <table class="my-1 w-full text-xs">
    <tbody>
      {#each headerOrder as name}
        {@const h = r.headers[name]}
        <tr class="align-top">
          <th scope="row" class="w-52 py-0.5 pl-3.5 text-left font-normal {h?.present ? '' : 'text-warn'}">
            <span class={h?.present ? 'text-ok' : ''}>{h?.present ? '✓' : '✕'}</span> {name}
          </th>
          <td class="py-0.5 pr-3.5 font-mono break-all {h?.present ? 'text-muted' : 'font-sans text-subtle'}">
            {#if h?.present}{h.value}{#if h.via}<span class="font-sans text-subtle"> (via {h.via})</span>{/if}{:else}missing{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if r.wordpress?.detected}
  <p class="px-3.5 pt-2 pb-3 text-xs">
    <span class="font-medium">WordPress{r.wordpress.version ? ` ${r.wordpress.version}` : ''}</span>
    {#if r.wordpress.critical_error}<span class="text-crit">· critical-error page</span>{/if}
    {#if r.wordpress.maintenance}<span class="text-warn">· maintenance mode</span>{/if}
    <span class="text-subtle">· via {r.wordpress.evidence.filter((e) => !e.endsWith(' page')).join(', ') || 'page content'}</span>
  </p>
{:else}
  <div class="pb-2"></div>
{/if}
