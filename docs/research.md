# Stackwell — pre-grill research (2026-10-03)

Source: ScribeK2/ToolHarness @ v1.5.0 (f1bd399), 81 commits, Dec 2025 → Jul 2026.

## What ToolHarness is
Single-user, local-first Rails 8 app for Tier-2 support: domain / DNS / email / TLS /
hosting / SQL diagnostics behind one vim-modal keyboard UI (NORMAL/INSERT/CMD/SEARCH,
`:` cmdline, `/` search, `j/k` rail, 12 themes, brutalist monospace look).
Shipped as a 140 MB x86_64 AppImage that boots Puma on :3000 and opens the browser.

18 tools: whois/RDAP, DNS (+ worldwide propagation), historical DNS, subdomain scan,
SSL inspect, website inspect (+WordPress), PageSpeed, email auth (SPF/DKIM/DMARC),
email validity, email header analyzer, Postfix/Dovecot mail-log analyzer, hosting
diagnostic (port sweep), blacklist, IPinfo, domain price checker, bulk runner,
SQL workbench (MySQL/TiDB, read-only default), credentials (encrypted store).

Supporting systems: ToolRun history + filter DSL + retention, result cache,
Batches (fan-out over domains), Investigations (tracks of dependent probes →
correlator → findings → paste-ready markdown ticket report), update checker banner.

## What it wants to be (trajectory from commits/code)
- From "pile of tools" → **guided investigation copilot**: tracks with dependent
  probes, correlators, severity findings with provenance, "visibility boundary"
  (what the rep can't see: registry, Pterodactyl container, PHP layer), ticket output.
- **Paste-in forensics** is the newest growth area (headers, mail logs) — inputs
  are blobs, not just domains.
- Every result is **ticket-ready text** (copy summary / section / full dump).
- A **desktop app** in all but name: auto-open, single-instance lock, update
  takeover of an older running copy, update banner. It fights the browser model.
- Consolidation over sprawl (v1.0 merged tools into fewer, deeper ones).

## Pain the stack caused (evidence in repo)
- Relocating Ruby into an AppImage: ruby-build, shebang rewriting, `.bundle` path
  bugs, linuxdeploy rpath walk, LD_LIBRARY_PATH to dodge Fedora libssl, glibc 2.35 floor.
- 216-line AppRun + 100-line takeover script: port collision, browser-launcher
  cascade, flock single-instance, SIGTERM/SIGKILL of old versions.
- `bin/dev` vs `rails server` footgun (jobs don't run without Solid Queue worker).
- Porkbun blocks Ruby's TLS fingerprint → pricing had to become a bundled snapshot.
- Stale `public/assets` shadowing source; 140 MB artifact.

## Packaging reality on Arch + Ubuntu (2026)
| Shell | AppImage risk |
|---|---|
| WebKitGTK (Tauri v2, Wails v3 beta) | Bundled WebKit/Mesa vs rolling-distro GPU stack → blank window / EGL_BAD_PARAMETER on Arch. Tauri CLI 2.12 mitigated it; still the most fragile class. Wails v3 still beta. |
| Electron | Chromium bundled, electron-updater does AppImage delta updates. Ubuntu 24.04+ AppArmor blocks userns sandbox → needs `--no-sandbox` wrapper or AppArmor profile. ~100 MB. |
| Static binary + system browser (current model) | Zero GUI libs to bundle. Works anywhere with a browser. Keeps port/launch concerns. |

Independent of shell: ToolHarness's smoke job needs `fuse libfuse2`, which neither
Arch nor Ubuntu 24.04 ships by default. Use the static type2 runtime (no libfuse2,
`--appimage-extract-and-run` fallback) — verify current appimagetool default at scaffold time.

## Recommended stack (to be grilled)
**Go, single static binary (CGO_ENABLED=0), UI embedded via `go:embed`, served on
localhost; AppImage = binary + .desktop + icon.**
- No runtime to relocate, no glibc floor, no linuxdeploy; ~20–30 MB.
- One process: goroutines replace Solid Queue, SSE replaces Action Cable/Turbo Streams.
- Network stdlib is first-class: `net`, `crypto/tls`, `crypto/x509`.
- Libs: `miekg/dns` (raw DNS to any resolver, DNSSEC), `openrdap/rdap`,
  `likexian/whois`, `go-sql-driver/mysql` (TiDB-tested), `modernc.org/sqlite`
  (pure Go), `refraction-networking/utls` (browser TLS fingerprint — candidate fix for the
  Porkbun block, **unverified**: test a Go GET against api.porkbun.com before promising live pricing).
- Self-update: download release AppImage, atomically replace `$APPIMAGE`, re-exec —
  replaces the takeover script. Fails if the AppImage sits on a read-only mount; fall back to "download, tell user".
- Single instance: unix socket in `$XDG_RUNTIME_DIR`; second launch just reopens URL.
- Window feel: open in Chromium/Chrome `--app=` mode if present, else `xdg-open`.

Runner-up: Electron + TypeScript (true window, mature updater) — pick if a real
native window outweighs a 4× artifact and the Ubuntu sandbox wrapper.

## Open questions for the grill
1. Browser-on-localhost OK, or is a native window a hard requirement?
2. Frontend: server-rendered (templ + htmx) vs embedded SPA (Svelte 5 + Vite)?
   The modal keymap/cmdline/rail is heavy client state.
3. Port all 18 tools, or re-cut the catalog around investigation tracks?
4. Import ToolHarness history/credentials, or clean start?
5. Investigations: hard-coded tracks or user-definable?
6. Keep 12 themes + brutalist look as-is?
7. Domain specifics (Pterodactyl, Porkbun, $25 promo cap) — generalize or keep?
8. Also Fedora, or strictly Arch + Ubuntu?
