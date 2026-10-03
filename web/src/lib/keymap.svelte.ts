import { untrack } from 'svelte'

// One registry for every action: the palette lists them, the help overlay
// documents them, and the global handler runs their shortcuts. No modes.

export type Action = {
  id: string
  title: string
  group: string
  keys?: string[] // e.g. ['mod+k', ':'], ['?'], ['j']
  global?: boolean // its mod+ combos also fire while typing in a field
  run: () => void
}

class Keymap {
  actions = $state<Action[]>([])
  paletteOpen = $state(false)
  helpOpen = $state(false)
  settingsOpen = $state(false)
  writeupOpen = $state(false)
}

export const keymap = new Keymap()

/** Registers actions; returns a function that removes them (use in $effect/onMount). */
export function register(...actions: Action[]): () => void {
  // untrack: registering from an $effect must not make that effect depend on
  // the registry it writes to, or effects re-trigger each other without end.
  untrack(() => keymap.actions.push(...actions))
  // By id: $state wraps stored actions in proxies, so identity never matches.
  const ids = new Set(actions.map((a) => a.id))
  return () => untrack(() => (keymap.actions = keymap.actions.filter((a) => !ids.has(a.id))))
}

// Plain keys stay case-sensitive (Shift+J isn't j); combos spell out shift.
function keyOf(e: KeyboardEvent): string {
  if (!(e.ctrlKey || e.metaKey)) return e.key
  return 'mod+' + (e.shiftKey ? 'shift+' : '') + e.key.toLowerCase()
}

function isEditable(el: EventTarget | null): boolean {
  return (
    el instanceof HTMLElement &&
    (el.isContentEditable || el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)
  )
}

export function handleKey(e: KeyboardEvent) {
  if (e.altKey || e.defaultPrevented) return
  const key = keyOf(e)
  // Dialogs own the keyboard while open (Escape is handled natively), but our
  // own combos must not leak to the browser (Ctrl+K focuses its search bar).
  if (keymap.paletteOpen || keymap.helpOpen || keymap.settingsOpen || keymap.writeupOpen) {
    if (keymap.actions.some((a) => a.global && a.keys?.includes(key))) e.preventDefault()
    return
  }
  const editing = isEditable(e.target)
  const action = keymap.actions.find((a) => a.keys?.includes(key) && (!editing || (a.global && key.startsWith('mod+'))))
  if (!action) return
  e.preventDefault()
  action.run()
}

/** Human-readable key for display: mod+k → Ctrl K. */
export function keyLabel(key: string): string[] {
  // A plain capital letter is typed with Shift: show it, so c and C differ.
  if (key.length === 1 && key !== key.toLowerCase()) return ['Shift', key]
  return key.split('+').map((k) => (k === 'mod' ? 'Ctrl' : k.length === 1 ? k.toUpperCase() : k))
}

// ── j/k list navigation ──────────────────────────────────────────────
// Lists opt in with `use:navList`; items carry `data-nav-item` and tabindex.
const lists: HTMLElement[] = []

export function navList(node: HTMLElement) {
  lists.push(node)
  return { destroy: () => lists.splice(lists.indexOf(node), 1) }
}

export function moveInList(delta: 1 | -1) {
  const active = document.activeElement
  const list = lists.find((l) => l.contains(active)) ?? lists[0]
  if (!list) return
  const items = [...list.querySelectorAll<HTMLElement>('[data-nav-item]')]
  if (!items.length) return
  const i = items.indexOf(active as HTMLElement)
  const next = i === -1 ? 0 : Math.max(0, Math.min(items.length - 1, i + delta))
  items[next].focus()
  items[next].scrollIntoView({ block: 'nearest' })
}
