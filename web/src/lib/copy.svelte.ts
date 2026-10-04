import { api } from './api'

// A short-lived message for things that happen without a visible change.
class Toast {
  message = $state('')
  open = $state(false)
  // Bumped on every show, so a repeat of the same message still plays again.
  count = $state(0)
  #timer = 0

  show(message: string) {
    this.message = message
    this.open = true
    this.count++
    clearTimeout(this.#timer)
    this.#timer = window.setTimeout(() => (this.open = false), 2200)
  }
}

export const toast = new Toast()

export async function copyText(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.show(`Copied ${what}`)
  } catch {
    toast.show('Could not copy: the browser refused clipboard access')
  }
}

export async function copyWriteup(caseID: number, format: 'markdown' | 'text') {
  const { text } = await api<{ text: string }>('GET', `/api/cases/${caseID}/writeup?format=${format}`)
  await copyText(text, format === 'markdown' ? 'Write-up (Markdown)' : 'Write-up (plain text)')
}
