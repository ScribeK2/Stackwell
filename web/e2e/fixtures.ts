import { expect, test as base } from '@playwright/test'

// Every e2e test fails on an uncaught error in the page: a broken reactive
// loop once hid behind a missing card and a suite that was merely slow.
export const test = base.extend<{ pageErrors: void }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = []
      page.on('pageerror', (e) => errors.push(e.message))
      await use()
      expect(errors, 'uncaught errors in the page').toEqual([])
    },
    { auto: true },
  ],
})

export { expect }
