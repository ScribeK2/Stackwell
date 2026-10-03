import { expect, test } from '@playwright/test'

test('any applicable Check runs from the palette, with its own result view', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('example.com')
  await target.press('Enter')
  await expect(page.getByRole('article').first()).toContainText(/Done|Failed/)

  await page.locator('body').click()
  await page.keyboard.press('Control+k')
  await page.keyboard.type('propagation mail example.com')
  await expect(page.getByRole('option').first()).toContainText('Run DNS Propagation (records: mail) on example.com')
  await page.keyboard.press('Enter')

  const step = page.getByRole('article', { name: /DNS Propagation example.com/ })
  await expect(step).toContainText('records: mail')
  // Real public resolvers: allow for slow ones (the Check timeout is 15s).
  await expect(step).toContainText('Resolver', { timeout: 20_000 })
})
