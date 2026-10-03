import { expect, test } from '@playwright/test'

test('a Playbook runs from the palette and reports its progress and limits', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('example.com')
  await target.press('Enter')
  await expect(page.getByRole('article').first()).toContainText(/Done|Failed/)

  await page.locator('body').click()
  await page.keyboard.press('Control+k')
  await page.keyboard.type('orientation example.com')
  await expect(page.getByRole('option').first()).toContainText('Run Orientation Playbook on example.com')
  await page.keyboard.press('Enter')

  const run = page.getByRole('article', { name: 'Orientation run on example.com' })
  await expect(run).toBeVisible()
  // Real network: registry, DNS and a quick port sweep.
  await expect(run).toContainText(/Done/, { timeout: 25_000 })
  await run.getByRole('button', { name: /What this can't see/ }).click()
  await expect(run).toContainText('Registrar account')
  await expect(page.getByRole('article', { name: /^Registration example.com/ })).toBeVisible()
})
