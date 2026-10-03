import { expect, test } from '@playwright/test'

test('a Finding explains the problem and its citation jumps to the Step', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('missing.invalid')
  await target.press('Enter')

  const findings = page.getByRole('region', { name: 'Findings' })
  await expect(findings).toContainText('Name does not exist')
  await expect(findings).toContainText('Critical')

  await findings.getByRole('button', { name: /DNS Lookup at/ }).first().click()
  await expect(page.getByRole('article').first()).toBeFocused()
})
