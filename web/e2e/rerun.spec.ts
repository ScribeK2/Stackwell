import { expect, test } from '@playwright/test'

test('r re-runs the focused Step; j/k move between runs', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('rerun.invalid')
  await target.press('Enter')

  const steps = page.getByRole('article')
  await expect(steps.first()).toContainText(/Done|Failed/)
  await page.locator('body').click()
  await page.keyboard.press('j')
  await page.keyboard.press('r')

  await expect(steps).toHaveCount(2)
  await expect(steps.first()).toContainText(/Done|Failed/)
  await expect(steps.nth(1)).toContainText('Earlier run')
  // Both runs got the same NXDOMAIN answer.
  await expect(steps.first()).toContainText('No changes since previous run')

  await page.locator('body').click()
  await page.keyboard.press('j')
  await expect(steps.first()).toBeFocused()
  await page.keyboard.press('j')
  await expect(steps.nth(1)).toBeFocused()
  await page.keyboard.press('k')
  await expect(steps.first()).toBeFocused()
})
