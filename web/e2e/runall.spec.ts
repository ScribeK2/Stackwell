import { expect, test } from './fixtures'

test('run a Check on all Targets, and cancel a running Step with x', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('one.invalid')
  await target.press('Enter')
  await target.fill('example.com')
  await target.press('Enter')
  const steps = page.getByRole('article', { name: /^DNS Lookup/ })
  await expect(steps).toHaveCount(2)

  await page.locator('body').click()
  await page.keyboard.press('Control+k')
  await page.keyboard.type('dns lookup all targets')
  await expect(page.getByRole('option').first()).toContainText('Run DNS Lookup on all Targets')
  await page.keyboard.press('Enter')
  await expect(steps).toHaveCount(4)

  // A full port sweep on a real host takes seconds: long enough to cancel.
  await page.locator('body').click()
  await page.keyboard.press('Control+k')
  await page.keyboard.type('hosting full example.com')
  await page.keyboard.press('Enter')
  const sweep = page.getByRole('article', { name: /^Hosting Reachability example.com/ })
  await expect(sweep).toContainText('Running')
  await page.locator('body').click()
  await page.keyboard.press('j') // the newest Step is first
  await expect(sweep).toBeFocused()
  await page.keyboard.press('x')
  await expect(sweep).toContainText('Cancelled')
})
