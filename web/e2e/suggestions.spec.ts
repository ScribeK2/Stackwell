import { expect, test } from '@playwright/test'

test('suggested Targets are triaged from the keyboard and never added on their own', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('example.com')
  await target.press('Enter')

  const suggested = page.getByRole('group', { name: 'Suggested Targets' })
  const chips = page.getByRole('list', { name: 'Targets' }).getByRole('listitem')
  await expect(suggested.getByRole('button', { name: /^Add / }).first()).toBeVisible()
  await expect(chips).toHaveCount(1) // nothing added on its own

  const count = await suggested.getByRole('button', { name: /^Add / }).count()
  const first = await suggested.getByRole('button', { name: /^Add / }).first().getAttribute('aria-label')

  await page.locator('body').click()
  await page.keyboard.press('s')
  await page.keyboard.press('x') // dismiss the first
  await expect(suggested.getByRole('button', { name: first! })).toHaveCount(0)
  if (count > 1) {
    await expect(suggested.getByRole('button', { name: /^Add / })).toHaveCount(count - 1)
    await page.keyboard.press('Enter') // focus moved to the next one: add it
    await expect(chips).toHaveCount(2)
  }
})
