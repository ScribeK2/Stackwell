import { expect, test } from './fixtures'

test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

test('long values are clamped with a Show all toggle; short ones are not', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  // github.com publishes dozens of TXT records: the DNS Lookup runs long.
  await target.fill('github.com')
  await target.press('Enter')
  const step = page.getByRole('article', { name: /^DNS Lookup github.com/ })
  await expect(step).toContainText('Done')

  const toggle = step.getByRole('button', { name: /^Show all \(\d+ rows\)$/ })
  await expect(toggle).toBeVisible()
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
  const collapsed = (await step.boundingBox())!.height

  await toggle.focus()
  await page.keyboard.press('Enter') // keyboard-operable
  const less = step.getByRole('button', { name: 'Show less' })
  await expect(less).toHaveAttribute('aria-expanded', 'true')
  expect((await step.boundingBox())!.height).toBeGreaterThan(collapsed + 100)

  await less.click()
  await expect(step.getByRole('button', { name: /^Show all/ })).toBeVisible()
  expect((await step.boundingBox())!.height).toBeLessThan(collapsed + 5)

  // Copying the Step still gives every record, not just the visible ones.
  await step.getByRole('button', { name: /^Copy DNS Lookup/ }).click()
  await expect(page.getByText('Copied Step')).toBeVisible()
  const copied = await page.evaluate(() => navigator.clipboard.readText())
  const copiedTXT = copied.split('\n').find((l) => l.startsWith('TXT:'))!.split('", "').length
  // Collapsed (as it is now), the card shows only some records; the copy has all.
  const shownTXT = await step.locator('td').evaluateAll(
    (tds) => tds.filter((td) => td.textContent?.trim().startsWith('"') && td.getBoundingClientRect().bottom < (td.closest('[style*="max-height"]')?.getBoundingClientRect().bottom ?? Infinity)).length,
  )
  expect(copiedTXT).toBeGreaterThan(shownTXT)

  // A short result has no toggle at all.
  await page.locator('body').click()
  await page.keyboard.press('n')
  await target.fill('short.invalid')
  await target.press('Enter')
  const short = page.getByRole('article', { name: /^DNS Lookup short.invalid/ })
  await expect(short).toContainText(/Done|Failed/)
  await expect(short.getByRole('button', { name: /^Show all/ })).toHaveCount(0)
})
