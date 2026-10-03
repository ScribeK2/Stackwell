import { expect, test } from './fixtures'

test.use({ permissions: ['clipboard-read', 'clipboard-write'] })

const clipboard = (page: import('@playwright/test').Page) => page.evaluate(() => navigator.clipboard.readText())

test('rep notes go into a Write-up that copies as Markdown or plain text', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('missing.invalid')
  await target.press('Enter')
  await expect(page.getByRole('region', { name: 'Findings' })).toContainText('Name does not exist')

  await page.locator('body').click()
  await page.keyboard.press('e')
  await page.keyboard.type('Customer says the domain lapsed last week.')
  await page.keyboard.press('Control+Enter') // saves
  await expect(page.getByRole('textbox', { name: 'Rep notes' })).not.toBeFocused()

  await page.locator('body').click()
  await page.keyboard.press('c')
  await expect(page.getByText('Copied Write-up (Markdown)')).toBeVisible()
  const md = await clipboard(page)
  expect(md).toContain('# missing.invalid')
  expect(md).toContain('**Critical** — Name does not exist')
  expect(md).toContain('Customer says the domain lapsed last week.')

  await page.keyboard.press('Shift+C')
  await expect(page.getByText('Copied Write-up (plain text)')).toBeVisible()
  const txt = await clipboard(page)
  expect(txt).toContain('FINDINGS')
  expect(txt).not.toContain('**')

  await page.keyboard.press('w')
  const preview = page.getByRole('dialog', { name: 'Write-up' })
  await expect(preview).toContainText('## Notes')
  await preview.getByRole('radio', { name: 'Plain text' }).click()
  await expect(preview).toContainText('NOTES')
  await page.keyboard.press('c') // works inside the preview too
  await expect(page.getByText('Copied Write-up (Markdown)')).toBeVisible()
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: /^Copy DNS Lookup on missing.invalid/ }).first().click()
  await expect(page.getByText('Copied Step')).toBeVisible()
  expect(await clipboard(page)).toContain('DNS Lookup on missing.invalid')
})
