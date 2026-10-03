import { readFileSync } from 'node:fs'
import { expect, test } from './fixtures'

const spoofed = readFileSync(new URL('../../internal/app/testdata/email_headers/spoofed.txt', import.meta.url), 'utf8')

test('pasted headers become Evidence with Findings, citations and suggestions', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('yourbank.invalid')
  await target.press('Enter')
  await expect(page.getByRole('article').first()).toContainText(/Done|Failed/)

  await page.locator('body').click()
  await page.keyboard.press('v')
  const dialog = page.getByRole('dialog', { name: 'Paste Evidence' })
  await expect(dialog.getByRole('textbox', { name: 'Pasted text' })).toBeFocused()

  // Not headers: refused with a reason, and the text stays to be fixed.
  await page.keyboard.type('hello there')
  await page.keyboard.press('Control+Enter')
  await expect(dialog.getByRole('alert')).toContainText("doesn't look like email headers")

  await dialog.getByRole('textbox', { name: 'Pasted text' }).fill(spoofed)
  await page.keyboard.press('Control+Enter')
  await expect(dialog).toBeHidden()

  const card = page.getByRole('article', { name: /^Email headers #/ })
  await expect(card).toContainText('Verify your account')
  await expect(card.getByRole('list', { name: 'Received chain' })).toContainText('198.51.100.66')

  const findings = page.getByRole('region', { name: 'Findings' })
  await expect(findings).toContainText('DMARC failed')
  await findings.getByRole('button', { name: /^Pasted Evidence #/ }).first().click()
  await expect(card).toBeFocused()

  await expect(page.getByRole('group', { name: 'Suggested Targets' })).toContainText('evil.test')
})
