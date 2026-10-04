import { expect, test } from './fixtures'

const bounce = (i: number) =>
  `Jun 12 02:30:00 mail01 postfix/smtp[2820]: Q${String(i).padStart(7, '0')}: to=<u${i}@example.net>, relay=mx.example.net[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)`
const sent = `2026-06-12T02:26:21.500Z mail01 postfix/smtp[2820]: A1B2C3D4: to=<rcpt@example.net>, relay=mx.example.net[198.51.100.5]:25, delay=1.3, dsn=2.0.0, status=sent (250 2.0.0 OK)`

test('a pasted mail log, large or wrapped, becomes readable messages and capped Findings', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('maillog.invalid')
  await target.press('Enter')
  await expect(page.getByRole('article').first()).toContainText(/Done|Failed/)

  await page.locator('body').click()
  await page.keyboard.press('v')
  const dialog = page.getByRole('dialog', { name: 'Paste Evidence' })
  await dialog.getByRole('combobox', { name: 'Kind' }).selectOption('mail_log')
  const log = [sent, ...Array.from({ length: 300 }, (_, i) => bounce(i))].join('\n')
  await dialog.getByRole('textbox', { name: 'Pasted text' }).fill(log)
  await dialog.getByRole('button', { name: 'Add to Case' }).click()
  await expect(dialog).toBeHidden()

  const card = page.getByRole('article', { name: /^Mail log #/ })
  await expect(card).toContainText('300 bounced')
  await expect(card).toContainText('1 delivered')
  await expect(card.getByRole('list', { name: 'Messages' }).getByRole('listitem')).toHaveCount(100)
  await card.getByRole('button', { name: /Show more/ }).click()
  await expect(card.getByRole('list', { name: 'Messages' }).getByRole('listitem')).toHaveCount(301)

  const findings = page.getByRole('region', { name: 'Findings' })
  await expect(findings).toContainText('Bounced: u0@example.net')
  await expect(findings).toContainText("Recipient mailbox doesn't exist")
  await expect(findings).toContainText('More in the log')
})
