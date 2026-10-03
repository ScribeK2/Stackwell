import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from './fixtures'

test('a team Playbook folder is set in Settings; broken files are named, good ones run', async ({ page }) => {
  const folder = mkdtempSync(join(tmpdir(), 'stackwell-team-'))
  writeFileSync(
    join(folder, 'quick-dns.yaml'),
    'name: quick_dns\nlabel: Quick DNS\nkinds: [domain]\nentries:\n  - check: dns_lookup\n',
  )
  writeFileSync(join(folder, 'broken.yaml'), 'name: broken\nlabel: Broken\nkinds: [domain]\nentries:\n  - check: no_such_check\n')

  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press(',')
  const settings = page.getByRole('dialog', { name: 'Settings' })
  await settings.getByRole('textbox', { name: 'Playbook folder path' }).fill(folder)
  await settings.getByRole('textbox', { name: 'Playbook folder path' }).press('Enter')

  await expect(settings.getByRole('list', { name: 'Playbooks' })).toContainText('Quick DNS')
  await expect(settings.getByRole('list', { name: 'Playbooks' })).toContainText('quick-dns.yaml')
  await expect(settings.getByRole('list', { name: 'Playbooks' })).toContainText('Orientation') // built-ins stay
  const problems = settings.getByRole('list', { name: 'Playbook files with problems' })
  await expect(problems).toContainText('broken.yaml')
  await expect(problems).toContainText('no_such_check')
  await page.keyboard.press('Escape')

  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('example.com')
  await target.press('Enter')
  await page.locator('body').click()
  await page.keyboard.press('Control+k')
  await page.keyboard.type('quick dns')
  await expect(page.getByRole('option').first()).toContainText('Run Quick DNS Playbook on example.com')
  await expect(page.getByRole('option').first()).toContainText('Team Playbook')
  await page.keyboard.press('Escape')

  // Leave the shared server as we found it.
  await page.locator('body').click()
  await page.keyboard.press(',')
  await settings.getByRole('button', { name: 'Clear' }).click()
  await expect(settings.getByRole('list', { name: 'Playbooks' })).not.toContainText('Quick DNS')
})
