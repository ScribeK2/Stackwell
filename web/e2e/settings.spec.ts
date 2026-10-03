import { expect, test } from './fixtures'

test('a secret is saved, shown only masked, and deleted', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press(',')
  const settings = page.getByRole('dialog', { name: 'Settings' })
  await expect(settings).toBeVisible()
  await expect(settings).toContainText('Stored in a file only you can read')

  await settings.getByRole('textbox', { name: 'Secret name' }).fill('e2e_token')
  const value = settings.getByLabel('Secret value')
  await value.fill('e2e-secret-value-98765')
  await value.press('Enter')

  const saved = settings.getByRole('list', { name: 'Saved secrets' })
  await expect(saved).toContainText('e2e_token')
  await expect(saved).toContainText('••••8765')
  await expect(value).toHaveValue('')
  await expect(page.locator('body')).not.toContainText('e2e-secret-value-98765')

  await saved.getByRole('button', { name: 'Delete e2e_token' }).click()
  await expect(saved).toContainText('No secrets saved')
  await page.keyboard.press('Escape')
  await expect(settings).toBeHidden()
})
