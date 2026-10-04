import { expect, test } from './fixtures'

test('find a past Case by ticket, see resolved ones on request, and preview a purge', async ({ page }) => {
  await page.goto('/')
  const target = page.getByRole('textbox', { name: 'Target' })
  const ticket = page.getByRole('textbox', { name: 'Ticket reference' })
  for (const [name, ref] of [
    ['history-one.invalid', '#77001'],
    ['history-two.invalid', '#77002'],
  ]) {
    await page.locator('body').click()
    await page.keyboard.press('n')
    await target.fill(name)
    await target.press('Enter')
    await ticket.fill(ref)
    await ticket.press('Enter')
    await expect(ticket).toHaveValue(ref)
  }
  await page.getByRole('button', { name: 'Resolve' }).click() // resolve the second
  await expect(page.getByRole('button', { name: 'Resolved' })).toBeVisible()

  await page.locator('body').click()
  await page.keyboard.press('h')
  const dialog = page.getByRole('dialog', { name: 'Cases' })
  const list = dialog.getByRole('listbox', { name: 'Cases found' })
  await expect(list).toContainText('history-one.invalid')
  await expect(list).not.toContainText('history-two.invalid')
  await dialog.getByRole('checkbox', { name: 'Show resolved' }).check()
  await expect(list).toContainText('history-two.invalid')

  await dialog.getByRole('textbox', { name: 'Search Cases' }).fill('77001')
  await expect(list.getByRole('option')).toHaveCount(1)
  await expect(list).toContainText('Ticket #77001')
  await page.keyboard.press('Enter')
  await expect(dialog).toBeHidden()
  await expect(ticket).toHaveValue('#77001')

  await page.locator('body').click()
  await page.keyboard.press('h')
  await dialog.getByRole('button', { name: 'Check' }).click()
  await expect(dialog).toContainText('Nothing that old.')
})
