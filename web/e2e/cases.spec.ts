import { expect, test } from '@playwright/test'

test('work two Cases: name them, switch by ticket ref, survive a reload', async ({ page }) => {
  await page.goto('/')
  const target = page.getByRole('textbox', { name: 'Target' })
  const title = page.getByRole('textbox', { name: 'Case title' })
  const ticket = page.getByRole('textbox', { name: 'Ticket reference' })

  // Case one
  await page.locator('body').click()
  await page.keyboard.press('n')
  await target.fill('one.invalid')
  await target.press('Enter')
  await title.fill('Bounce on one')
  await title.press('Enter')
  await ticket.fill('#11111')
  await ticket.press('Enter')
  await expect(page.getByRole('list', { name: 'Targets' })).toContainText('one.invalid')

  // A second Target joins the same Case
  await target.fill('https://WWW.One.invalid/x')
  await target.press('Enter')
  await expect(page.getByRole('list', { name: 'Targets' })).toContainText('www.one.invalid')

  // Case two
  await page.locator('body').click()
  await page.keyboard.press('n')
  await expect(title).toBeHidden()
  await target.fill('two.invalid')
  await target.press('Enter')
  await expect(page.getByRole('list', { name: 'Targets' })).toContainText('two.invalid')
  await expect(page.getByRole('list', { name: 'Targets' })).not.toContainText('one.invalid')

  // Back to Case one by its ticket reference
  await page.keyboard.press('Control+k')
  await page.keyboard.type('11111')
  await page.keyboard.press('Enter')
  await expect(title).toHaveValue('Bounce on one')

  await page.reload()
  await expect(title).toHaveValue('Bounce on one')
  await expect(ticket).toHaveValue('#11111')

  // Resolve
  await page.getByRole('button', { name: 'Resolve' }).click()
  await expect(page.getByRole('button', { name: 'Resolved' })).toBeVisible()
})

test('an invalid Target shows why', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('not a host')
  await target.press('Enter')
  await expect(page.getByRole('alert')).toContainText('not a valid')
  await expect(target).toHaveValue('not a host')
})

test('Targets typed in quick succession land in one Case', async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click()
  await page.keyboard.press('n')
  const target = page.getByRole('textbox', { name: 'Target' })
  await target.fill('fast1.invalid')
  await target.press('Enter')
  await target.fill('fast2.invalid') // no waiting: the first request is still in flight
  await target.press('Enter')
  const chips = page.getByRole('list', { name: 'Targets' })
  await expect(chips).toContainText('fast1.invalid')
  await expect(chips).toContainText('fast2.invalid')
})
