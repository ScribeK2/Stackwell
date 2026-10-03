import { type Page } from '@playwright/test'
import { expect, test } from './fixtures'

const palette = (page: Page) => page.getByRole('dialog', { name: 'Command palette' })
const help = (page: Page) => page.getByRole('dialog', { name: 'Keyboard shortcuts' })
const target = (page: Page) => page.getByRole('textbox', { name: 'Target' })

test.beforeEach(async ({ page }) => {
  await page.goto('/')
  await page.locator('body').click() // focus outside any field
})

test('Ctrl+K opens the command palette listing actions', async ({ page }) => {
  await page.keyboard.press('Control+k')
  await expect(palette(page)).toBeVisible()
  await expect(palette(page).getByRole('option', { name: /Show keyboard shortcuts/ })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(palette(page)).toBeHidden()
})

test(': opens the palette, and running an action works by Enter', async ({ page }) => {
  await page.keyboard.press(':')
  await expect(palette(page)).toBeVisible()
  await page.keyboard.type('shortcuts')
  await page.keyboard.press('Enter')
  await expect(palette(page)).toBeHidden()
  await expect(help(page)).toBeVisible()
})

test('? opens the shortcut overlay', async ({ page }) => {
  await page.keyboard.press('?')
  await expect(help(page)).toBeVisible()
  await expect(help(page)).toContainText('Command palette')
  await page.keyboard.press('Escape')
  await expect(help(page)).toBeHidden()
})

test('typing in a field is never intercepted by shortcuts', async ({ page }) => {
  await target(page).click()
  await page.keyboard.type('j:k?/t x')
  await expect(target(page)).toHaveValue('j:k?/t x')
  await expect(palette(page)).toBeHidden()
  await expect(help(page)).toBeHidden()
})

test('Ctrl+K still works from inside a field', async ({ page }) => {
  await target(page).click()
  await page.keyboard.press('Control+k')
  await expect(palette(page)).toBeVisible()
})

test('/ focuses the target field', async ({ page }) => {
  await page.keyboard.press('/')
  await expect(target(page)).toBeFocused()
  await expect(target(page)).toHaveValue('')
})

test('j/k move focus through Steps', async ({ page }) => {
  // Until re-run (#7) a Case has one Step, so this pins the mechanics:
  // j enters the list, k at the top stays put.
  await target(page).fill('a.invalid')
  await target(page).press('Enter')
  const step = page.getByRole('article').first()
  await expect(step).toBeVisible()
  await page.locator('body').click()
  await page.keyboard.press('j')
  await expect(step).toBeFocused()
  await page.keyboard.press('k')
  await expect(step).toBeFocused()
})

test('Ctrl+K inside the open palette stays in the palette', async ({ page }) => {
  await page.keyboard.press('Control+k')
  await page.keyboard.press('Control+k')
  await expect(palette(page).getByRole('combobox')).toBeFocused()
})

test('Shift+J is not j', async ({ page }) => {
  await target(page).fill('a.invalid')
  await target(page).press('Enter')
  await expect(page.getByRole('article').first()).toBeVisible()
  await page.locator('body').click()
  await page.keyboard.press('Shift+J')
  await expect(page.getByRole('article').first()).not.toBeFocused()
})
