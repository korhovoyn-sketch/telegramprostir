import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * Нативна кнопка «Назад» видима, коли `history.length > 0` (page.tsx). role-select
 * і profile-setup — обидва в AUTH_SCREENS і фільтруються з history в `back()`,
 * тож якщо перехід МІЖ ними чи З НИХ зроблено через `navigate()` (штовхає в
 * history), а не `navigateRoot()` (чистить history), кнопка лишається видимою й
 * НІЧОГО не робить по тапу — юзер бачить робочу на вигляд кнопку в глухому куті.
 */
const backButtonVisible = (page: Page) =>
  page.evaluate(() => window.Telegram?.WebApp?.BackButton?.isVisible ?? false)

// Full first-run owner journey: splash → (auto-login) → role-select →
// profile-setup → empty-state. Screenshots at each step double as a visual record.
test('owner onboarding reaches the empty-state with a working CTA', async ({ page }, testInfo) => {
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
  await page.goto('/')

  // Step 1 — role select
  await expect(page.getByText(/Хто ти\?/i)).toBeVisible()
  await testInfo.attach('1-role-select', { body: await page.screenshot(), contentType: 'image/png' })
  expect(await backButtonVisible(page), 'role-select: перший екран онбордингу, нема куди повертатись').toBe(false)
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()

  // Step 2 — profile setup
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  await testInfo.attach('2-profile-setup', { body: await page.screenshot(), contentType: 'image/png' })
  expect(await backButtonVisible(page), 'profile-setup: роль уже закомічена, «назад» до role-select нікуди').toBe(false)
  await page.getByRole('button', { name: /Почати роботу/i }).click()

  // Step 3 — empty state for owners
  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible()
  await testInfo.attach('3-empty-state', { body: await page.screenshot(), contentType: 'image/png' })
  await expect(page.getByRole('button', { name: /Створити першу базу/i })).toBeVisible()
  expect(await backButtonVisible(page), 'empty-state: глухий кут — нативна «Назад» не має з’являтись').toBe(false)
})
