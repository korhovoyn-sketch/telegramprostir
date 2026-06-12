import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// Full first-run owner journey: splash → (auto-login) → role-select →
// profile-setup → empty-state. Screenshots at each step double as a visual record.
test('owner onboarding reaches the empty-state with a working CTA', async ({ page }, testInfo) => {
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
  await page.goto('/')

  // Step 1 — role select
  await expect(page.getByText(/Хто ти\?/i)).toBeVisible()
  await testInfo.attach('1-role-select', { body: await page.screenshot(), contentType: 'image/png' })
  await page.getByText('Власник').click()
  await page.getByRole('button', { name: /Продовжити/i }).click()

  // Step 2 — profile setup
  await expect(page.getByText(/Контакти/i)).toBeVisible()
  await testInfo.attach('2-profile-setup', { body: await page.screenshot(), contentType: 'image/png' })
  await page.getByRole('button', { name: /Почати роботу/i }).click()

  // Step 3 — empty state for owners
  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible()
  await testInfo.attach('3-empty-state', { body: await page.screenshot(), contentType: 'image/png' })
  await expect(page.getByRole('button', { name: /Створити першу базу/i })).toBeVisible()
})
