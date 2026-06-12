import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// The "застрягання на спінері" regression: while the Edge Function is slow, the
// user must see a real loading state with step messages — never a frozen,
// squished button.
test('shows the auth loading state with step messages while the Edge Function is slow', async ({ page }) => {
  await setupApp(page, { user: { ...DEFAULT_USER, role: null }, loginDelayMs: 4000 })
  await page.goto('/')

  // Auto-login fires; the full-screen loading UI must appear.
  await expect(page.getByText(/Авторизація/i)).toBeVisible()
  await expect(page.getByText(/Підключаємось до Telegram|Перевіряємо дані|Завантажуємо профіль/i)).toBeVisible()
  await expect(page.getByText(/Не закривайте додаток/i)).toBeVisible()

  // Once the slow login resolves, we land on onboarding (role is null → role-select).
  await expect(page.getByRole('button', { name: /Продовжити/i })).toBeVisible({ timeout: 15_000 })
})

// A returning user with a valid cached session must reach their dashboard
// WITHOUT hitting the Edge Function login at all.
test('valid session skips the Edge Function login', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setupApp(page, { user: owner })

  let loginPosted = false
  await page.route('**/functions/v1/telegram-auth', (route) => {
    if (route.request().method() === 'POST') loginPosted = true
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
  })

  // Seed a cached profile so Fast Path 0 restores instantly.
  await page.addInitScript((u) => {
    localStorage.setItem('ps_user', JSON.stringify(u))
  }, owner)

  await page.goto('/')
  // Owner lands on the database list (its create FAB / heading), no login POST.
  await page.waitForLoadState('networkidle')
  expect(loginPosted).toBe(false)
})
