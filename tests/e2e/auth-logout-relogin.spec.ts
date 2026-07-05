import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// Regression coverage for: "login fails right after logout with a false
// 'no internet' error." Two root causes were fixed —
//   1. logout() used to hold Supabase's internal auth lock via a network
//      signOut(); it now uses scope:'local' and loginViaTelegram awaits the
//      in-flight signOut promise before its own setSession().
//   2. an Edge Function CORS misconfiguration used to make the login fetch
//      reject in a way indistinguishable from "no internet"; it now surfaces
//      a readable CONFIG_ERROR instead.
// These tests drive the real UI (Profile → logout → Welcome → login) rather
// than asserting on the fix internals, so they'd catch a regression in either
// direction.

const OWNER = { ...DEFAULT_USER, role: 'owner' as const }

// Mirrors harness.ts's private makeJwt() — not exported, so duplicated here
// (structurally valid, decodable, unsigned JWT with a future exp so
// supabase-js's setSession() accepts it without a network round-trip).
function makeJwt(user: { id: string; tg_id: number }): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload = {
    sub: user.id,
    email: `${user.tg_id}@telegram.propspace.app`,
    aud: 'authenticated',
    role: 'authenticated',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  }
  return `${enc(header)}.${enc(payload)}.sig`
}

test('logout then re-login as owner round-trips back to db-list', async ({ page }) => {
  await setupApp(page, { user: OWNER })
  // Skip onboarding coach marks — they render a full-screen overlay that
  // intercepts pointer events and would block the tab-bar/profile clicks below.
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
  await page.goto('/')

  // ── 1. Land as a logged-in owner (real auto-login through Splash → Welcome) ──
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // ── 2. Open Profile ─────────────────────────────────────────────────────────
  await page.locator('[data-t="profile"]').click()
  await expect(page.getByText('Вийти з акаунту')).toBeVisible()

  // ── 3. Tap logout, confirm the modal ────────────────────────────────────────
  await page.getByText('Вийти з акаунту').click()
  await expect(page.getByText('Вийти з акаунту?')).toBeVisible()
  await page.getByRole('button', { name: 'Вийти', exact: true }).click()

  // ── 4. Land on the idle WelcomeScreen (fromLogout suppresses auto-login —
  //      it must NOT silently bounce back to db-list on its own) ──────────────
  const loginBtn = page.getByRole('button', { name: /Увійти через Telegram/i })
  await expect(loginBtn).toBeVisible({ timeout: 10_000 })
  await page.waitForTimeout(600)
  await expect(loginBtn).toBeVisible()
  await expect(page.getByText('Мої бази')).toHaveCount(0)

  // ── 5. Tap the Telegram login button again — this is exactly the moment the
  //      bug fired: logout's lingering auth lock / CORS failure made this hang
  //      or show a false "no internet" error instead of succeeding ───────────
  await loginBtn.click()

  // ── 6. Fresh login succeeds and lands back on db-list ───────────────────────
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.toast')).toHaveCount(0)
})

test('login network abort shows a toast (not a hang) and a retry with a working mock succeeds', async ({ page }) => {
  await setupApp(page, { user: OWNER })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })

  let mode: 'fail' | 'success' = 'fail'
  const jwt = makeJwt(OWNER)

  // Registered after setupApp()'s mockBackend route, so this one wins
  // (Playwright: most-recently-registered matching route runs first).
  await page.route('**/functions/v1/telegram-auth', async (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, checks: {} }) })
    }
    if (mode === 'fail') {
      await route.abort('failed')
      return
    }
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ access_token: jwt, refresh_token: 'refresh-xyz', user: OWNER, is_new: false }),
    })
  })

  // Reach the idle WelcomeScreen directly (no auto-login), same trick used by
  // layout-buttons.spec.ts: the #fromLogout hash makes SplashScreen skip
  // restoreSession() and go straight to the manual-login screen.
  await page.goto('/#fromLogout')
  const loginBtn = page.getByRole('button', { name: /Увійти через Telegram/i })
  await expect(loginBtn).toBeVisible({ timeout: 10_000 })

  // ── 1. First attempt: the network call is aborted — must surface a toast,
  //      never hang the button in a permanent loading state ─────────────────
  await loginBtn.click()
  // Scope to the app's own Toast component — Next.js also renders an
  // (empty, unrelated) route-announcer div with role="alert" on every page.
  const alert = page.locator('.toast[role="alert"]')
  await expect(alert).toBeVisible({ timeout: 10_000 })
  await expect(alert).toContainText(/Помилка входу/i)

  // App must still be usable — back on idle Welcome, button clickable again.
  await expect(loginBtn).toBeVisible()
  await expect(page.getByText('Мої бази')).toHaveCount(0)

  // ── 2. Second attempt with a working mock succeeds ──────────────────────────
  mode = 'success'
  await loginBtn.click()
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
})
