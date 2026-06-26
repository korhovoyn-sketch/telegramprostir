import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ⭐ The headline guard: on a small screen (iPhone SE), every primary button a
// user must tap during onboarding has to be fully visible and tappable. This is
// the exact class of bug ("синю кнопку входу не видно / сплюснута") that kept
// recurring. boundingBox() reads the REAL rendered layout, not the DOM.

const MIN_TAP_HEIGHT = 40

async function assertButtonTappable(name: RegExp, page: import('@playwright/test').Page) {
  const btn = page.getByRole('button', { name })
  await expect(btn).toBeVisible()
  const box = await btn.boundingBox()
  expect(box, `boundingBox for ${name}`).not.toBeNull()
  const vp = page.viewportSize()!
  expect(box!.height, 'button height').toBeGreaterThanOrEqual(MIN_TAP_HEIGHT)
  // Top and bottom edges must sit inside the viewport (not clipped by overflow:hidden).
  expect(box!.y, 'button top in viewport').toBeGreaterThanOrEqual(0)
  expect(box!.y + box!.height, 'button bottom in viewport').toBeLessThanOrEqual(vp.height + 1)
}

test('login button is fully visible on the idle Welcome screen', async ({ page }) => {
  await setupApp(page, { noAutoLogin: true })
  await page.goto('/?tgWebAppData=mock#fromLogout')
  // Idle Welcome shows once auto-login is suppressed; reach it via the manual path.
  await page.getByRole('button', { name: /Увійти через Telegram/i }).waitFor()
  await assertButtonTappable(/Увійти через Telegram/i, page)
})

test('onboarding buttons stay visible across role-select → profile-setup → empty-state', async ({ page }) => {
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
  await page.goto('/')

  // role-select
  await assertButtonTappable(/Продовжити/i, page)
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()

  // profile-setup — both the main and skip buttons
  await assertButtonTappable(/Почати роботу/i, page)
  await assertButtonTappable(/Пропустити/i, page)
  await page.getByRole('button', { name: /Пропустити/i }).click()

  // empty-state (owner)
  await assertButtonTappable(/Створити першу базу/i, page)
})
