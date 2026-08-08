import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// У webview Telegram на iOS `env(safe-area-inset-*)` не наповнюється — саме тому
// Bot API 8.0 додав safeAreaInset / contentSafeAreaInset. На цих значеннях у нас
// висить УВЕСЬ хром (таббар, плаваюча CTA, панель обраних, кнопки шита), тож
// нульовий вріз = кнопка під home-індикатором. Chromium цього не показує, бо в
// ньому env() працює, — перевіряємо саме телеграмний шлях.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '2', status: 'occupied', area_useful: 100, area_total: 120,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: 'ТОВ «Ромашка»', lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}

type SafeAreaFn = (d: { top?: number; bottom?: number }, c?: { top?: number; bottom?: number }) => void

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * Значення --safe-* міряємо через РЕАЛЬНУ властивість: кастомна властивість
 * підставляється як текст, тож getPropertyValue('--safe-bottom') віддає
 * невирішений `max(0px,34px)`. Проба з padding дає вже порахований px.
 */
const readVars = (page: Page) => page.evaluate(() => {
  const probe = document.createElement('div')
  probe.style.paddingTop = 'var(--safe-top)'
  probe.style.paddingBottom = 'var(--safe-bottom)'
  document.body.appendChild(probe)
  const cs = getComputedStyle(probe)
  const out = {
    top: cs.paddingTop,
    bottom: cs.paddingBottom,
    tgBottom: getComputedStyle(document.documentElement).getPropertyValue('--tg-safe-bottom').trim(),
  }
  probe.remove()
  return out
})

/**
 * Чекає, поки СКІНЧЕНІ анімації елемента дограють. Без цього вимір геометрії
 * ловить кадр анімації входу: `.tabbar` заїжджає з `scale(.92)`, тож базова
 * висота читалась як 55 замість 56 — і `before.height + 34` розходився з
 * фактичним на 1-2px (флейк, який ретрай маскував). Фільтруємо саме по
 * елементу: у застосунку є нескінченні анімації (shimmer, orbPulse), їхній
 * `finished` не настане ніколи.
 */
async function settle(page: Page, ...selectors: string[]) {
  await page.evaluate(async (sels) => {
    const anims = sels.flatMap((sel) => {
      const el = document.querySelector(sel)
      return el ? el.getAnimations() : []
    })
    await Promise.all(anims.map((a) => a.finished.catch(() => {})))
  }, selectors)
}

/** Відступ таббару від низу застосунку — на ньому найкраще видно вріз. */
const tabbarGap = (page: Page) => page.evaluate(() => {
  const tab = document.querySelector('.tabbar') as HTMLElement
  const root = document.getElementById('app-root') as HTMLElement
  const cs = getComputedStyle(tab)
  return {
    height: Math.round(tab.getBoundingClientRect().height),
    paddingBottom: Math.round(parseFloat(cs.paddingBottom)),
    bottomEdge: Math.round(root.getBoundingClientRect().bottom - tab.getBoundingClientRect().bottom),
  }
})

test('вріз від Telegram піднімає хром, навіть коли env() дає нуль', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  await settle(page, '.scr', '.tabbar')
  const before = await tabbarGap(page)
  expect(before.paddingBottom, 'без врізу таббар без нижнього відступу').toBe(0)

  // iPhone із home-індикатором: Telegram повідомляє 34px
  await page.evaluate(() => (window as unknown as { __tgSafeArea: SafeAreaFn }).__tgSafeArea({ bottom: 34, top: 47 }))
  await page.waitForTimeout(200)

  const vars = await readVars(page)
  expect(vars.tgBottom, 'значення від Telegram доїхало в CSS').toBe('34px')
  expect(vars.bottom, '--safe-bottom = max(env, telegram)').toBe('34px')
  expect(vars.top).toBe('47px')

  await settle(page, '.scr', '.tabbar')
  const after = await tabbarGap(page)
  expect(after.paddingBottom, 'таббар отримав нижній відступ під індикатор').toBe(34)
  expect(after.height, 'висота таббару зросла на вріз').toBe(before.height + 34)
})

test('contentSafeArea (контроли Telegram) додається до врізу пристрою', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // Fullscreen: шапка Telegram накриває контент — обійти треба ОБА врізи
  await page.evaluate(() => (window as unknown as { __tgSafeArea: SafeAreaFn })
    .__tgSafeArea({ top: 47, bottom: 34 }, { top: 46, bottom: 0 }))
  await page.waitForTimeout(200)

  const vars = await readVars(page)
  expect(vars.top, 'вріз пристрою + контроли Telegram').toBe('93px')
  expect(vars.bottom).toBe('34px')
})

test('плаваюча CTA і панель обраних стоять вище home-індикатора', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })

  await settle(page, '.scr', '.fbtn')
  const gapBefore = await page.evaluate(() => {
    const btn = document.querySelector('.fbtn') as HTMLElement
    const root = document.getElementById('app-root') as HTMLElement
    return Math.round(root.getBoundingClientRect().bottom - btn.getBoundingClientRect().bottom)
  })

  await page.evaluate(() => (window as unknown as { __tgSafeArea: SafeAreaFn }).__tgSafeArea({ bottom: 34 }))
  await page.waitForTimeout(250)

  await settle(page, '.scr', '.fbtn')
  const gapAfter = await page.evaluate(() => {
    const btn = document.querySelector('.fbtn') as HTMLElement
    const root = document.getElementById('app-root') as HTMLElement
    return Math.round(root.getBoundingClientRect().bottom - btn.getBoundingClientRect().bottom)
  })
  expect(gapAfter, 'кнопка піднялась рівно на вріз').toBe(gapBefore + 34)
})

test('нульовий вріз не ламає calc — хром лишається на місці', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // Telegram повідомляє нулі (пристрій без нотча) — жодна висота не має злетіти
  await page.evaluate(() => (window as unknown as { __tgSafeArea: SafeAreaFn }).__tgSafeArea({ top: 0, bottom: 0 }))
  await page.waitForTimeout(200)

  const geo = await page.evaluate(() => {
    const tab = document.querySelector('.tabbar') as HTMLElement
    const body = document.querySelector('.body') as HTMLElement
    return {
      tabH: Math.round(tab.getBoundingClientRect().height),
      bodyPad: Math.round(parseFloat(getComputedStyle(body).paddingBottom)),
    }
  })
  expect(geo.tabH, 'таббар лишився 56px').toBe(56)
  expect(geo.bodyPad, 'padding тіла лишився валідним (не 0 і не auto)').toBeGreaterThan(50)
})
