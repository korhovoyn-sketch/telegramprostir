import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Клавіатура «з'їдає» екран двома різними способами:
//  • ПЕРЕКРИВАЄ (iOS): лейаут на всю висоту → відступ знизу додаємо ми;
//  • СТИСКАЄ webview (Android, новий Telegram iOS): лейаут уже без клавіатури →
//    наш відступ відняв би її ВДРУГЕ.
// Друге і сталося на скріні користувача: модалку затиснуло до ~180px, її тіло
// почало прокручуватись, і sticky-кнопки накрили поле, у яке він друкував.

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

async function openScheduleModal(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()
}

const kbVar = (page: Page) => page.evaluate(() =>
  parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--keyboard-h')) || 0)
const vhVar = (page: Page) => page.evaluate(() =>
  parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--tg-vh')) || 0)

test('клавіатура ПЕРЕКРИВАЄ: висоту віддаємо в --keyboard-h', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  const h = page.viewportSize()!.height
  // Стабільна висота = висота вікна → webview на весь екран, лейаут не стиснуто
  await page.evaluate((v) => (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), h)
  await page.evaluate(() => (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(280))
  await page.waitForTimeout(200)

  expect(await kbVar(page), 'відступ додаємо ми').toBe(280)
  expect(await vhVar(page), 'лейаут лишився на всю висоту').toBe(h)
})

test('клавіатура СТИСКАЄ webview: другий раз її не віднімаємо', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  const full = page.viewportSize()!.height
  await page.evaluate((v) => (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), full)
  // Саме так поводиться Telegram, що ресайзить webview: вікно стало нижчим…
  await page.setViewportSize({ width: page.viewportSize()!.width, height: full - 280 })
  // …і паралельно прийшов viewportChanged із тією ж різницею
  await page.evaluate(() => (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(280))
  await page.waitForTimeout(200)

  expect(await kbVar(page), 'лейаут уже без клавіатури — додатковий відступ = 0').toBe(0)
  expect(await vhVar(page), '--tg-vh дорівнює реально доступній висоті').toBe(full - 280)
})

test('модалка у стиснутому webview не затискається і не ховає поле під кнопки', async ({ page }) => {
  await setup(page)
  await openScheduleModal(page)

  const full = page.viewportSize()!.height
  await page.evaluate((v) => (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), full)
  await page.setViewportSize({ width: page.viewportSize()!.width, height: full - 300 })
  await page.evaluate(() => (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(300))
  await page.waitForTimeout(300)

  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  await dayInput.focus()
  await page.waitForTimeout(900)

  const geo = await page.evaluate(() => {
    const f = (document.querySelector('.modal input[inputmode="numeric"]') as HTMLElement).getBoundingClientRect()
    const a = (document.querySelector('.modal-actions') as HTMLElement).getBoundingClientRect()
    const m = (document.querySelector('.modal') as HTMLElement).getBoundingClientRect()
    return {
      fieldTop: Math.round(f.top), fieldBottom: Math.round(f.bottom),
      actionsTop: Math.round(a.top), modalH: Math.round(m.height), modalTop: Math.round(m.top),
    }
  })
  expect(geo.fieldBottom, 'поле не заходить під кнопки дій').toBeLessThanOrEqual(geo.actionsTop)
  expect(geo.fieldTop, 'поле не виїхало за верх').toBeGreaterThan(0)
  expect(geo.modalTop, 'шапка шита на екрані').toBeGreaterThanOrEqual(0)
  await expect(dayInput).toBeVisible()
  await expect(page.getByRole('button', { name: 'Зберегти' })).toBeVisible()
})
