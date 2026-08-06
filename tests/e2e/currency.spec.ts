import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Користувач: «зміна валюти не працює». Перевіряємо весь ланцюг: тап по
// сегменту → PATCH users → активний сегмент → суми в застосунку в новій валюті.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', currency: 'USD' }
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
  created_at: NOW, updated_at: NOW, photos: [],
}

async function setup(page: Page, captured: { patch?: Record<string, unknown> }) {
  const state = { user: { ...USER } }
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/users**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      captured.patch = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      state.user = { ...state.user, ...captured.patch }
      const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? state.user : [state.user])
    }
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? state.user : [state.user])
  })
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

test('валюта: тап по ₴ надсилає PATCH, сегмент стає активним, суми у ₴', async ({ page }) => {
  const captured: { patch?: Record<string, unknown> } = {}
  await setup(page, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible()

  const uah = page.locator('.fr-seg-b', { hasText: 'UAH' })
  await expect(uah).toBeVisible()
  await expect(uah).not.toHaveClass(/on/)
  await uah.click()

  await expect.poll(() => captured.patch, { timeout: 10_000 }).toBeTruthy()
  expect(captured.patch!.currency, 'валюта в PATCH').toBe('UAH')
  await expect(uah, 'сегмент UAH став активним').toHaveClass(/on/, { timeout: 10_000 })

  // Суми в застосунку одразу в новій валюті
  await page.locator('.tabbar [aria-label="Бази"]').click()
  await expect(page.getByText('Мої бази')).toBeVisible()
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toContainText('₴', { timeout: 15_000 })
})

test('валюта переживає перезапуск (кеш профілю)', async ({ page }) => {
  const captured: { patch?: Record<string, unknown> } = {}
  await setup(page, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.locator('.fr-seg-b', { hasText: 'EUR' }).click()
  await expect(page.locator('.fr-seg-b', { hasText: 'EUR' })).toHaveClass(/on/, { timeout: 10_000 })

  await page.reload()
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toContainText('€', { timeout: 15_000 })
})

