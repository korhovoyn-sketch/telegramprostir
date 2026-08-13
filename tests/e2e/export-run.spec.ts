import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Експорт: сам ЗАПУСК, а не лише наявність кнопки.
//
// До цього спека `handleExport` не викликався жодним тестом: `owner-sweep`
// перевіряв, що кнопка є, `native-client-sweep` — що екран живий,
// `screenshots` — як він виглядає. Тобто вибірка даних, фільтр «тільки вільні»,
// порожня база й офлайн-гард не були покриті взагалі.
//
// Найважливіший інваріант тут — `share_token` НЕ потрапляє у вибірку: файл
// їде за межі застосунку і не має нести живі креденшели доступу.

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, status: string) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс ${100 + n}`, floor: String(n), status, area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: status === 'occupied' ? 'ТОВ «Ромашка»' : null,
    lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  }
}

interface Wire { selects: string[] }

async function setup(page: Page, wire: Wire, props = [prop(1, 'free'), prop(2, 'occupied')]) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const url = decodeURIComponent(r.request().url())
    if (r.request().method() === 'GET') wire.selects.push(url)
    return jsonRoute(r, props)
  })
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

async function openExport(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Експорт', { exact: true }).click()
  await expect(page.getByRole('button', { name: /Завантажити/ })).toBeVisible({ timeout: 15_000 })
}

test('експорт PDF тягне дані і НЕ включає share_token у вибірку', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire)
  await openExport(page)

  const before = wire.selects.length
  await page.getByRole('button', { name: /Завантажити PDF/ }).click()
  await expect.poll(() => wire.selects.length, { timeout: 15_000 }).toBeGreaterThan(before)

  const exportSelect = wire.selects[wire.selects.length - 1]
  expect(exportSelect, 'вибірка обмежена цією базою').toContain(`db_id=eq.${DB_ID}`)
  expect(exportSelect, 'токен доступу не має їхати у файл').not.toContain('share_token')
})

test('перемикання на Excel міняє підпис кнопки і теж виконується', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire)
  await openExport(page)

  await page.locator('.format-card').nth(1).click()
  await expect(page.getByRole('button', { name: /Завантажити Excel/ })).toBeVisible()

  const before = wire.selects.length
  await page.getByRole('button', { name: /Завантажити Excel/ }).click()
  await expect.poll(() => wire.selects.length, { timeout: 20_000 }).toBeGreaterThan(before)
})

test('порожня база: замість порожнього файлу — зрозуміла відмова', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire, [])
  await openExport(page)

  await page.getByRole('button', { name: /Завантажити/ }).click()
  await expect(page.locator('.toast')).toContainText(/Немає об.єктів для експорту/, { timeout: 15_000 })
})

test('«тільки вільні» на базі без вільних — окреме пояснення, а не тиша', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire, [prop(1, 'occupied'), prop(2, 'occupied')])
  await openExport(page)

  // Перемикач «тільки вільні» — єдиний свіч на екрані експорту.
  await page.locator('.switch, [role="switch"]').first().click()
  await page.waitForTimeout(200)
  await page.getByRole('button', { name: /Завантажити/ }).click()

  await expect(page.locator('.toast')).toContainText(/вільних об.єктів/, { timeout: 15_000 })
})

test('офлайн: експорт не стартує і каже про це', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire)
  await openExport(page)

  await page.evaluate(() => window.dispatchEvent(new Event('offline')))
  await page.waitForTimeout(200)

  const before = wire.selects.length
  await page.getByRole('button', { name: /Завантажити/ }).click()
  await page.waitForTimeout(900)

  expect(wire.selects.length, 'офлайн не має ходити в мережу').toBe(before)
  await expect(page.locator('.toast')).toContainText(/офлайн|Немає інтернету/i)
})
