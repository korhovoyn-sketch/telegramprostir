import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, objectAction } from './helpers/harness'

/**
 * ЗАПИС НА БЕКЕНДІ, ДЕ МІГРАЦІЮ 064 (`landlord_name`) ЩЕ НЕ НАКОЧЕНО.
 *
 * CLAUDE.md обіцяв «порядок деплою НЕ критичний»: читані списки мають ретрай
 * на 42703. Але ретрай стояв лише на ЧИТАННІ списку. Запис обʼєкта просив у
 * відповідь `select=…landlord_name…` і слав ту саму колонку в тілі, тож на
 * такому бекенді PostgREST віддавав 400 на КОЖНЕ збереження:
 *   • редагування обʼєкта, «Здати в оренду», «Звільнити»;
 *   • створення й редагування бази;
 *   • масове створення з форми та імпорт CSV — ці падали навіть із ПОРОЖНІМ
 *     полем, бо supabase-js для масиву ставить `columns=` з `Object.keys`, а
 *     ключ зі значенням `undefined` туди потрапляє.
 * Користувач бачив «Сервіс тимчасово недоступний» — тобто нічого не міг
 * зберегти, хоча список малювався нормально.
 *
 * Мок відтворює саме дріт PostgREST: невідома колонка в `select=`, `columns=`
 * або тілі — 400 з її іменем у повідомленні. Решту запитів віддає далі.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = '2026-09-01T09:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', created_at: NOW, updated_at: NOW, properties: [],
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'free', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 100, created_at: NOW, updated_at: NOW, photos: [],
}

type Log = { refused: string[]; writes: { method: string; table: string; body: unknown }[] }

/** Що на дроті згадує колонку, якої ще немає. */
function mentionsLandlord(r: Route): boolean {
  const rq = r.request()
  const url = decodeURIComponent(rq.url())
  return url.includes('landlord_name') || (rq.postData() ?? '').includes('landlord_name')
}

async function setup(page: Page, log: Log) {
  await setupApp(page, { user: USER })
  const state = { prop: { ...PROP } as Record<string, unknown>, db: { ...DB } as Record<string, unknown>, created: [] as Record<string, unknown>[] }

  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() !== 'GET') {
      const body = JSON.parse(rq.postData() ?? '{}')
      log.writes.push({ method: rq.method(), table: 'databases', body })
      state.db = { ...state.db, ...(Array.isArray(body) ? body[0] : body) }
      return jsonRoute(r, wantsObject ? state.db : [state.db])
    }
    return jsonRoute(r, wantsObject ? state.db : [state.db])
  })

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}')
      log.writes.push({ method: 'PATCH', table: 'properties', body })
      state.prop = { ...state.prop, ...body }
      return jsonRoute(r, wantsObject ? state.prop : [state.prop])
    }
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '{}')
      log.writes.push({ method: 'POST', table: 'properties', body })
      const rows = (Array.isArray(body) ? body : [body]).map((b: Record<string, unknown>, i: number) => ({
        ...PROP, ...b, id: `2${String(i + 2).padStart(7, '0')}-0000-0000-0000-000000000099`, photos: [],
      }))
      state.created.push(...rows)
      return jsonRoute(r, wantsObject ? rows[0] : rows)
    }
    const all = [state.prop, ...state.created]
    return jsonRoute(r, wantsObject ? state.prop : all)
  })

  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'db_members', 'tenancies', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  // БЕКЕНД БЕЗ 064 — реєструється ОСТАННІМ, тож вирішує першим і пропускає
  // далі лише те, що колонки не згадує.
  for (const table of ['properties', 'databases']) {
    await page.route(`**/rest/v1/${table}**`, (r) => {
      if (!mentionsLandlord(r)) return r.fallback()
      log.refused.push(`${r.request().method()} ${table}`)
      const insert = r.request().method() === 'POST'
      return r.fulfill({
        status: 400, contentType: 'application/json',
        body: JSON.stringify(insert
          ? { code: 'PGRST204', message: `Could not find the 'landlord_name' column of '${table}' in the schema cache` }
          : { code: '42703', message: `column ${table}.landlord_name does not exist` }),
      })
    })
  }

  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function openDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 10_000 })
}

const successfulWrite = (log: Log, method: string, table: string) =>
  log.writes.some((w) => w.method === method && w.table === table && !JSON.stringify(w.body).includes('landlord_name'))

test('редагування обʼєкта зберігається', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await openDb(page)
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  await expect(page.getByText('Збережено')).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'PATCH', 'properties'), 'PATCH без недоступної колонки так і не пішов').toBe(true)
  // Антивакуум: бекенд справді відмовив першій спробі — інакше тест не
  // відрізняв би «ретрай працює» від «колонку й так ніхто не шле».
  expect(log.refused.length, 'мок без 064 не спрацював жодного разу').toBeGreaterThan(0)
  await expect(page.getByText('Сервіс тимчасово недоступний')).toHaveCount(0)
})

test('масове створення з форми зберігається навіть із порожнім орендодавцем', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await openDb(page)
  await page.getByRole('button', { name: /Додати обʼєкт|Новий обʼєкт/ }).first().click()
  await expect(page.getByText('Новий обʼєкт')).toBeVisible()
  await page.getByPlaceholder('Офіс 101').fill('Склад')
  await page.getByLabel('Більше обʼєктів').click()
  await page.getByRole('button', { name: /Додати 2/ }).click()

  await expect(page.getByText(/Додано 2/)).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'POST', 'properties')).toBe(true)
  expect(log.refused.length).toBeGreaterThan(0)
})

test('«Здати в оренду» зберігається', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await openDb(page)
  await page.locator('.obj-t').first().click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await page.getByLabel('Орендар').fill('ТОВ «Ромашка»')
  await page.getByRole('button', { name: 'Здати в оренду' }).last().click()

  await expect(page.getByText('Обʼєкт здано в оренду')).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'PATCH', 'properties')).toBe(true)
  expect(log.refused.length).toBeGreaterThan(0)
})

test('редагування бази зберігається', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Редагувати базу').click()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Рубін Плаза')
  await page.getByRole('button', { name: /Зберегти/ }).click()

  await expect(page.getByText('Базу оновлено')).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'PATCH', 'databases')).toBe(true)
  expect(log.refused.length).toBeGreaterThan(0)
})

test('імпорт CSV зберігається', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText(/Імпорт/).click()
  await page.locator('input[type="file"][accept*="csv"]').setInputFiles({
    name: 'objects.csv', mimeType: 'text/csv',
    buffer: Buffer.from('Назва;Поверх\nОфіс 201;2\nОфіс 202;2\n', 'utf8'),
  })
  await page.getByRole('button', { name: /Імпортувати/ }).click()

  await expect(page.getByText(/Додано 2/)).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'POST', 'properties')).toBe(true)
  expect(log.refused.length).toBeGreaterThan(0)
})

test('створення бази зберігається', async ({ page }) => {
  const log: Log = { refused: [], writes: [] }
  await setup(page, log)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /Створити базу|Нова база/ }).first().click()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Нова')
  await page.locator('.type-card').first().click()
  await page.getByRole('button', { name: 'Створити базу' }).last().click()

  await expect(page.getByText('Базу створено')).toBeVisible({ timeout: 10_000 })
  expect(successfulWrite(log, 'POST', 'databases')).toBe(true)
  expect(log.refused.length).toBeGreaterThan(0)
})
