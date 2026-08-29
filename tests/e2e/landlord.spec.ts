import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Орендодавець (той, ХТО ЗДАЄ) — 064. Модель: значення бази є дефолтом на всі
// її обʼєкти, обʼєкт може його перевизначити; NULL на обʼєкті = «як у базі».
//
// Найтонше місце — КАРТКА списку: назва там показується ЛИШЕ при
// перевизначенні. Спільний на всю базу орендодавець дав би той самий рядок на
// кожній картці, яку щойно спеціально схудли на 56px. Тому кожен гард картки
// тут має антивакуумну половину: обʼєкт, чиє значення ЗБІГАЄТЬСЯ з базою, і
// обʼєкт БЕЗ власного значення не малюють нічого.

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()
const BASE_LL = 'ТОВ «Дефолт»'
const OWN_LL = 'ФОП Кравець'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', landlord_name: BASE_LL,
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, landlord: string | null) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс ${100 + n}`, floor: String(n), status: 'free',
    area_useful: 45, area_total: 52, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, landlord_name: landlord,
    lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [] as Record<string, unknown>[],
  }
}

interface Wire {
  dbPosts: Record<string, unknown>[]
  propPatches: Record<string, unknown>[]
  propSelects: string[]
}

const freshWire = (): Wire => ({ dbPosts: [], propPatches: [], propSelects: [] })

async function setup(page: Page, wire: Wire, props = [prop(1, OWN_LL), prop(2, BASE_LL), prop(3, null)]) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    if (rq.method() === 'POST') {
      wire.dbPosts.push(JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>)
      return jsonRoute(r, [{ ...DB, id: '10000000-0000-0000-0000-0000000000ff' }])
    }
    return jsonRoute(r, (rq.headers()['accept'] ?? '').includes('object') ? DB : [DB])
  })

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    const url = decodeURIComponent(rq.url())
    if (rq.method() === 'PATCH') {
      wire.propPatches.push(JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>)
      const id = url.match(/id=eq\.([0-9a-f-]+)/)?.[1]
      return jsonRoute(r, [props.find((p) => p.id === id) ?? props[0]])
    }
    if (rq.method() === 'GET') wire.propSelects.push(url)
    if ((rq.headers()['accept'] ?? '').includes('object')) {
      const id = url.match(/id=eq\.([0-9a-f-]+)/)?.[1]
      return jsonRoute(r, props.find((p) => p.id === id) ?? props[0])
    }
    return jsonRoute(r, props)
  })

  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

async function openDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

test('форма бази пише орендодавця в POST', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /Створити базу|Додати базу/ }).first().click()

  await page.getByLabel('Назва бази').fill('БЦ Новий')
  await page.getByLabel('Орендодавець бази').fill('  ТОВ «Мега»  ')
  await page.locator('.type-card').first().click()
  await page.locator('.mbtn').first().click()
  await expect.poll(() => wire.dbPosts.length, { timeout: 15_000 }).toBe(1)

  expect(wire.dbPosts[0].landlord_name, 'значення обрізається').toBe('ТОВ «Мега»')
})

test('картка показує орендодавця ЛИШЕ при перевизначенні', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)

  const card = (name: string) => page.locator('.obj-card').filter({ hasText: name })

  // Перевизначив — видно.
  await expect(card('Офіс 101').getByText(OWN_LL)).toBeVisible()

  // Антивакуум-1: значення ЗБІГАЄТЬСЯ з базою — рядка немає (інакше кожна
  // картка бази з одним орендодавцем несла б однаковий шум).
  await expect(card('Офіс 102').getByText(BASE_LL)).toHaveCount(0)
  // Антивакуум-2: власного значення немає взагалі — теж нічого.
  await expect(card('Офіс 103').getByText(BASE_LL)).toHaveCount(0)
  await expect(card('Офіс 103').getByText(OWN_LL)).toHaveCount(0)
})

test('деталь: обʼєкт без свого значення успадковує орендодавця бази', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)

  // Офіс 103 — landlord_name: null.
  await page.locator('.obj-card').filter({ hasText: 'Офіс 103' }).locator('.obj-t').click()
  await expect(page.getByText('Орендодавець', { exact: true })).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText(BASE_LL, { exact: true })).toBeVisible()
})

test('форма обʼєкта пише орендодавця, і НЕ гейтить його статусом', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)

  await page.locator('.obj-card').filter({ hasText: 'Офіс 103' }).locator('.obj-more').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.getByText('Редагувати', { exact: true }).click()
  await expect(page.getByLabel('Орендодавець')).toBeVisible({ timeout: 15_000 })

  // Статус лишається «Вільно» — орендодавець є властивістю ПРОСТОРУ, а не
  // орендних відносин, тож поле мусить бути доступним і зберігатись.
  await page.getByLabel('Орендодавець').fill(OWN_LL)
  await page.locator('.mbtn').first().click()
  await expect.poll(() => wire.propPatches.length, { timeout: 15_000 }).toBeGreaterThan(0)

  expect(wire.propPatches[0].landlord_name).toBe(OWN_LL)
})

test('експорт тягне орендодавця у вибірці', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Експорт', { exact: true }).click()
  await expect(page.getByRole('button', { name: /Завантажити/ })).toBeVisible({ timeout: 15_000 })

  const before = wire.propSelects.length
  await page.getByRole('button', { name: /Завантажити/ }).click()
  await expect.poll(() => wire.propSelects.length, { timeout: 20_000 }).toBeGreaterThan(before)

  const sel = wire.propSelects[wire.propSelects.length - 1]
  expect(sel, 'без колонки в вибірці документ друкував би порожній стовпець').toContain('landlord_name')
  expect(sel, 'share_token за межі застосунку не їде').not.toContain('share_token')
})
