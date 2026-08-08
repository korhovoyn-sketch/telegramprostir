import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Пошук по об'єктах: репорт «вводиш ключову фразу — не підтягує нічого».
// Дані відтворюють реальну базу: об'єкти розкладені по папках (акордеон), у
// назвах довгі фрази з дужками, є орендарі й поверхи.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const F1 = '30000000-0000-0000-0000-0000000000f1'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'Міком Палац', address: 'Дегтярівська 27-Т',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}

const FOLDERS = [{ id: F1, db_id: DB_ID, owner_id: USER.id, name: 'Орендарі', sort_order: 1, created_at: NOW, updated_at: NOW }]

function prop(n: number, name: string, folder: string | null, extra: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-0000000000${String(n).padStart(2, '0')}`,
    db_id: DB_ID, owner_id: USER.id, name, floor: String(n), status: 'occupied',
    area_useful: 100 + n, area_total: 120 + n, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: folder, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: 'Фоп Плотко', lease_start_date: null, lease_end_date: null,
    sort_order: n, share_token: `bb0000000000000000${String(n).padStart(4, '0')}`,
    share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
    ...extra,
  }
}

const PROPS = [
  prop(1, 'Офіс 10 поверху ( мале крило )', F1),
  prop(2, 'Офіс 11 поверху ( велике крило )', F1),
  prop(3, 'Склад цокольний', null),
]

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : PROPS))
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, FOLDERS))
  for (const t of ['property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

async function openObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Міком Палац').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible({ timeout: 15_000 })
}

/**
 * Назви КАРТОК, які реально видно. `getClientRects()` тут не годиться: у
 * згорнутій папці `.fold-wrap` має height:0 + overflow:hidden, і вкладені
 * елементи все одно звітують свої прямокутники — тобто «видимими» виглядали б
 * і заклеєні картки. Тому перевіряємо саму обгортку акордеона.
 */
const visibleCards = (page: Page) => page.evaluate(() =>
  [...document.querySelectorAll('.obj-t')]
    .filter((el) => {
      const wrap = el.closest('.fold-wrap') as HTMLElement | null
      if (wrap && wrap.getBoundingClientRect().height === 0) return false
      return (el as HTMLElement).getClientRects().length > 0
    })
    .map((el) => el.textContent?.trim() ?? ''))

test('пошук по назві звужує список, знахідка видима', async ({ page }) => {
  await setup(page)
  await openObjects(page)

  await page.getByPlaceholder('Пошук об\'єкту...').fill('мале')
  await page.waitForTimeout(500)

  expect(await visibleCards(page)).toEqual(['Офіс 10 поверху ( мале крило )'])
})

test('пошук працює у ЗГОРНУТІЙ папці — знахідку видно, а не порожню секцію', async ({ page }) => {
  await setup(page)
  await openObjects(page)

  // Користувач згортає папку — саме так виглядає щоденний стан бази.
  await page.locator('.fold-hd', { hasText: 'Орендарі' }).click()
  await page.waitForTimeout(500)
  expect(await visibleCards(page)).toEqual(['Склад цокольний'])

  await page.getByPlaceholder('Пошук об\'єкту...').fill('велике')
  await page.waitForTimeout(600)

  expect(await visibleCards(page), 'знахідка в згорнутій папці мусить проявитись').toEqual(['Офіс 11 поверху ( велике крило )'])
})

test('пошук по орендарю знаходить об\'єкт', async ({ page }) => {
  await setup(page)
  await openObjects(page)

  await page.getByPlaceholder('Пошук об\'єкту...').fill('плотко')
  await page.waitForTimeout(500)

  expect(await visibleCards(page)).toHaveLength(3)
})

test('пошук по поверху знаходить об\'єкт', async ({ page }) => {
  await setup(page)
  await openObjects(page)

  // Поверх «3» має лише «Склад цокольний» — тобто збіг саме по полю floor,
  // у назві цифри немає.
  await page.getByPlaceholder('Пошук об\'єкту...').fill('3')
  await page.waitForTimeout(500)

  expect(await visibleCards(page)).toEqual(['Склад цокольний'])
})

test('ключова ФРАЗА: слова з різних місць назви, порядок і зайві слова не важать', async ({ page }) => {
  await setup(page)
  await openObjects(page)

  const input = page.getByPlaceholder('Пошук об\'єкту...')

  // Точного підрядка «офіс мале» в назві НЕМА — між словами ще «10 поверху (».
  await input.fill('офіс мале')
  await page.waitForTimeout(500)
  expect(await visibleCards(page)).toEqual(['Офіс 10 поверху ( мале крило )'])

  // Зворотний порядок слів дає той самий результат.
  await input.fill('мале офіс')
  await page.waitForTimeout(500)
  expect(await visibleCards(page)).toEqual(['Офіс 10 поверху ( мале крило )'])

  // Слово, якого немає ні в кого, лишає порожньо (фільтр не «пропускає все»).
  await input.fill('офіс горище')
  await page.waitForTimeout(500)
  expect(await visibleCards(page)).toEqual([])
})

test('крос-база: пошук з домашнього екрана питає всі поля і не звужує по owner_id', async ({ page }) => {
  const queries: string[] = []
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const url = r.request().url()
    if (url.includes('or=')) {
      queries.push(decodeURIComponent(url))
      return jsonRoute(r, [{ ...PROPS[0], tenant_name: 'Фоп Плотко' }])
    }
    return jsonRoute(r, PROPS)
  })
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, FOLDERS))
  for (const t of ['property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByPlaceholder(/Пошук бази або об/).fill('плотко')
  await expect.poll(() => queries.length, { timeout: 10_000 }).toBeGreaterThan(0)

  const q = queries[0]
  expect(q, 'орендар').toContain('tenant_name.ilike')
  expect(q, 'адреса').toContain('address.ilike')
  expect(q, 'поверх').toContain('floor.ilike')
  // Обмеження «свій owner_id» віддавало члену команди порожньо — видимість
  // вирішує RLS, а не клієнт.
  expect(q, 'owner_id не фільтруємо').not.toContain('owner_id=eq')

  await expect(page.getByText('Офіс 10 поверху ( мале крило )').first()).toBeVisible()
})
