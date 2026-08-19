import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Full owner workflow: every screen an owner touches ───────────────────────

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'occupied', rent_rate: 2500, area_useful: 80, rent_type: 'fixed' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, rent_type: 'per_m2',
    rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5 }),
  prop(2, { status: 'occupied', tenant_name: 'ФОП Іванов', rent_type: 'fixed', rent_rate: 2500, area_useful: 80, area_total: 90 }),
  prop(3, {}),
]

async function setupFixtures(page: Page) {
  await setupApp(page, { user: USER })
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (route) => {
    if (route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      return json(route, [{ ...DB, ...body, id: '10000000-0000-0000-0000-000000000002', properties: [] }])
    }
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const url = route.request().url()
    const accept = route.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = url.match(/id=eq\.([0-9a-f-]+)/)
      const found = PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0]
      return json(route, found)
    }
    return json(route, PROPERTIES)
  })
  await page.route('**/rest/v1/guest_links**', (route) => {
    if (route.request().method() === 'POST') {
      return json(route, [{
        id: '30000000-0000-0000-0000-000000000001', owner_id: USER.id,
        property_id: null, db_id: DB_ID, invite_token: 'cc00112233445566778899aa',
        label: 'Тестовий гість', guest_user_id: null, status: 'pending',
        claimed_at: null, created_at: NOW,
      }])
    }
    return json(route, [])
  })
  await page.route('**/rest/v1/rpc/manage_share', (route) =>
    json(route, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))

  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

test('owner: create database form submits', async ({ page }) => {
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Тест')
  await page.locator('.type-card', { hasText: 'Бізнес-центр' }).click() // canCreate needs a type
  const postReq = page.waitForRequest(r => r.url().includes('/rest/v1/databases') && r.method() === 'POST')
  await page.getByRole('button', { name: 'Створити базу' }).click()
  await postReq
})

test('owner: objects — sort, search, select & reorder modes', async ({ page }) => {
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Sort by rent: fixed 2500 (Офіс 102) must come before 100×18=1800 (Офіс 101)
  await page.getByText('За орендою').click()
  await expect(page.locator('.obj-t').first()).toHaveText('Офіс 102')
  // Sort by floor: ascending ground-up (Офіс 101 = floor 2) → first, unlike rent
  await page.getByText('За поверхом').click()
  await expect(page.locator('.obj-t').first()).toHaveText('Офіс 101')
  await page.getByText('За порядком').click()

  // Search filters the list
  await page.getByPlaceholder("Пошук об'єкту...").fill('103')
  await expect(page.locator('.obj-card')).toHaveCount(1)
  await page.getByPlaceholder("Пошук об'єкту...").fill('')

  // Select mode via the action sheet; "Вибрати все"/"Зняти все" toggle
  await page.getByLabel('Меню бази').click()
  await page.getByText("Виділити об'єкти").click()
  await expect(page.getByText("Оберіть об'єкти для дії")).toBeVisible()
  await page.getByText('Вибрати все').click()
  await expect(page.getByText('Зняти все')).toBeVisible()
  await page.getByText('Зняти все').click()
  await page.getByRole('button', { name: 'Скасувати' }).click()  // exit select mode (header)
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Reorder mode via the action sheet
  await page.getByLabel('Меню бази').click()
  await page.getByText('Змінити порядок').click()
  await expect(page.getByText(/Натисніть ↑ або ↓/)).toBeVisible()
  await page.getByText('Готово').click()  // exit reorder mode
})

test('owner: property detail and form validation logic', async ({ page }) => {
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Property detail opens from a card (card view shows the object name)
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible()

  // Back to objects, then new-property form validation
  await page.getByText('Назад', { exact: true }).first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  await page.getByPlaceholder('Офіс 101').fill('Тест-об\'єкт')
  await page.getByPlaceholder('47').fill('100')  // useful
  await page.getByPlaceholder('52').fill('50')   // total < useful → error
  await page.getByRole('button', { name: "Додати об'єкт" }).click()
  await expect(page.getByText('Корисна площа більша за розрахункову')).toBeVisible()

  // negative/garbage input can't even be typed — the sanitizer strips it at
  // entry (the old error-toast path is unreachable from the keyboard now)
  await page.getByPlaceholder('52').fill('120')
  const rate = page.getByPlaceholder('18')
  await rate.fill('-5')
  await expect(rate).toHaveValue('5')
  await rate.fill('12,5')
  await expect(rate).toHaveValue('12.5')
  await rate.fill('12.5.7')
  await expect(rate).toHaveValue('12.57')
})

test('owner: empty status tab shows a status message, not a search dead-end', async ({ page }) => {
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // The fixture has 0 for-sale objects — the "Продаж" tab is empty.
  await page.getByText(/Продаж \(0\)/).click()
  // Status-specific empty state + a way back to all — NOT the search "Нічого
  // не знайдено" with an empty query and a useless "Очистити пошук".
  await expect(page.getByText('Немає об\'єктів на продаж')).toBeVisible()
  await expect(page.getByText(/Нічого не знайдено/)).toHaveCount(0)
  await page.getByRole('button', { name: 'Показати всі' }).click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
})

test('owner: calendar, guests, notifications, profile screens open cleanly', async ({ page }) => {
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Payment calendar
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.locator('.retry-h')).toHaveCount(0)
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible()
  await page.getByText('Назад', { exact: true }).first().click()

  // Manage guests: create an invite
  await page.getByLabel('Меню бази').click()
  await page.getByText('Управління гостями').click()
  await page.getByLabel('Запросити гостя').click()
  const createBtn = page.getByRole('button', { name: /Створити/ })
  await createBtn.click()
  await expect(page.getByText(/Посилання створено/)).toBeVisible()

  // Notifications via tab bar (header bell removed — tab is the only entry)
  // CreateInviteScreen — повноекранний маршрут (фаза 3 переробки модалок),
  // виходимо кнопкою Header «Назад» (перший клік: created → manage-guests,
  // другий: manage-guests → db-objects, де вже є таббар).
  await page.getByText('Назад', { exact: true }).first().click()
  await page.getByText('Назад', { exact: true }).first().click()
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Немає сповіщень')).toBeVisible()

  // Profile via tab bar
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible()
})

test('owner: bulk create sends one INSERT with auto-numbered names', async ({ page }) => {
  await setupFixtures(page)
  let postBody: Record<string, unknown>[] | null = null
  // Registered after setupFixtures → takes precedence; GETs fall back to it.
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      postBody = JSON.parse(req.postData() ?? '[]')
      const rows = (postBody ?? []).map((b, i) => ({
        ...PROPERTIES[0], ...b, id: `20000000-0000-0000-0000-00000000010${i}`, photos: [],
      }))
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(rows) })
    }
    return route.fallback()
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  await page.getByPlaceholder('Офіс 101').fill('Офіс 201')
  await page.getByLabel("Більше об'єктів").click()
  await page.getByLabel("Більше об'єктів").click() // count = 3
  await expect(page.getByText('Буде створено')).toBeVisible()
  for (const n of ['Офіс 201', 'Офіс 202', 'Офіс 203']) {
    await expect(page.getByPlaceholder(n, { exact: true })).toBeVisible()
  }

  await page.getByRole('button', { name: "Додати 3 об'єкти" }).click()
  await expect.poll(() => postBody, { timeout: 10_000 }).not.toBeNull()
  expect(postBody!.map(b => b.name)).toEqual(['Офіс 201', 'Офіс 202', 'Офіс 203'])
  // Success lands back on the objects list
  await expect(page.getByPlaceholder("Пошук об'єкту...")).toBeVisible()
})
