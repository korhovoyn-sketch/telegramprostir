import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Користувач: «не зберігаються зміни ставки оренди та експлуатації на картці
// простору». PATCH-и вже покриті edit-persistence.spec — тут перевіряємо ПОВНИЙ
// круг: зберегти → повернутись → відкрити редагування ЗНОВУ і побачити нове
// значення (а не старе з SWR-кешу).
//
// GET списку відповідає із затримкою — це не «стабілізація», а сама умова бага:
// на мобільній мережі екран малює кеш РАНІШЕ, ніж приходить свіжий рядок, і
// префіл форми встигає взяти застаріле значення.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()
const NET_LAG = 350

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'free', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

async function setup(page: Page, state: { prop: Record<string, unknown> },
                    captured: { patches: Record<string, unknown>[] }) {
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return jsonRoute(r, accept.includes('object') ? DB : [DB])
  })

  await page.route('**/rest/v1/properties**', async (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      captured.patches.push(body)
      // Реальний бекенд оновлює updated_at — від нього залежить свіжість кешу.
      state.prop = { ...state.prop, ...body, updated_at: new Date().toISOString() }
      // `.select().single()` просить саме обʼєкт (Accept: …pgrst.object+json) —
      // масив у відповідь підмінив би рядок у списку масивом.
      const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? state.prop : [state.prop])
    }
    if (rq.method() !== 'GET') return r.fallback()
    const accept = rq.headers()['accept'] ?? ''
    await new Promise((res) => setTimeout(res, NET_LAG))
    return jsonRoute(r, accept.includes('object') ? state.prop : [state.prop])
  })

  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function openObjects(page: Page) {
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
}

/** Вхід у редагування з екрана самого обʼєкта (олівець у хедері). */
async function editFromDetail(page: Page) {
  await expect(page.locator('.hdr-t')).toContainText('Офіс 101', { timeout: 15_000 })
  await page.getByLabel('Редагувати').click()
  await expect(page.getByText('Редагування')).toBeVisible()
}

// Страхує ДРУГИЙ напрямок того ж бага: оновлення списку не має права затирати
// вже введене у форму. Саме на цьому спіймався перший підхід до фіксу свіжості
// (свіжий рядок переграв префіл і надіслав у PATCH старе значення).
test('ставки не відкатуються при ПОВТОРНОМУ редагуванні через екран обʼєкта', async ({ page }) => {
  const state = { prop: { ...PROP } }
  const captured = { patches: [] as Record<string, unknown>[] }
  await setup(page, state, captured)

  await page.goto('/')
  await openObjects(page)
  // Через екран обʼєкта — тут кеш списку лишався старим після PATCH
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await editFromDetail(page)

  await expect(page.getByPlaceholder('18')).toHaveValue('18', { timeout: 10_000 })
  await page.getByPlaceholder('18').fill('25')
  await page.getByPlaceholder('2.5').fill('9')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  await expect.poll(() => captured.patches.length, { timeout: 10_000 }).toBe(1)
  expect(Number(captured.patches[0].rent_rate)).toBe(25)
  expect(Number(captured.patches[0].utilities_rate)).toBe(9)

  // Відкриваємо редагування ЗНОВУ — форма мусить показати збережене
  await editFromDetail(page)
  await expect(page.getByPlaceholder('18')).toHaveValue('25', { timeout: 10_000 })
  await expect(page.getByPlaceholder('2.5')).toHaveValue('9')

  // …і повторне збереження не має відіслати назад старе значення
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-Б')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expect.poll(() => captured.patches.length, { timeout: 10_000 }).toBe(2)
  expect(Number(captured.patches[1].rent_rate), 'ставка не відкотилась').toBe(25)
})

test('картка у списку показує нову ставку одразу після збереження', async ({ page }) => {
  const state = { prop: { ...PROP } }
  const captured = { patches: [] as Record<string, unknown>[] }
  await setup(page, state, captured)

  await page.goto('/')
  await openObjects(page)
  // база розрахунку — розрахункова площа: 120 × 18 + 120 × 2.5 = 2 460
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toContainText('2 460')

  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()
  await expect(page.getByPlaceholder('18')).toHaveValue('18', { timeout: 10_000 })
  await page.getByPlaceholder('18').fill('25')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  // Збереження з КАРТКИ повертає рівно у список (а не через екран обʼєкта, який
  // ще й зʼїдав список зі стека — Back стрибав аж у список баз).
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  // 120 × 25 + 300 = 3 300 — кеш списку більше не малює стару суму
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toContainText('3 300', { timeout: 10_000 })
})

test('Back зі списку обʼєктів після редагування веде у список баз, не глибше', async ({ page }) => {
  const state = { prop: { ...PROP } }
  const captured = { patches: [] as Record<string, unknown>[] }
  await setup(page, state, captured)

  await page.goto('/')
  await openObjects(page)
  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-В')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByText('Бази', { exact: true }).first().click()
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 10_000 })
})
