import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Глибокі сценарії: платіжний цикл, аварійні режими, офлайн, фото ───────────
// Драйвимо ланцюги, які поодинокі тести не проходять цілком: розклад → платіж →
// скасування; 403 від RLS; офлайн-гард; аплоуд фото через PhotoUploadScreen.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

const PROP = {
  id: '20000000-0000-0000-0000-000000000001',
  db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'occupied', area_useful: 100, area_total: 120, rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: null, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, utilities: null, description: null,
  address: null, sale_price: null, tenant_name: 'ТОВ «Ромашка»',
  lease_start_date: '2025-01-01', lease_end_date: '2027-01-01',
  sort_order: 100, share_token: 'bb00000000000000000000_1', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() !== 'GET') return route.fallback()
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openCalendar(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.getByText(/Календар платежів|Платежі — /)).toBeVisible({ timeout: 15_000 })
}

// ─── Повний платіжний цикл ──────────────────────────────────────────────────────

test('payment lifecycle: schedule → due item → mark paid → stats → unpay', async ({ page }) => {
  await fixtures(page)

  // Розклад: 5-те число (у минулому для поточного місяця, якщо сьогодні >5 —
  // item або «Прострочено», або майбутній; для стабільності беремо день 1 —
  // завжди в минулому або сьогодні → завжди рендериться в поточному місяці)
  const schedules: Record<string, unknown>[] = []
  const records: Record<string, unknown>[] = []
  await page.route('**/rest/v1/rent_payments**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      const row = { id: '60000000-0000-0000-0000-000000000001', created_at: NOW, ...body }
      schedules.splice(0, schedules.length, row)
      return json(route, row, 201)
    }
    return json(route, schedules)
  })
  await page.route('**/rest/v1/rent_payment_records**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      const row = { id: '70000000-0000-0000-0000-000000000001', created_at: NOW, paid_at: NOW, notes: null, ...body }
      records.splice(0, records.length, row)
      return json(route, row, 201)
    }
    if (req.method() === 'DELETE') {
      records.length = 0
      return json(route, [])
    }
    return json(route, records)
  })

  await openCalendar(page)

  // 1. Об'єкт без розкладу → «Налаштувати»
  await expect(page.getByText('Немає розкладу')).toBeVisible()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  await dayInput.fill('1')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  await expect(page.getByText('Розклад збережено')).toBeVisible()
  expect(schedules[0]).toMatchObject({ property_id: PROP.id, owner_id: USER.id, due_day: 1, is_active: true })

  // 2. З розкладом з'являється платіжний item поточного місяця з CTA «Отримано»
  await expect(page.getByText('Немає розкладу')).toHaveCount(0)
  const receiveBtn = page.getByRole('button', { name: /Отримано/ }).first()
  await expect(receiveBtn).toBeVisible()

  // 3. Підтвердження платежу: сума з оренди (100м² × 18 = 1800) префілиться
  await receiveBtn.click()
  await expect(page.getByText('Підтвердити отримання')).toBeVisible()
  await page.getByRole('button', { name: 'Підтвердити оплату' }).click()
  await expect(page.getByText('Платіж підтверджено ✓')).toBeVisible()
  await expect.poll(() => records.length).toBe(1)
  expect(records[0]).toMatchObject({ property_id: PROP.id, owner_id: USER.id, status: 'paid', amount: 1800 })

  // 4. Рядок стає «Сплачено», стата «Отримано» показує суму
  await expect(page.getByText('✓ Сплачено')).toBeVisible()
  await expect(page.locator('.stat-n', { hasText: '1 800' })).toBeVisible()

  // 5. Скасування платежу (×) повертає item у неоплачені
  await page.getByTitle('Скасувати платіж').click()
  // Модалка підтвердження скасування — якщо є; інакше одразу
  const confirmUnpay = page.getByRole('button', { name: /Скасувати платіж|Так/ })
  if (await confirmUnpay.count() > 0) await confirmUnpay.first().click()
  await expect(page.getByText('Платіж скасовано')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByRole('button', { name: /Отримано/ }).first()).toBeVisible()
})

// ─── RLS 403 на мутації: чесний тост, без падіння ──────────────────────────────

test('403 on schedule save surfaces an error toast and keeps the app alive', async ({ page }) => {
  await fixtures(page)
  await page.route('**/rest/v1/rent_payments**', (route) => {
    if (route.request().method() === 'POST') {
      return json(route, { code: '42501', message: 'permission denied for table rent_payments' }, 403)
    }
    return json(route, [])
  })

  await openCalendar(page)
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await page.locator('.modal input[inputmode="numeric"]').first().fill('5')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()

  await expect(page.getByText('Помилка збереження')).toBeVisible()
  // Застосунок живий: модалку можна закрити, екран далі працює
  await page.getByRole('button', { name: 'Скасувати' }).click()
  await expect(page.getByText('Немає розкладу')).toBeVisible()
})

// ─── Офлайн-гард ────────────────────────────────────────────────────────────────

test('offline: mutations are blocked with the offline toast, restore announces itself', async ({ page }) => {
  await fixtures(page)
  await page.route('**/rest/v1/rent_payments**', (route) => json(route, []))
  await openCalendar(page)

  // Емуляція розриву: window offline event → setOnline(false)
  await page.evaluate(() => window.dispatchEvent(new Event('offline')))
  // Глобальний банер деградації показується одразу
  await expect(page.getByText('Немає інтернету — дані можуть бути застарілими')).toBeVisible()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await page.locator('.modal input[inputmode="numeric"]').first().fill('5')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  // Гард мутації: тост (окремо від банера)
  await expect(page.getByText('Збереження недоступне офлайн')).toBeVisible()

  // Відновлення: тост і мутації знову проходять
  await page.evaluate(() => window.dispatchEvent(new Event('online')))
  await expect(page.getByText("З'єднання відновлено")).toBeVisible()
})

// ─── Фото: аплоуд через PhotoUploadScreen ──────────────────────────────────────

test('photo upload: file → storage POST + property_photos INSERT → success toast', async ({ page }) => {
  await fixtures(page)

  const storagePosts: string[] = []
  const photoRows: Record<string, unknown>[] = []
  await page.route('**/storage/v1/object/photos/**', (route) => {
    if (route.request().method() === 'POST') {
      storagePosts.push(new URL(route.request().url()).pathname)
    }
    return json(route, { Key: 'photos/x' })
  })
  await page.route('**/rest/v1/property_photos**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      photoRows.push(body)
      return json(route, [{ id: '80000000-0000-0000-0000-000000000001', sort_order: 0, ...body }], 201)
    }
    return json(route, photoRows)
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card .obj-t', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Фотографії')).toBeVisible()

  // 1×1 PNG — компресор fail-open поверне оригінал, якщо canvas не впорається
  const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64',
  )
  // Два file-інпути на екрані (фото + документи) — беремо саме фото-інпут
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles({ name: 'photo.png', mimeType: 'image/png', buffer: png })

  // PhotoUploadScreen жене чергу і рапортує фінальний стан
  await expect(page.getByText('Завантажено!')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Збережено', { exact: true })).toBeVisible()

  expect(storagePosts.length).toBe(1)
  // Шлях сторінки: {propertyId}/{timestamp}_{rand}.{ext} — без user-controlled сегментів
  // Формат шляху: {propertyId}/{timestamp}_{queueIdx}_{rand}.{ext}
  expect(storagePosts[0]).toMatch(new RegExp(`/photos/${PROP.id}/\\d+_\\d+_[a-z0-9]+\\.png$`))
  expect(photoRows[0]).toMatchObject({ property_id: PROP.id })
  expect((photoRows[0] as { storage_path: string }).storage_path).toMatch(new RegExp(`^${PROP.id}/`))
})
