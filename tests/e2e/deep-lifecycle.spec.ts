import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, skipCoachmarks, jsonRoute as json } from './helpers/harness'

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
  // `area_basis` ЯВНО: саме вона вирішує, на яку площу множиться $/м²-ставка.
  // Поки її тут не було, фікстура мовчки брала дефолт 'total' (120 м²), тобто
  // картка й експорт рахували 2 160, а календар — 1 800, і тест закріплював
  // РОЗБІЖНІСТЬ як норму. Тепер умова висловлена, і всі поверхні дають 1 800.
  status: 'occupied', area_useful: 100, area_total: 120, area_basis: 'useful',
  rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: null, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, utilities: null, description: null,
  address: null, sale_price: null, tenant_name: 'ТОВ «Ромашка»',
  lease_start_date: '2025-01-01', lease_end_date: '2027-01-01',
  sort_order: 100, share_token: 'bb00000000000000000000_1', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

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
  await skipCoachmarks(page)
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
    const accept = req.headers()['accept'] ?? ''
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      const row = { id: '60000000-0000-0000-0000-000000000001', created_at: NOW, ...body }
      schedules.splice(0, schedules.length, row)
      return json(route, row, 201)
    }
    // .maybeSingle() (PaymentScheduleScreen) asks for a single object via Accept.
    return json(route, accept.includes('object') ? (schedules[0] ?? null) : schedules)
  })
  await page.route('**/rest/v1/rent_payment_records**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      const row = { id: '70000000-0000-0000-0000-000000000001', created_at: NOW, paid_at: NOW, notes: null, ...body }
      records.splice(0, records.length, row)
      return json(route, row, 201)
    }
    if (req.method() === 'DELETE') {
      // ВІДДАЄМО ЗАЧЕПЛЕНИЙ РЯДОК, а не порожній масив. Порожній набір із
      // NULL у `error` — це рівно те, як PostgREST під RLS повідомляє про
      // ВІДМОВУ, тож мок, який так відповідає, моделює заблокований запис і
      // видає його за успіх. Та сама пастка вже ловилась на відкликанні
      // доступу й на пакетних діях.
      const removed = records.splice(0, records.length)
      return json(route, removed.map((r) => ({ id: (r as { id: string }).id })))
    }
    // .maybeSingle() (PaymentConfirmScreen) asks for a single object via Accept.
    return json(route, accept.includes('object') ? (records[0] ?? null) : records)
  })

  await openCalendar(page)

  // 1. Обʼєкт без розкладу → «Налаштувати»
  await expect(page.getByText('Немає розкладу')).toBeVisible()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()
  await page.getByLabel('День місяця').fill('1')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await expect(page.getByText('Розклад збережено')).toBeVisible()
  expect(schedules[0]).toMatchObject({ property_id: PROP.id, owner_id: USER.id, due_day: 1, is_active: true })
  await expect(page.getByText(/Календар платежів|Платежі — /)).toBeVisible({ timeout: 15_000 })

  // 2. З розкладом зʼявляється платіжний item поточного місяця з CTA «Отримано»
  await expect(page.getByText('Немає розкладу')).toHaveCount(0)
  const receiveBtn = page.getByRole('button', { name: /Отримано/ }).first()
  await expect(receiveBtn).toBeVisible()

  // 2b. Сума на самій картці due-платежу — НОРМАЛІЗОВАНА (100м² × 18 = 1 800),
  // не сира ставка rent_rate (18). Картка показувала «$18» замість «$1 800» —
  // rent_rate для per_m2/per_day є ставкою за одиницю, не сумою до сплати.
  await expect(page.getByText('1 800', { exact: false }).first()).toBeVisible()

  // 3. Підтвердження платежу: сума з оренди (100м² × 18 = 1800) префілиться
  await receiveBtn.click()
  await expect(page.getByText('Підтвердити платіж')).toBeVisible()
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expect(page.getByText('Платіж підтверджено ✓')).toBeVisible()
  await expect.poll(() => records.length).toBe(1)
  expect(records[0]).toMatchObject({ property_id: PROP.id, owner_id: USER.id, status: 'paid', amount: 1800 })
  await expect(page.getByText(/Календар платежів|Платежі — /)).toBeVisible({ timeout: 15_000 })

  // 3b. Валідація суми — перенесено з modal-sweep.spec.ts: порожнє поле лишається
  // легальним (береться очікувана сума), а введене мусить бути додатним числом.
  await page.getByText('✓ Сплачено').click()
  await expect(page.getByText('Редагувати платіж')).toBeVisible()
  const amountInput = page.getByLabel('Сума отриманого платежу')
  const saveBtn = page.getByRole('button', { name: 'Зберегти зміни' })
  await amountInput.fill('0')
  await expect(saveBtn).toBeDisabled()
  await amountInput.fill('.')
  await expect(saveBtn).toBeDisabled()
  await amountInput.fill('1500')
  await expect(saveBtn).toBeEnabled()
  await page.getByRole('button', { name: 'Назад' }).click()
  await expect(page.getByText(/Календар платежів|Платежі — /)).toBeVisible({ timeout: 15_000 })

  // 4. Рядок стає «Сплачено», стата «Отримано» показує суму
  await expect(page.getByText('✓ Сплачено')).toBeVisible()
  await expect(page.locator('.stat-n', { hasText: '1 800' })).toBeVisible()

  // 5. Скасування платежу (×) — ЗАВЖДИ через confirm-модалку
  await page.getByTitle('Скасувати платіж').click()
  await expect(page.getByText('Скасувати платіж?')).toBeVisible()
  await page.getByRole('button', { name: 'Скасувати платіж', exact: true }).click()
  await expect(page.getByText('Платіж скасовано')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByRole('button', { name: /Отримано/ }).first()).toBeVisible()
})

// ─── RLS 403 на мутації: чесний тост, без падіння ──────────────────────────────

test('403 on schedule save surfaces an error toast and keeps the app alive', async ({ page }) => {
  await fixtures(page)
  await page.route('**/rest/v1/rent_payments**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    if (route.request().method() === 'POST') {
      return json(route, { code: '42501', message: 'permission denied for table rent_payments' }, 403)
    }
    return json(route, accept.includes('object') ? null : [])
  })

  await openCalendar(page)
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()
  await page.getByLabel('День місяця').fill('5')
  await page.getByRole('button', { name: 'Зберегти' }).click()

  await expect(page.getByText('Помилка збереження')).toBeVisible()
  // Застосунок живий: екран не впав, назад повертає на календар без втрат
  await page.getByRole('button', { name: 'Назад' }).click()
  await expect(page.getByText('Немає розкладу')).toBeVisible()
})

// ─── Офлайн-гард ────────────────────────────────────────────────────────────────

test('offline: mutations are blocked with the offline toast, restore announces itself', async ({ page }) => {
  await fixtures(page)
  await page.route('**/rest/v1/rent_payments**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? null : [])
  })
  await openCalendar(page)

  // Емуляція розриву: window offline event → setOnline(false)
  await page.evaluate(() => window.dispatchEvent(new Event('offline')))
  // Глобальний банер деградації показується одразу
  await expect(page.getByText('Немає інтернету — дані можуть бути застарілими')).toBeVisible()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()
  await page.getByLabel('День місяця').fill('5')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  // Гард мутації: тост (окремо від банера)
  await expect(page.getByText('Збереження недоступне офлайн')).toBeVisible()

  // Відновлення: тост і мутації знову проходять
  await page.evaluate(() => window.dispatchEvent(new Event('online')))
  await expect(page.getByText("Зʼєднання відновлено")).toBeVisible()
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
  // Формат шляху (уніфікований конвеєр lib/photoUpload): {propertyId}/{timestamp}_{rand}.{ext}
  // — без user-controlled сегментів; перший сегмент = propertyId (storage RLS).
  expect(storagePosts[0]).toMatch(new RegExp(`/photos/${PROP.id}/\\d+_[a-z0-9]+\\.png$`))
  expect(photoRows[0]).toMatchObject({ property_id: PROP.id })
  expect((photoRows[0] as { storage_path: string }).storage_path).toMatch(new RegExp(`^${PROP.id}/`))
})

/**
 * `sort_order` НОВОГО фото продовжує наявні, а не стартує з нуля — інакше друга
 * партія дає знімок із `sort_order = 0`, тобто нічию з чинною обкладинкою.
 *
 * ЦЕЙ ГАРД БУВ НЕМОЖЛИВИЙ ДО `Content-Range` В ХАРНЕСІ. `PhotoUploadScreen`
 * бере кількість наявних через `count: 'exact', head: true`, тобто із
 * ЗАГОЛОВКА, а не з тіла; харнес його не віддавав, `count` приходив `null`, і
 * фолбек ставив рівно 0. Тобто фікс колізії обкладинки виглядав зробленим, а
 * перевірити його не міг ЖОДЕН із 317 тестів.
 *
 * Заголовок додає сам `jsonRoute` (у цьому файлі імпортований як `json`) —
 * рівно там же, де вже живе проєкція через `select=`.
 */
test('photo upload: sort_order продовжує наявні фото, а не стартує з нуля', async ({ page }) => {
  await fixtures(page)

  const EXISTING = [
    { id: '80000000-0000-0000-0000-0000000000a1', property_id: PROP.id, storage_path: `${PROP.id}/a.jpg`, sort_order: 0, created_at: NOW },
    { id: '80000000-0000-0000-0000-0000000000a2', property_id: PROP.id, storage_path: `${PROP.id}/b.jpg`, sort_order: 1, created_at: NOW },
  ]
  const inserted: Record<string, unknown>[] = []
  await page.route('**/storage/v1/object/photos/**', (route) => json(route, { Key: 'photos/x' }))
  await page.route('**/rest/v1/property_photos**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      inserted.push(body)
          return json(route, [{ id: '80000000-0000-0000-0000-0000000000b1', ...body }], 201)
    }
    return json(route, EXISTING)
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card .obj-t', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Фотографії')).toBeVisible()

  const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64',
  )
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles({ name: 'photo.png', mimeType: 'image/png', buffer: png })
  await expect(page.getByText('Завантажено!')).toBeVisible({ timeout: 15_000 })

  expect(inserted.length).toBe(1)
  expect(inserted[0], 'нове фото стало другою обкладинкою').toMatchObject({ sort_order: 2 })
})
