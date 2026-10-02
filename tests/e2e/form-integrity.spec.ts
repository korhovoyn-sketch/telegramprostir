import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'
import { realtorFixtures } from './helpers/screens'

/**
 * ЦІЛІСНІСТЬ ФОРМ: що бачить і що може зробити користувач, коли поле, запит
 * або сервер поводяться не так, як на щасливому шляху.
 *
 * Кожен кейс тут — знайдений дефект, червоний до свого фікса.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = '2026-09-01T09:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', landlord_name: null, created_at: NOW, updated_at: NOW, properties: [],
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'occupied', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: 'Світлий офіс', address: 'вул. Хрещатик, 1',
  sale_price: null, tenant_name: 'ТОВ «Ромашка»', landlord_name: null,
  lease_start_date: '2026-01-01', lease_end_date: '2027-01-01',
  sort_order: 100, created_at: NOW, updated_at: NOW, photos: [],
}

type Ctl = { failPropsList: boolean; patches: Record<string, unknown>[] }

async function setup(page: Page, ctl: Ctl) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}')
      ctl.patches.push(body)
      return jsonRoute(r, { ...PROP, ...body })
    }
    const url = decodeURIComponent(rq.url())
    if (ctl.failPropsList && url.includes('db_id=eq.')) {
      return r.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ message: 'upstream unavailable' }) })
    }
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? PROP : [PROP])
  })
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'db_members', 'tenancies', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * ФОРМА РЕДАГУВАННЯ БЕЗ ДАНИХ НЕ СМІЄ БУТИ ПОРОЖНЬОЮ ФОРМОЮ.
 *
 * Якщо список обʼєктів не завантажився (збій мережі, кеш протух або його
 * немає — вхід із deep-лінка), форма малювала ПОРОЖНІ поля з активною
 * кнопкою «Зберегти зміни». Користувач, що вводить хоча б назву й тисне
 * «Зберегти», слав PATCH, де кожне інше поле — `null`, а статус — `free`:
 * площі, ставки, орендар, договір і опис стирались одним дотиком, а тригер
 * архіву ще й закривав оренду.
 */
test('редагування: обʼєкт не завантажився — не порожня форма, а повтор', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-t').first().click()
  await expect(page.getByRole('button', { name: 'Редагувати обʼєкт' })).toBeVisible({ timeout: 10_000 })

  // Відтепер список падає, а кешу, з якого форма могла б домалюватись, немає.
  ctl.failPropsList = true
  await page.evaluate(() => {
    for (const k of Object.keys(localStorage)) if (k.startsWith('snap_v1:')) localStorage.removeItem(k)
  })
  await page.getByRole('button', { name: 'Редагувати обʼєкт' }).click()

  await expect(page.getByRole('button', { name: /Повторити|Спробувати/ })).toBeVisible({ timeout: 10_000 })
  // Порожньої форми, яку можна «зберегти», на екрані бути не повинно.
  await expect(page.getByRole('button', { name: 'Зберегти зміни' })).toHaveCount(0)
  await expect(page.getByLabel('Назва обʼєкта')).toHaveCount(0)
  expect(ctl.patches, 'PATCH на порожніх полях — стирання обʼєкта').toEqual([])

  // Повтор при живій мережі приводить до заповненої форми.
  ctl.failPropsList = false
  await page.getByRole('button', { name: /Повторити|Спробувати/ }).click()
  await expect(page.getByLabel('Назва обʼєкта')).toHaveValue('Офіс 101', { timeout: 10_000 })
  await expect(page.getByLabel('Орендар')).toHaveValue('ТОВ «Ромашка»')
})

/**
 * ПРОФІЛЬ: та сама перевірка контактів, що й на онбордингу. Доти «abc»
 * зберігалось як email, а телефон не перевірявся ніде — хоча за згодою
 * власника саме він стає кнопкою «Подзвонити» на публічній /v.
 */
test('профіль: невалідний email і телефон не зберігаються, очищення пише null', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  const userPatches: Record<string, unknown>[] = []
  await page.route('**/rest/v1/users**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}')
      userPatches.push(body)
      return jsonRoute(r, { ...USER, email: 'old@mail.com', ...body })
    }
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    const row = { ...USER, email: 'old@mail.com', phone: null, public_phone: false }
    return jsonRoute(r, wantsObject ? row : [row])
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  const email = page.getByLabel('Email')
  await expect(email).toBeVisible({ timeout: 10_000 })

  await email.fill('abc')
  await email.blur()
  await expect(page.getByText('Невірний email')).toBeVisible()
  await expect(email, 'невалідне значення не лишається в полі як «збережене»').toHaveValue(/old@mail\.com|^$/)

  const phone = page.getByLabel('Телефон')
  await phone.fill('дзвоніть увечері')
  await phone.blur()
  await expect(page.getByText('Невірний номер телефону')).toBeVisible()
  expect(userPatches, 'жодне невалідне значення не мало дійти до сервера').toEqual([])

  await phone.fill('+380 67 000 0000')
  await phone.blur()
  await expect.poll(() => userPatches.length, { timeout: 10_000 }).toBe(1)
  expect(userPatches[0].phone).toBe('+380 67 000 0000')

  // Межа поля — з колонки (VARCHAR(32)), а не з повідомлення сервера.
  expect(await phone.getAttribute('maxlength')).toBe('32')
  expect(await email.getAttribute('maxlength')).toBe('254')
})

/**
 * ПОРЯДОК ПАПОК: збій збереження мусить бути ВИДНО. supabase-js не кидає, а
 * повертає `{ error }`, тож голий try/catch навколо запису був мертвим —
 * офлайн чи відмова RLS проходили мовчки, і після перезаходу папки стрибали
 * назад «самі».
 */
test('папки: невдале збереження порядку — відкат і пояснення', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  const FOLDERS = [
    { id: 'f0000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id, name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW },
    { id: 'f0000000-0000-0000-0000-000000000002', db_id: DB_ID, owner_id: USER.id, name: 'Другий поверх', sort_order: 200, created_at: NOW, updated_at: NOW },
  ]
  let patches = 0
  await page.route('**/rest/v1/property_folders**', (r) => {
    if (r.request().method() === 'PATCH') {
      patches++
      return r.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ message: 'upstream unavailable' }) })
    }
    return jsonRoute(r, FOLDERS)
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  const names = page.locator('.fold-mng-name')
  await expect(names).toHaveText(['Перший поверх', 'Другий поверх'], { timeout: 10_000 })

  await page.getByRole('button', { name: 'Вниз' }).first().click()
  await expect(page.getByText('Не вдалося зберегти порядок')).toBeVisible({ timeout: 10_000 })
  await expect(names, 'порядок мусить повернутись — сервер його не прийняв').toHaveText(['Перший поверх', 'Другий поверх'])
  expect(patches, 'антивакуум: запис справді пішов').toBeGreaterThan(0)
})

/**
 * ІМПОРТ: одна задовга клітинка не сміє валити ВЕСЬ пакет. Доти поверх із 40
 * символів (колонка — VARCHAR(32)) давав 400 на всі рядки разом, і тост
 * «Спробуйте ще раз» не казав, який рядок винен.
 */
test('імпорт: рядок із задовгим значенням відсіюється поіменно, решта заходить', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  const inserted: unknown[] = []
  await page.route('**/rest/v1/properties**', (r) => {
    if (r.request().method() !== 'POST') return r.fallback()
    const body = JSON.parse(r.request().postData() ?? '[]')
    inserted.push(...body)
    return jsonRoute(r, body.map((b: Record<string, unknown>, i: number) => ({ ...PROP, ...b, id: `2${i}000000-0000-0000-0000-000000000077` })))
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel('Меню бази').click()
  await page.getByText(/Імпорт/).click()
  const longFloor = 'х'.repeat(40)
  await page.locator('input[type="file"][accept*="csv"]').setInputFiles({
    name: 'objects.csv', mimeType: 'text/csv',
    buffer: Buffer.from(`Назва;Поверх\nОфіс 201;2\nОфіс 202;${longFloor}\nОфіс 203;3\n`, 'utf8'),
  })
  await expect(page.getByText(/Пропущено \(задовге значення\):.*Офіс 202/)).toBeVisible()
  await page.getByRole('button', { name: 'Імпортувати' }).click()
  await expect(page.getByText(/Додано 2/)).toBeVisible({ timeout: 10_000 })
  expect((inserted as { name: string }[]).map((x) => x.name)).toEqual(['Офіс 201', 'Офіс 203'])
})

/**
 * «ЗДАТИ В ОРЕНДУ»: відмова сервера мусить казати ЧОМУ. Екран клав власний
 * тост поверх тоста хука, а стор тримає ОДИН — тож причина зникала.
 */
test('здати в оренду: відмова показує причину, а не лише «не вдалося»', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  const FREE = { ...PROP, status: 'free', tenant_name: null, lease_start_date: null, lease_end_date: null }
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      return r.fulfill({ status: 400, contentType: 'application/json',
        body: JSON.stringify({ code: '22001', message: 'value too long for type character varying(200)' }) })
    }
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? FREE : [FREE])
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-t').first().click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  const tenant = page.getByLabel('Орендар')
  await tenant.fill('ТОВ «Ромашка»')
  expect(await tenant.getAttribute('maxlength'), 'межа поля — з колонки tenant_name').toBe('200')
  await page.getByRole('button', { name: 'Здати в оренду' }).last().click()

  const toast = page.locator('.toast')
  await expect(toast).toContainText('Не вдалося здати в оренду', { timeout: 10_000 })
  await expect(toast, 'причина відмови мусить лишитись у тості').toContainText('задовге')
})

/**
 * ЧЕРНЕТКА: орендодавець — таке саме поле форми, як решта, але в чернетку не
 * писався й з неї не відновлювався. Після збою вебвʼю все інше поверталось, а
 * він — ні, і поле виглядало «як у базі».
 */
test('чернетка нового обʼєкта зберігає й відновлює орендодавця', async ({ page }) => {
  const ctl: Ctl = { failPropsList: false, patches: [] }
  await setup(page, ctl)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByRole('button', { name: /Додати обʼєкт|Новий обʼєкт/ }).first().click()
  await page.getByPlaceholder('Офіс 101').fill('Офіс 909')
  await page.getByLabel('Орендодавець').fill('ТОВ «Власник»')
  // Чернетка пишеться з дебаунсом 600мс.
  await expect.poll(() => page.evaluate(() =>
    Object.keys(localStorage).filter((k) => k.startsWith('draft_v1:')).map((k) => localStorage.getItem(k)).join('')),
  { timeout: 5_000 }).toContain('ТОВ «Власник»')

  await page.reload()
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByRole('button', { name: /Додати обʼєкт|Новий обʼєкт/ }).first().click()
  await expect(page.getByText('Чернетку відновлено')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByLabel('Орендодавець')).toHaveValue('ТОВ «Власник»')
})

/**
 * ПІДБІРКА: збій завантаження ≠ «підбірка порожня». Доти екран упевнено казав
 * «Немає обʼєктів. Додай перший» про підбірку, у якій обʼєкти є.
 */
test('підбірка: збій завантаження обʼєктів дає повтор, а не «Немає обʼєктів»', async ({ page }) => {
  await realtorFixtures(page)
  let fail = true
  await page.route('**/rest/v1/collections**', (r) => jsonRoute(r, [{
    id: '40000000-0000-0000-0000-000000000001', realtor_id: 'x', name: 'Для клієнта А', is_draft: false,
    share_token: 'ff00112233445566778899aa', share_expires_at: null, created_at: NOW, updated_at: NOW,
    collection_properties: [{ count: 2 }],
  }]))
  await page.route('**/rest/v1/collection_properties**', (r) => fail
    ? r.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ message: 'upstream unavailable' }) })
    : jsonRoute(r, []))
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await page.getByText('Для клієнта А').first().click()

  const retry = page.getByRole('button', { name: 'Спробувати ще раз' })
  await expect(retry).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Немає обʼєктів')).toHaveCount(0)
  // Антивакуум: повтор при живій мережі веде до справжнього стану.
  fail = false
  await retry.click()
  await expect(page.getByText('Немає обʼєктів')).toBeVisible({ timeout: 10_000 })
})
