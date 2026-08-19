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

/**
 * ГРОШІ У ФАЙЛІ мусять збігатися з грошима на екрані.
 *
 * `basisArea()` при `area_basis === undefined` мовчки бере РОЗРАХУНКОВУ площу.
 * Вибірка експорту цю колонку не тягнула взагалі, тож обʼєкт, якому власник
 * задав базою корисну площу, рахувався в PDF/XLSX по іншій площі, ніж у
 * застосунку: на 100/120 м² і $18/м² це $1 800 на екрані проти $2 160 у файлі.
 * Мовчки, без помилки, у документі, який власник надсилає клієнту.
 */
test('експорт тягне area_basis — інакше суми у файлі розходяться з екраном', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire)
  await openExport(page)

  const before = wire.selects.length
  await page.getByRole('button', { name: /Завантажити PDF/ }).click()
  await expect.poll(() => wire.selects.length, { timeout: 15_000 }).toBeGreaterThan(before)

  expect(wire.selects[wire.selects.length - 1], 'без area_basis сума рахується по чужій площі')
    .toContain('area_basis')
})

/**
 * ПОРЯДОК у файлі — той самий, що в застосунку.
 *
 * Було `.order('name')`, тобто лексикографічно: «Офіс 10» ставало перед
 * «Офіс 2», а ручний «Змінити порядок» не впливав на документ ВЗАГАЛІ.
 * Той самий клас міграція 040 вже виправила для публічної /v.
 */
test('експорт сортує за sort_order, як застосунок, а не за назвою', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await setup(page, wire)
  await openExport(page)

  const before = wire.selects.length
  await page.getByRole('button', { name: /Завантажити PDF/ }).click()
  await expect.poll(() => wire.selects.length, { timeout: 15_000 }).toBeGreaterThan(before)

  const exportSelect = wire.selects[wire.selects.length - 1]
  expect(exportSelect, 'порядок документа мусить іти за ручним порядком власника')
    .toContain('order=sort_order')
  expect(exportSelect, 'лексикографічний порядок ставив «Офіс 10» перед «Офіс 2»')
    .not.toContain('order=name')
})

/**
 * ЯК файл віддається користувачу — і чому це не косметика.
 *
 * Webview Telegram ІГНОРУЄ атрибут `download`: замість збереження він переходить
 * на blob-URL. `XLSX.writeFile()` усередині клацає саме такий `<a download>`,
 * тож замість файлу власник бачив вміст ZIP-контейнера .xlsx сирим текстом
 * прямо в застосунку (`xl/worksheets/sheet1.xml`, `xl/styles.xml`…) — скріншот
 * з пристрою. PDF цього не мав лише тому, що вже йшов через Web Share API.
 *
 * Гард стоїть на ОБОХ форматах: підміняємо `navigator.share`/`canShare` і
 * перевіряємо, що файл пішов саме туди — з правильним іменем і MIME.
 */
async function stubShare(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __shared: { name: string; type: string }[] }
    w.__shared = []
    Object.defineProperty(navigator, 'canShare', { value: () => true, configurable: true })
    Object.defineProperty(navigator, 'share', {
      configurable: true,
      value: async (data: { files?: File[] }) => {
        for (const f of data.files ?? []) w.__shared.push({ name: f.name, type: f.type })
      },
    })
  })
}
const sharedFiles = (page: Page) =>
  page.evaluate(() => (window as unknown as { __shared: { name: string; type: string }[] }).__shared)

test('Excel віддається через share, а не мертвим <a download>', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await stubShare(page)
  await setup(page, wire)
  await openExport(page)

  await page.getByText('Excel таблиця').click()
  await page.getByRole('button', { name: /Завантажити Excel/ }).click()
  await expect(page.getByText(/Excel збережено/)).toBeVisible({ timeout: 20_000 })

  const files = await sharedFiles(page)
  expect(files.length, 'файл не пішов у share — у webview Telegram це означає сирий ZIP на екрані').toBe(1)
  expect(files[0].name).toMatch(/\.xlsx$/)
  expect(files[0].type, 'MIME мусить бути xlsx, інакше система не знає, чим відкривати')
    .toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
})

test('PDF віддається тим самим шляхом', async ({ page }) => {
  const wire: Wire = { selects: [] }
  await stubShare(page)
  await setup(page, wire)
  await openExport(page)

  await page.getByRole('button', { name: /Завантажити PDF/ }).click()
  await expect(page.getByText(/PDF збережено/)).toBeVisible({ timeout: 20_000 })

  const files = await sharedFiles(page)
  expect(files.length).toBe(1)
  expect(files[0].name).toMatch(/\.pdf$/)
  expect(files[0].type).toBe('application/pdf')
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
