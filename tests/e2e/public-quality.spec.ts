import { test, expect, type Page, type Route } from '@playwright/test'

/**
 * ЯКІСТЬ ПУБЛІЧНОЇ /v — прогалина, що була СТРУКТУРНОЮ.
 *
 * `helpers/screens.ts` водить `contrast`, `design-system-runtime`, `devices` і
 * `screen-text-fit` усіма 25 екранами ЗАСТОСУНКУ — але `/v` живе поза цим
 * обходом (окремий Next-маршрут, не екран `appStore`), тож її не міряв ЖОДЕН
 * гард якості. Функціональні тести перевіряли, що вона рендериться; скрін-
 * бейслайни — що не змінилась. Ані доступних назв, ані зони дотику, ані
 * поведінки на вузькому екрані не перевіряв ніхто.
 *
 * Ціна прогалини вища, ніж деінде: `/v` — ЄДИНА поверхня, яку бачать СТОРОННІ
 * люди (потенційні орендарі й покупці), причому в звичайному браузері, а не в
 * Telegram. Знайдені нею дефекти першого прогону: стрілки галереї й мініатюри
 * без доступної назви, кнопка Telegram у шапці 36×36, стрілки 32×32.
 */

const json = (r: Route, b: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(b) })

const NOW_PLUS = new Date(Date.now() + 30 * 86400000).toISOString()

const PROP = {
  property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
  property_status: 'occupied', property_floor: '3', property_area_useful: 100,
  property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
  property_utilities_rate: 2.5, property_description: 'Світлий офіс у центрі',
  property_address: 'вул. Хрещатик, 1', property_has_parking: true,
  property_parking_spaces: 2, property_sale_price: null, share_expires_at: NOW_PLUS,
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін',
  db_type: 'business_center', db_color: 'pink', owner_first_name: 'Микола',
  owner_last_name: 'К.', owner_tg_username: 'mykola', owner_phone: '+380670000000',
  owner_currency: 'USD',
  // Три фото — інакше галерея не малює ні стрілок, ні смужки мініатюр, тобто
  // рівно ті вузли, на яких і знайшлись дефекти, лишились би поза заміром.
  photos: ['p/1.jpg', 'p/2.jpg', 'p/3.jpg'],
}

const DB_BASE = {
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін',
  db_type: 'business_center', db_color: 'pink', share_expires_at: NOW_PLUS,
  owner_first_name: 'Микола', owner_last_name: 'К.', owner_tg_username: 'mykola',
  owner_phone: '+380670000000', owner_currency: 'UAH', first_photo: null,
}
const DB_ROWS = [
  { ...DB_BASE, property_id: 'a1', property_name: 'Офіс 101', property_status: 'free',
    property_floor: '3', property_area_useful: 100, property_area_total: 120,
    property_rent_type: 'per_m2', property_rent_rate: 18, property_sale_price: null,
    property_description: 'Світлий офіс у самому центрі міста, панорамні вікна.' },
  { ...DB_BASE, property_id: 'a2', property_name: 'Торгове приміщення на першій лінії',
    property_status: 'for_sale', property_floor: '1', property_area_useful: 210,
    property_area_total: 240, property_rent_type: 'per_m2', property_rent_rate: null,
    property_sale_price: 450000, property_description: null },
]

const COL_ROWS = [{
  collection_id: '40000000-0000-0000-0000-000000000001',
  collection_name: 'Підбірка для клієнта', share_expires_at: NOW_PLUS,
  realtor_first_name: 'Олена', realtor_last_name: 'Р.', realtor_tg_username: 'olena',
  realtor_phone: null, property_id: 'b1', property_name: 'Квартира 12',
  property_status: 'free', property_floor: '5', property_area_useful: 60,
  property_area_total: 65, property_rent_type: 'per_m2', property_rent_rate: 15,
  property_sale_price: null, owner_currency: 'EUR', property_description: null,
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'ЖК Липки',
  db_type: 'residential', db_color: 'blue', first_photo: null,
}]

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64')

async function setup(page: Page) {
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram = { WebApp: { openTelegramLink() {}, ready() {}, expand() {} } }
  })
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) => json(r, [PROP]))
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, DB_ROWS))
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (r) => json(r, COL_ROWS))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, true))
  await page.route('**/storage/v1/object/public/**', (r) =>
    r.fulfill({ status: 200, contentType: 'image/png', body: PNG }))
}

/** Інтерактивні вузли без доступної назви. */
async function unnamed(page: Page) {
  return page.evaluate(() => {
    const bad: string[] = []
    document.querySelectorAll('button, a[href], input, select').forEach((el) => {
      const e = el as HTMLElement
      if (e.offsetParent === null) return
      // Гліфи-стрілки НЕ вважаються назвою: читалка озвучує «‹» як назву
      // пунктуаційного знака, тобто ніяк. Саме так і було знайдено дефект.
      const name = (e.getAttribute('aria-label') ?? '').trim()
        || (e.textContent ?? '').replace(/[‹›×→←\s]/g, '').trim()
        || (e.querySelector('img')?.getAttribute('alt') ?? '').trim()
        || (e.getAttribute('title') ?? '').trim()
      if (!name) bad.push(`<${e.tagName.toLowerCase()} class="${e.className}">`)
    })
    return [...new Set(bad)]
  })
}

/** Кнопки й посилання нижче 44px Apple HIG. */
async function smallTargets(page: Page) {
  return page.evaluate(() => {
    const bad: string[] = []
    document.querySelectorAll('button, a[href]').forEach((el) => {
      const e = el as HTMLElement
      if (e.offsetParent === null) return
      const r = e.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return
      if (r.height < 44 || r.width < 44) {
        bad.push(`${Math.round(r.width)}×${Math.round(r.height)} <${e.tagName.toLowerCase()} class="${e.className}">`)
      }
    })
    return [...new Set(bad)]
  })
}

/** Контейнери, ширші за себе, — тобто сторінка їде вбік. */
async function overflowing(page: Page) {
  return page.evaluate(() => {
    const bad: string[] = []
    document.querySelectorAll('div, section, header, main, article').forEach((el) => {
      const e = el as HTMLElement
      // Скролер клiпає власний вміст — це «ще не доскролено», а не дефект.
      if (getComputedStyle(e).overflowX !== 'visible') return
      if (e.scrollWidth > e.clientWidth + 1) {
        bad.push(`${e.scrollWidth}>${e.clientWidth} <${e.tagName.toLowerCase()} class="${e.className}">`)
      }
    })
    return [...new Set(bad)]
  })
}

const VIEWS = [
  ['обʼєкт',   '/v/?prop=aabbccddeeff001122334455', 'Офіс 101'],
  ['база',     '/v/?db=aabbccddeeff001122334455',   'БЦ Рубін'],
  ['підбірка', '/v/?col=aabbccddeeff001122334455',  'Підбірка для клієнта'],
] as const

for (const [label, url, marker] of VIEWS) {
  test(`публічна /v (${label}): назви, зона дотику, ширина`, async ({ page }) => {
    await setup(page)
    await page.goto(url)
    await expect(page.getByText(marker).first()).toBeVisible({ timeout: 20_000 })
    // Каскад входу (`v-rise`) зсуває елементи — міряти під час анімації означає
    // отримати геометрію, якої на екрані ніколи не буває.
    await page.waitForTimeout(1200)

    // Антивакуумність: якщо вибірка порожня, «порушень немає» не означає нічого.
    const count = await page.locator('button, a[href]').count()
    expect(count, 'вибірка порожня — селектор застарів').toBeGreaterThan(1)

    expect(await unnamed(page), 'інтерактивний вузол без доступної назви').toEqual([])
    expect(await smallTargets(page), 'зона дотику менша за 44px').toEqual([])
    expect(await overflowing(page), 'сторінка ширша за екран').toEqual([])
  })
}

/**
 * Вузький Android (360) — не «майже 375», а окремий випадок: саме там
 * розсипаються рядки з трьома контролами. Публічну сторінку на ньому не міряв
 * ніхто, бо `devices.spec.ts` ходить лише екранами застосунку.
 */
test('публічна /v тримається на 360px', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 })
  await setup(page)
  for (const [, url, marker] of VIEWS) {
    await page.goto(url)
    await expect(page.getByText(marker).first()).toBeVisible({ timeout: 20_000 })
    await page.waitForTimeout(900)
    expect(await overflowing(page), `${url}: сторінка ширша за 360px`).toEqual([])
    expect(await smallTargets(page), `${url}: зона дотику < 44px на 360`).toEqual([])
  }
})
