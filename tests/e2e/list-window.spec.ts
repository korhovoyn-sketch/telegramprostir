import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * ВІКНО РЕНДЕРА списку обʼєктів.
 *
 * Заміряно: 200 обʼєктів давали 8200 вузлів DOM і 200 шарів `backdrop-filter`.
 * Ліміт рендера зрізає це до ~3400/80 — але саме тому потрібні гарди: усе, що
 * працює НАД списком, мусить і далі бачити список ЦІЛКОМ. Обмежений рендер, з
 * якого «Вибрати все» вибирає лише видиме, гірший за повільний список: він
 * мовчки робить не те, що каже.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()
const N = 60

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const PROPS = Array.from({ length: N }, (_, i) => ({
  id: `20000000-0000-0000-0000-${String(100000 + i)}`,
  db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + i}`, floor: String((i % 9) + 1),
  status: 'free', area_useful: 45, area_total: 52, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, landlord_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: i * 100, share_token: `bb000000000000000${String(1000 + i)}`,
  share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [],
}))

interface Wire { patches: { url: string; body: Record<string, unknown> }[] }

async function openDb(page: Page, wire: Wire) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const url = decodeURIComponent(rq.url())
      wire.patches.push({ url, body: JSON.parse(rq.postData() ?? '{}') })
      const ids = url.match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      return jsonRoute(r, ids.map((id) => ({ id })))
    }
    return jsonRoute(r, PROPS)
  })
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(`Всі (${N})`)).toBeVisible({ timeout: 15_000 })
}

test('перша порція обмежена, а не весь список', async ({ page }) => {
  const wire: Wire = { patches: [] }
  await openDb(page, wire)
  const rendered = await page.locator('.obj-card').count()
  expect(rendered, `у DOM мусить бути менше за ${N}`).toBeLessThan(N)
  expect(rendered, 'але не порожньо — інакше це не вікно, а зламаний список').toBeGreaterThan(10)
})

test('прокрутка довантажує решту', async ({ page }) => {
  const wire: Wire = { patches: [] }
  await openDb(page, wire)
  const before = await page.locator('.obj-card').count()

  // Прокрутка тілом екрана — sentinel має `rootMargin: 400px`, тож порція
  // приїжджає ДО краю.
  for (let i = 0; i < 6; i++) {
    await page.locator('.body').evaluate((el) => { el.scrollTop += 1200 })
    await page.waitForTimeout(200)
  }
  await expect.poll(() => page.locator('.obj-card').count(), { timeout: 15_000 })
    .toBeGreaterThan(before)
})

/**
 * НАЙВАЖЛИВІШИЙ гард розділу: операція над списком бачить УСІ рядки, а не лише
 * відрендерені. «Вибрати все», що вибирає 40 із 60, — це не оптимізація, а
 * мовчазна брехня про те, що зроблено.
 */
test('«Вибрати все» бере ВЕСЬ список, а не тільки видиме', async ({ page }) => {
  const wire: Wire = { patches: [] }
  await openDb(page, wire)
  expect(await page.locator('.obj-card').count()).toBeLessThan(N)

  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Виділити обʼєкти', { exact: true }).click()

  await page.getByRole('button', { name: 'Вибрати все' }).click()
  await expect(page.getByText(new RegExp(`${N}`)).first()).toBeVisible()

  await page.getByRole('button', { name: /Вільно/ }).first().click()
  const conf = page.locator('.modal').getByRole('button', { name: /Вільно|Підтвердити|Так/ })
  if (await conf.count()) await conf.last().click()

  await expect.poll(() => wire.patches.length, { timeout: 15_000 }).toBeGreaterThan(0)
  const ids = decodeURIComponent(wire.patches[0].url).match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
  expect(ids.length, `пакетна дія мусить зачепити всі ${N}, а не лише відрендерені`).toBe(N)
})

/**
 * У режимі «Змінити порядок» вікно вимикається цілком: стрілки переставляють
 * СУСІДА по глобальному `sort_order`, і сусід, якого немає в DOM, зробив би
 * перестановку наосліп.
 */
test('режим порядку рендерить список ЦІЛКОМ', async ({ page }) => {
  const wire: Wire = { patches: [] }
  await openDb(page, wire)
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Змінити порядок', { exact: true }).click()

  await expect.poll(() => page.locator('.obj-card, .row-t').count(), { timeout: 15_000 })
    .toBeGreaterThanOrEqual(N)
})
