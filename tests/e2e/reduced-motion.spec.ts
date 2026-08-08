import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'

/**
 * `prefers-reduced-motion: reduce` мусить справді спиняти рух — не «майже».
 *
 * Блок у globals.css гасить CSS-анімації, але Web Animations API (`el.animate()`)
 * він не зупиняє в принципі. Саме так `Collapsible` рухався 300 мс навіть з
 * вимкненим рухом — єдине місце застосунку, що обходило власне ж правило.
 *
 * Другий тест тримає КЛАС дефекту, а не лише цей випадок: жодна анімація на
 * екрані не має права тривати довше за кадр, хоч би чим її запустили.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const FOLDER_ID = '50000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const FOLDERS = [{
  id: FOLDER_ID, db_id: DB_ID, owner_id: USER.id, name: 'Орендарі',
  sort_order: 1, created_at: NOW, updated_at: NOW,
}]
const PROPS = [1, 2].map((i) => ({
  id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс 10${i}`, floor: String(i), status: 'occupied',
  area_useful: 100, area_total: 120, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: i === 1 ? FOLDER_ID : null,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: `ТОВ ${i}`, lease_start_date: null, lease_end_date: null,
  sort_order: i, share_token: `bb0000000000000000001${i}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}))

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : PROPS))
  await page.route('**/rest/v1/property_folders**', (r) => json(r, FOLDERS))
  for (const t of ['property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

async function toObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
}

/**
 * Найдовша анімація, що ЗАРАЗ біжить: або на всій сторінці, або на конкретному
 * елементі.
 *
 * Поріг усюди — ОДИН КАДР, а не нуль. Блок reduced-motion не прибирає переходи,
 * а ставить їм `.01ms`, тож вони чесно звітують 0.01 — і на `.fold-wrap` теж,
 * бо фікс пише інлайн `opacity`/`visibility`, а на них висить глобальний
 * `transition`. Різниця, яку ловить гард, на два порядки: без фікса тут
 * 300 мс WAAPI-анімації, з ним — 0.01 мс переходу.
 */
const longestRunning = (page: Page, selector?: string) => page.evaluate((sel) => {
  const scope = sel ? document.querySelector(sel) : null
  if (sel && !scope) return -1
  // БЕЗ subtree: анімація Collapsible цілиться в сам `.fold-wrap`, а піддерево
  // притягнуло б `cascadeIn` дочірніх карток (їм reduced-motion ставить .01мс,
  // тобто не нуль) — і точна перевірка стала б неможливою.
  const anims = scope ? scope.getAnimations() : document.getAnimations()
  return anims
    .filter((a) => a.playState === 'running')
    .reduce((max, a) => {
      const d = (a.effect?.getTiming().duration ?? 0) as number
      return typeof d === 'number' && d > max ? d : max
    }, 0)
}, selector)

test('акордеон папки НЕ анімується, коли рух вимкнено', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await setup(page)
  await toObjects(page)

  const header = page.locator('.fold-hd', { hasText: 'Орендарі' })
  await expect(header).toBeVisible()

  // Згортаємо і ОДРАЗУ читаємо: без фікса тут біжить 300-мілісекундна
  // Web Animation, яку CSS-блок не гасить.
  await header.click()
  const running = await longestRunning(page, '.fold-wrap')
  expect(running, `з вимкненим рухом акордеон не має анімуватись (${running}ms)`).toBeLessThanOrEqual(17)

  // Кінцевий стан усе одно застосований — папка згорнута, а не завмерла.
  await expect.poll(async () => page.evaluate(() => {
    const w = document.querySelector('.fold-wrap') as HTMLElement | null
    return w ? Math.round(w.getBoundingClientRect().height) : -1
  }), { timeout: 3000 }).toBe(0)

  // І розгортається так само — стрибком, але справді.
  await header.click()
  const back = await longestRunning(page, '.fold-wrap')
  expect(back, `розгортання теж без анімації (${back}ms)`).toBeLessThanOrEqual(17)
  await expect.poll(async () => page.evaluate(() => {
    const w = document.querySelector('.fold-wrap') as HTMLElement | null
    return w ? Math.round(w.getBoundingClientRect().height) : -1
  }), { timeout: 3000 }).toBeGreaterThan(0)
})

test('жодна анімація на екрані не переживає кадр із вимкненим рухом', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await setup(page)

  // Обходимо місця, де анімації запускаються: вхід екрана, акордеон, модалка,
  // панель обраних. Після кожної дії — жодна анімація не має тривати довго.
  const steps: [string, () => Promise<void>][] = [
    ['вхід на список баз', async () => {
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    }],
    ['перехід у базу', async () => {
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
    }],
    ['акордеон папки (згорнути)', async () => {
      await page.locator('.fold-hd', { hasText: 'Орендарі' }).click()
    }],
    ['акордеон папки (розгорнути)', async () => {
      // Інакше перша .obj-card лишається всередині згорнутої папки й ніколи не
      // стане видимою для кроку з режимом вибору.
      await page.locator('.fold-hd', { hasText: 'Орендарі' }).click()
      await expect(page.locator('.obj-card').first()).toBeVisible()
    }],
    ['меню бази (модалка)', async () => {
      await page.getByLabel('Меню бази').click()
      await expect(page.locator('.modal')).toBeVisible()
    }],
    ['режим вибору', async () => {
      await page.getByText('Виділити об\'єкти', { exact: true }).click()
      await page.locator('.obj-card').first().click()
      await expect(page.locator('.batchbar')).toBeVisible()
    }],
  ]

  for (const [label, go] of steps) {
    await go()
    const running = await longestRunning(page)
    // Один кадр при 60 Гц — ~17 мс. Блок reduced-motion ставить .01 мс, тож
    // будь-яке значення понад кадр означає анімацію, що обійшла CSS.
    expect(running, `${label}: анімація ${running}ms обходить reduced-motion`).toBeLessThanOrEqual(17)
  }
})
