import { test, expect, type Browser, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Персонаж порожнього героя (обʼєкт без фото). Тут перевіряється не «як
// виглядає» — це кадр і око власника, — а те, що він ЖИВИЙ: реагує на палець,
// має різну палітру за статусом і зупиняється, коли рух вимкнено.
const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'
const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const prop = (id: string, status: string) => ({
  id, db_id: DB_ID, owner_id: USER.id, name: `Офіс ${id.slice(-2)}`, floor: '3',
  status, area_useful: 45, area_total: 52, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null, utilities: null,
  description: null, address: null, sale_price: null, tenant_name: null,
  lease_start_date: null, lease_end_date: null, sort_order: 1,
  share_token: `bb0000000000000000000000${id.slice(-2)}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
})
const FREE = prop('20000000-0000-0000-0000-000000000011', 'free')
const BUSY = prop('20000000-0000-0000-0000-000000000022', 'occupied')

async function open(page: Page, p: typeof FREE) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? p : [p]))
  await page.route('**/rest/v1/db_members**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/property_files**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/rent_payments**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/property_views**', (r) => jsonRoute(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-t').first().click()
  await expect(page.locator('.orb-stage')).toBeVisible({ timeout: 15_000 })
}

test('персонаж реагує на палець: сцена нахиляється, очі ведуть за рухом', async ({ page }) => {
  await open(page, FREE)
  const stage = page.locator('.orb-stage')
  const box = (await stage.boundingBox())!

  // У спокої нахилу немає — інакше порівняння нижче нічого не доводить.
  const rest = await stage.evaluate((el) => (el as HTMLElement).style.getPropertyValue('--nx'))
  expect(rest === '' || rest === '0.000', `у спокої --nx мусить бути нульовим, а він «${rest}»`).toBe(true)

  // Палець веде праворуч-вниз.
  await page.mouse.move(box.x + box.width * 0.85, box.y + box.height * 0.8)
  await page.waitForTimeout(120)
  const moved = await stage.evaluate((el) => ({
    nx: parseFloat((el as HTMLElement).style.getPropertyValue('--nx') || '0'),
    ny: parseFloat((el as HTMLElement).style.getPropertyValue('--ny') || '0'),
  }))
  expect(moved.nx, 'сцена не побачила руху пальця по горизонталі').toBeGreaterThan(0.3)
  expect(moved.ny, 'сцена не побачила руху пальця по вертикалі').toBeGreaterThan(0.2)

  // Очі мусять реально зміститись — саме це читається як «дивиться на палець».
  const shifted = await page.locator('.orb-eyes').evaluate((el) => getComputedStyle(el).transform)
  expect(shifted, 'очі не зрушили — погляд не працює').not.toBe('none')
})

test('тап по персонажу дає реакцію: примружився і бризнув пилом', async ({ page }) => {
  await open(page, FREE)
  const stage = page.locator('.orb-stage')
  const box = (await stage.boundingBox())!
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await page.mouse.down()
  // Клас спалаху вішає РЕНДЕР React, а не сам обробник, тож читати стиль у
  // тому ж кроці — це замір ДО коміту (пастка, вже наступана на шитах).
  await expect(page.locator('.orb-dust.orb-burst')).toHaveCount(1, { timeout: 2000 })
  await expect(page.locator('.orb-eye.squint')).toHaveCount(2)
  await page.mouse.up()
})

test('палітра відрізняється за статусом — це РІЗНІ персонажі, не копія', async ({ browser }) => {
  // Кожен статус — у ВЛАСНОМУ контексті: `page.route` реєструється на сторінку
  // і повторний `setupApp` мовчки лишає перші фікстури, тож другий статус
  // ніколи б не доїхав до екрана (пастка, вже наступана).
  const read = async (b: Browser, p: typeof FREE) => {
    const ctx = await b.newContext({ viewport: { width: 375, height: 667 } })
    const page = await ctx.newPage()
    try {
      await open(page, p)
      return await page.locator('.orb-stage').evaluate((el) =>
        (el as HTMLElement).style.getPropertyValue('--orb-a'))
    } finally {
      await ctx.close()
    }
  }
  const free = await read(browser, FREE)
  const busy = await read(browser, BUSY)
  expect(free, 'вільний простір лишився без кольору').toMatch(/#[0-9a-f]{6}/i)
  expect(busy, 'зайнятий простір узяв ТОЙ САМИЙ колір, що й вільний').not.toBe(free)
})

test('порожній герой не має темного скриму — перехід у контент суцільний', async ({ page }) => {
  // Скрим `transparent → rgba(0,0,0,.55)` існує, щоб бейдж читався ПОВЕРХ
  // ФОТО. Без фото він лишав темну смугу внизу і рвав градієнт — саме це
  // власник побачив на пристрої.
  await open(page, FREE)
  const hero = page.locator('.obj-hero')
  await expect(hero).toHaveClass(/empty/)
  const scrim = await hero.evaluate((el) => getComputedStyle(el, '::after').display)
  expect(scrim, 'скрим лишився на порожньому герої — унизу буде темна смуга').toBe('none')
  const bg = await hero.evaluate((el) => getComputedStyle(el).backgroundImage)
  expect(bg, 'порожній герой має власний фон — градієнт екрана крізь нього не пройде').toBe('none')
})
