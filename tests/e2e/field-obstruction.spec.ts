import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// «Перевір, щоб такого більше ніде не було» — прохід по ВСІХ екранах із полями
// вводу: жодне поле у фокусі не має ховатись під плаваючою смугою (фіксована
// кнопка збереження, sticky-дії модалки, таббар, панель обраних, FAB).
// Клавіатуру імітуємо в обох режимах: перекриття і стиснення webview.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '2', status: 'occupied', area_useful: 100, area_total: 120,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: 'ТОВ «Ромашка»', lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}

/** Смуги, що плавають над вмістом і тому можуть накрити поле. */
const OVERLAYS = ['.mbtn', '.modal-actions', '.tabbar', '.batchbar', '.fbtn']

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/users**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? USER : [USER])
  })
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Клавіатура ПЕРЕКРИВАЄ лейаут (класичний iOS). */
async function keyboardOverlay(page: Page, h: number) {
  const vh = page.viewportSize()!.height
  await page.evaluate((v) => (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), vh)
  await page.evaluate((k) => (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(k), h)
  await page.waitForTimeout(250)
}

/** Клавіатура СТИСКАЄ webview (Android / новий Telegram iOS). */
async function keyboardShrink(page: Page, h: number) {
  const size = page.viewportSize()!
  await page.evaluate((v) => (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), size.height)
  await page.setViewportSize({ width: size.width, height: size.height - h })
  await page.evaluate((k) => (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(k), h)
  await page.waitForTimeout(250)
}

/**
 * Фокусує кожне видиме поле по черзі й повертає ті, що перекриті плаваючою
 * смугою більше ніж на 2px (антиаліасинг).
 */
async function findObstructed(page: Page, scope = ''): Promise<string[]> {
  const count = await page.locator(`${scope} input:visible, ${scope} textarea:visible`).count()
  const bad: string[] = []
  for (let i = 0; i < count; i++) {
    const field = page.locator(`${scope} input:visible, ${scope} textarea:visible`).nth(i)
    // date/file інпути відкривають нативний пікер, а не клавіатуру
    const type = await field.getAttribute('type')
    if (type === 'file' || type === 'date') continue
    await field.focus()
    await page.waitForTimeout(650)
    const hit = await page.evaluate((sels) => {
      const el = document.activeElement as HTMLElement | null
      if (!el || (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA')) return null
      const f = el.getBoundingClientRect()
      if (f.height === 0) return null
      for (const sel of sels) {
        for (const node of document.querySelectorAll(sel)) {
          const o = (node as HTMLElement).getBoundingClientRect()
          if (o.width === 0 || o.height === 0) continue
          const style = getComputedStyle(node as HTMLElement)
          if (style.visibility === 'hidden' || style.opacity === '0' || style.pointerEvents === 'none') continue
          const overlapY = Math.min(f.bottom, o.bottom) - Math.max(f.top, o.top)
          const overlapX = Math.min(f.right, o.right) - Math.max(f.left, o.left)
          if (overlapY > 2 && overlapX > 2) {
            return `${sel} накриває поле (${el.getAttribute('placeholder') ?? el.className}) на ${Math.round(overlapY)}px`
          }
        }
      }
      // Поле нижче видимої області — теж «під клавіатурою»
      if (f.top > window.innerHeight - 8) return `поле нижче екрана (${el.getAttribute('placeholder') ?? el.className})`
      return null
    }, OVERLAYS)
    if (hit) bad.push(hit)
  }
  return bad
}

test('форма обʼєкта: жодне поле не ховається під фіксованою кнопкою', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()

  await keyboardOverlay(page, 300)
  expect(await findObstructed(page), 'клавіатура перекриває лейаут').toEqual([])
})

test('форма обʼєкта: те саме, коли webview стискається', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()

  await keyboardShrink(page, 300)
  expect(await findObstructed(page), 'webview стиснуто').toEqual([])
})

test('створення бази: поля вільні від кнопки збереження', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByLabel('Створити базу').click()
  await expect(page.getByPlaceholder('БЦ Олімп')).toBeVisible()

  await keyboardOverlay(page, 300)
  expect(await findObstructed(page)).toEqual([])
})

test('профіль: контактні поля не під таббаром', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible()

  await keyboardOverlay(page, 300)
  expect(await findObstructed(page)).toEqual([])
})

test('модалки з полями: розклад платежів і оренда', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  await keyboardShrink(page, 300)
  expect(await findObstructed(page, '.modal'), 'розклад платежів').toEqual([])
})

test('модалка папок: поле нової папки лишається видимим', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.locator('.fold-mng-input')).toBeVisible()

  await keyboardShrink(page, 300)
  expect(await findObstructed(page, '.modal')).toEqual([])
})
