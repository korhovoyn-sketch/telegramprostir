import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Input fields across device sizes ─────────────────────────────────────────
// The load-bearing rule (CLAUDE.md): every focusable input renders at >= 16px so
// iOS Safari / the Telegram webview never auto-zooms on focus. This drives the
// real forms at three widths and asserts the computed font-size of every input,
// plus that inputs actually fill (value updates) and drive derived UI.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '3', status: 'free', area_useful: 45, area_total: 52,
  rent_type: 'per_m2', rent_rate: null, utilities_rate: null, has_parking: false,
  parking_spaces: 0, parking_type: null, ev_charger: false, utilities: null,
  description: null, address: null, sale_price: null, tenant_name: null,
  lease_start_date: null, lease_end_date: null, sort_order: 1,
  share_token: 'bb000000000000000000000001', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const VIEWPORTS = [
  { name: 'iPhone SE (320)', width: 320, height: 568 },
  { name: 'iPhone (375)', width: 375, height: 667 },
  { name: 'Large phone (414)', width: 414, height: 896 },
]

async function setupFixtures(page: Page) {
  await setupApp(page, { user: USER })
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

// Every visible input/textarea must compute to >= 16px (iOS anti-zoom).
async function assertNoZoomInputs(page: Page, where: string) {
  const sizes = await page.locator('input:visible, textarea:visible').evaluateAll((els) =>
    els.map((el) => ({
      fs: parseFloat(getComputedStyle(el).fontSize),
      tag: el.tagName.toLowerCase(),
      type: (el as HTMLInputElement).type ?? '',
    })),
  )
  expect(sizes.length, `${where}: expected some inputs`).toBeGreaterThan(0)
  for (const s of sizes) {
    expect(s.fs, `${where}: <${s.tag}${s.type ? ` type=${s.type}` : ''}> font-size ${s.fs}px must be >= 16 (iOS zoom guard)`).toBeGreaterThanOrEqual(16)
  }
}

for (const vp of VIEWPORTS) {
  test(`inputs @ ${vp.name}: no iOS-zoom sizes + fields fill`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height })
    await setupFixtures(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

    // ── Create-database form ──────────────────────────────────────────────
    await page.getByLabel('Створити базу').click()
    await expect(page.getByText('Нова база')).toBeVisible()
    await assertNoZoomInputs(page, `${vp.name} · create-db`)

    const dbName = page.getByPlaceholder('БЦ Олімп')
    await dbName.fill('БЦ Тест')
    await expect(dbName).toHaveValue('БЦ Тест')       // filled
    const dbAddr = page.getByPlaceholder('Хрещатик 22')
    await dbAddr.fill('вул. Тестова, 5')
    await expect(dbAddr).toHaveValue('вул. Тестова, 5')

    // Reset to the list (create-db's back label is 'Бази', not 'Назад'; a fresh
    // load is the robust way back), then open a property form — more input types
    // (number / date / text).
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText(/Всі \(\d\)/)).toBeVisible()
    await page.getByLabel("Додати об'єкт").click()
    await expect(page.getByText("Новий об'єкт")).toBeVisible()
    await assertNoZoomInputs(page, `${vp.name} · property-form`)

    // Fill numeric fields and confirm the derived rent preview reacts (заповненість)
    await page.getByPlaceholder('Офіс 101').fill('Тест-101')
    await page.getByPlaceholder('47').fill('50')       // useful area
    await page.getByPlaceholder('18').fill('20')       // rent rate ($/m²)
    await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Тест-101')
    await expect(page.getByPlaceholder('47')).toHaveValue('50')
    await expect(page.getByPlaceholder('18')).toHaveValue('20')
    // Filling area + rate drives the derived preview — the 'Розрахунок' row
    // appears only when rentCalc > 0 (locale-independent, unlike the $ number).
    await expect(page.getByText('Розрахунок').first()).toBeVisible()
  })
}
