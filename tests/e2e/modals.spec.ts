import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Modal behaviour + data-entry: rent modal (live preview, validation),
// schedule modal (range validation), close affordances (backdrop, Escape),
// and the 16px anti-zoom guarantee for inputs INSIDE modals.

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

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, rent_type: 'per_m2',
    rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
    parking_type: null, ev_charger: false,
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120 }),
  prop(2, {}), // Офіс 102 — вільний: ціль rent-модалки
  prop(3, {}),
]

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
    if (req.method() === 'PATCH') {
      const body = JSON.parse(req.postData() ?? '{}')
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      const base = PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0]
      return json(route, { ...base, ...body })
    }
    if (req.method() === 'GET' && accept.includes('object')) {
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      return json(route, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    if (req.method() === 'GET') return json(route, PROPERTIES)
    return route.fallback()
  })
  await page.route('**/rest/v1/rent_payments**', (route) => {
    if (route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      return json(route, { id: '55550000-0000-0000-0000-000000000001', created_at: NOW, ...body })
    }
    return json(route, [])
  })
  await page.route('**/rest/v1/rent_payment_records**', (route) => json(route, []))
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openRentModal(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  // Клік по заголовку — центр короткої картки влучає в рядок дій
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.getByText('Здати в оренду', { exact: true }).first()).toBeVisible()
}

test('rent modal: disabled CTA, live monthly preview, currency-aware unit labels', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)

  // «Здати» must be disabled until the tenant is named
  const submit = page.getByRole('button', { name: 'Здати', exact: true })
  await expect(submit).toBeDisabled()

  // Unit labels carry the owner's currency symbol (USD user → $)
  await expect(page.getByText('Оренда, $/м²')).toBeVisible()
  await expect(page.getByText('Експлуатаційні, $/м²')).toBeVisible()

  // Live preview on the default basis (розрахункова/total area 52):
  // 52 м² × 20 + 52 м² × 5 = 1 300 — recomputes as you type
  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  await expect(submit).toBeEnabled()
  const rateInput = page.locator('.modal .fld input[inputmode="decimal"]').first()
  const utilInput = page.locator('.modal .fld input[inputmode="decimal"]').nth(1)
  await rateInput.fill('20')
  await expect(page.getByText('Разом на місяць')).toBeVisible()
  await expect(page.locator('.modal').getByText(/\$1\s?040/)).toBeVisible()
  await utilInput.fill('5')
  await expect(page.locator('.modal').getByText(/\$1\s?300/)).toBeVisible()

  // All modal inputs obey the 16px anti-zoom floor
  const sizes = await page.locator('.modal input').evaluateAll(els =>
    els.map(el => parseFloat(getComputedStyle(el).fontSize)))
  for (const s of sizes) expect(s).toBeGreaterThanOrEqual(16)
})

test('rent modal: lease that ends before it starts is rejected; valid save PATCHes', async ({ page }) => {
  await fixtures(page)
  const patches: Record<string, unknown>[] = []
  await page.route('**/rest/v1/properties?id=eq.*', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    const body = JSON.parse(route.request().postData() ?? '{}')
    patches.push(body)
    return json(route, { ...PROPERTIES[1], ...body })
  })
  await openRentModal(page)

  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  const dates = page.locator('.modal input[type="date"]')
  await dates.first().fill('2026-05-10')
  await dates.nth(1).fill('2026-05-01') // раніше початку

  await page.getByRole('button', { name: 'Здати', exact: true }).click()
  await expect(page.getByText('Дата закінчення оренди раніше початку')).toBeVisible()
  // Модалка лишається відкритою, нічого не збережено
  await expect(page.locator('.modal')).toBeVisible()
  expect(patches).toHaveLength(0)

  await dates.nth(1).fill('2026-12-01')
  await page.getByRole('button', { name: 'Здати', exact: true }).click()
  await expect.poll(() => patches.length).toBe(1)
  expect(patches[0].status).toBe('occupied')
  expect(patches[0].tenant_name).toBe('ФОП Петренко')
  expect(patches[0].lease_end_date).toBe('2026-12-01')
})

test('modal closes on Escape and on backdrop tap, not on inner tap', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)

  // Тап всередині модалки не закриває
  await page.locator('.modal-head').click()
  await expect(page.locator('.modal')).toBeVisible()

  // Escape закриває (десктопний Telegram / браузер)
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // Бекдроп закриває
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.locator('.modal-overlay').click({ position: { x: 10, y: 10 } })
  await expect(page.locator('.modal')).toHaveCount(0)
})

test('schedule modal: day outside 1–28 shows the range error; valid day saves', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  // Заголовок залежить від входу: per-property — «Платежі — <назва>»
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })

  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  await dayInput.fill('45')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  await expect(page.getByText('День платежу має бути від 1 до 28')).toBeVisible()
  await expect(page.locator('.modal')).toBeVisible() // не закрилась

  await dayInput.fill('10')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  await expect(page.locator('.modal')).toHaveCount(0, { timeout: 10_000 })
})
