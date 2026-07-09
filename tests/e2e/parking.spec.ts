import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Parking DB: the property form must adapt to a spot-oriented field set ─────

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000009'
const NOW = new Date().toISOString()

const PARK_DB = {
  id: DB_ID, owner_id: USER.id, name: 'Паркінг Центр', address: 'вул. Гаражна, 5',
  type: 'parking', color: 'purple',
  share_token: 'ppaarrkk00112233445566778899', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [{ status: 'free', rent_rate: 100, area_useful: 12, rent_type: 'fixed' }],
}

const PARK_PROP = {
  id: '20000000-0000-0000-0000-000000000091',
  db_id: DB_ID, owner_id: USER.id, name: '№ 10', floor: '-1',
  status: 'free', area_useful: 12, area_total: null, rent_type: 'fixed',
  rent_rate: 100, utilities_rate: 30, has_parking: false, parking_spaces: 0,
  parking_type: 'underground', ev_charger: true,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'pp00000000000000000000000091', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

async function setupFixtures(page: Page, onCreate?: (body: Record<string, unknown>) => void) {
  await setupApp(page, { user: USER })
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? PARK_DB : [PARK_DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const method = route.request().method()
    if (method === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      onCreate?.(body)
      return json(route, { ...PARK_PROP, ...body })
    }
    const accept = route.request().headers()['accept'] ?? ''
    if (accept.includes('object')) return json(route, PARK_PROP)
    return json(route, [PARK_PROP])
  })

  // Dismiss onboarding coach marks so the FAB is directly clickable.
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openNewObjectForm(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Паркінг Центр').first().click()
  await expect(page.getByText(/Всі \(\d\)/)).toBeVisible()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()
}

test('parking DB shows a spot-oriented form, not the office layout', async ({ page }) => {
  await setupFixtures(page)
  await openNewObjectForm(page)

  // Parking-specific fields present
  await expect(page.getByPlaceholder('№ 42, A-15')).toBeVisible()       // spot number
  await expect(page.getByText('Площа місця')).toBeVisible()             // single area
  await expect(page.getByText('Подобово')).toBeVisible()               // daily rent option
  await expect(page.getByText('Підземний')).toBeVisible()              // spot type
  await expect(page.getByText('Просто неба')).toBeVisible()
  await expect(page.getByText('Зарядка для електромобіля')).toBeVisible()

  // Office-only fields hidden
  await expect(page.getByText('Загальна')).toHaveCount(0)              // no useful/total split
  await expect(page.getByText('$ за м²')).toHaveCount(0)               // no per-m² rent option
  await expect(page.getByText('Є паркінг')).toHaveCount(0)             // no nested parking toggle
})

test('parking property submits with per_day rate, parking_type and ev_charger', async ({ page }) => {
  let created: Record<string, unknown> | null = null
  await setupFixtures(page, (b) => { created = b })
  await openNewObjectForm(page)

  await page.getByPlaceholder('№ 42, A-15').fill('№ 42')
  await page.getByPlaceholder('13.5').fill('13.5')          // spot area
  await page.getByText('Подобово').click()                  // switch to daily rate
  await page.getByPlaceholder('150').fill('150')            // daily rate (placeholder flips to 150)
  await page.getByText('Підземний').click()                 // spot type
  await page.locator('[role="switch"]').first().click()     // EV charger toggle

  await page.getByRole('button', { name: "Додати об'єкт" }).click()
  // Wait for the success toast: it fires only after the POST round-trips, which
  // guarantees the route handler already recorded the payload (avoids racing
  // waitForRequest, which resolves before the handler runs).
  await expect(page.getByText("Об'єкт додано")).toBeVisible({ timeout: 15_000 })

  expect(created).toMatchObject({
    rent_type: 'per_day',
    rent_rate: 150,
    area_useful: 13.5,
    parking_type: 'underground',
    ev_charger: true,
    has_parking: false,
    parking_spaces: 0,
  })
  // A parking spot carries no office total area.
  expect(created!.area_total == null).toBe(true)
})
