import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, type HarnessUser } from './helpers/harness'

// ─── Sweep: RealtorDashboardScreen (realtor role) + GuestHomeScreen (guest role) ─
// Both screens are reached straight from login (WelcomeScreen / useAuth
// navigateRoot) and have never had a dedicated e2e test — this covers the
// empty-state and one-item-list render paths for each without touching src.

const REALTOR_USER: HarnessUser = { ...DEFAULT_USER, role: 'realtor', first_name: 'Олена' }
// HarnessUser['role'] is 'owner' | 'realtor' | null — the app also has a
// 'guest' role (src/types/index.ts UserRole) that the test harness type
// doesn't model. Cast at the boundary; setupApp/mockBackend only read
// tg_id/first_name/id off this object, never `role`, so this is safe.
const GUEST_USER = { ...DEFAULT_USER, role: 'guest', first_name: 'Гість' } as unknown as HarnessUser

const DB_ID = '10000000-0000-0000-0000-000000000009'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: '00000000-0000-0000-0000-000000000099', name: 'ЖК Липки', address: 'вул. Липська, 5',
  type: 'residential', color: 'blue',
  share_token: 'aa11bb22cc33dd44ee55ff66', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
}

const SUBSCRIPTION = {
  id: '30000000-0000-0000-0000-000000000001',
  realtor_id: REALTOR_USER.id, db_id: DB_ID, created_at: NOW,
  database: DB,
}

const PROPERTY = {
  id: '20000000-0000-0000-0000-000000000002',
  db_id: DB_ID, owner_id: DB.owner_id, name: 'Квартира 12', floor: '3',
  status: 'occupied', area_useful: 60, area_total: 65, rent_type: 'per_m2',
  rent_rate: 15, has_parking: false, parking_spaces: 0,
  created_at: NOW, updated_at: NOW, photos: [],
}

const GUEST_LINK = {
  id: '50000000-0000-0000-0000-000000000001',
  owner_id: DB.owner_id, property_id: PROPERTY.id, db_id: null,
  invite_token: 'gg000000000000000000001', label: 'Мій орендар',
  guest_user_id: GUEST_USER.id, status: 'active',
  claimed_at: NOW, created_at: NOW,
  property: PROPERTY, database: null,
}

function jsonRoute(route: Route, body: unknown) {
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
}

test.describe('realtor + guest sweep', () => {
  test('RealtorDashboardScreen renders cleanly with an empty realtor_subscriptions list', async ({ page }) => {
    await setupApp(page, { user: REALTOR_USER })
    await page.route('**/rest/v1/realtor_subscriptions**', (route) => jsonRoute(route, []))

    await page.goto('/')

    await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Немає підписок')).toBeVisible()
    await expect(page.getByText('Відскануй QR від власника')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Додати базу за QR' })).toBeVisible()
    await expect(page.getByText('Помилка')).toHaveCount(0)
    await expect(page.getByText(/Не вдалося завантажити/)).toHaveCount(0)
  })

  test('RealtorDashboardScreen renders cleanly with one realtor_subscriptions item', async ({ page }: { page: Page }) => {
    await setupApp(page, { user: REALTOR_USER })
    await page.route('**/rest/v1/realtor_subscriptions**', (route) => jsonRoute(route, [SUBSCRIPTION]))
    await page.route('**/rest/v1/properties**', (route) => {
      // count query uses head:true / Prefer: count=exact, response body is irrelevant
      return jsonRoute(route, [])
    })

    await page.goto('/')

    await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('ЖК Липки')).toBeVisible()
    await expect(page.getByText('1', { exact: true })).toBeVisible() // "Баз" stat
    await expect(page.getByText('Немає підписок')).toHaveCount(0)
    await expect(page.getByText('Помилка')).toHaveCount(0)
  })

  test('GuestHomeScreen renders cleanly with an empty guest_links list', async ({ page }) => {
    await setupApp(page, { user: GUEST_USER })
    await page.route('**/rest/v1/guest_links**', (route) => jsonRoute(route, []))

    await page.goto('/')

    await expect(page.getByText("Мої об'єкти")).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText("Немає доступних об'єктів")).toBeVisible()
    await expect(page.getByText("Власник надішле вам запрошення-посилання")).toBeVisible()
    await expect(page.getByText('Помилка')).toHaveCount(0)
    await expect(page.getByText(/Не вдалося завантажити/)).toHaveCount(0)
  })

  test('GuestHomeScreen renders cleanly with one guest_links item', async ({ page }) => {
    await setupApp(page, { user: GUEST_USER })
    await page.route('**/rest/v1/guest_links**', (route) => jsonRoute(route, [GUEST_LINK]))

    await page.goto('/')

    await expect(page.getByText("Мої об'єкти")).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Квартира 12')).toBeVisible()
    await expect(page.getByText('Мій орендар')).toBeVisible()
    await expect(page.getByText("Немає доступних об'єктів")).toHaveCount(0)
    await expect(page.getByText('Помилка')).toHaveCount(0)
  })
})
