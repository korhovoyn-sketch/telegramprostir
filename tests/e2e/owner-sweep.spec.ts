import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Owner sweep: CollectionsScreen + ExportScreen ────────────────────────────
// (PaymentCalendarScreen and NotificationsScreen already covered in owner-workflow.spec.ts)

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const COL_ID = '40000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
  ],
}

const PROPERTIES = [
  {
    id: '20000000-0000-0000-0000-000000000001',
    db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
    status: 'occupied', area_useful: 100, area_total: 120, rent_type: 'per_m2',
    rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: 'ТОВ «Ромашка»', lease_start_date: null, lease_end_date: null,
    sort_order: 1, share_token: 'bb000000000000000000001', share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  },
]

const COLLECTION = {
  id: COL_ID, realtor_id: USER.id, name: 'Підбірка для клієнта', is_draft: false,
  share_token: 'cc00112233445566778899bb', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
}

async function baseFixtures(page: Page) {
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const url = route.request().url()
    const accept = route.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = url.match(/id=eq\.([0-9a-f-]+)/)
      const found = PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0]
      return json(route, found)
    }
    return json(route, PROPERTIES)
  })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

test.describe('owner sweep: uncovered screens', () => {
  test('ExportScreen renders with its action button', async ({ page }) => {
    await setupApp(page, { user: USER })
    await baseFixtures(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText('Всі (1)')).toBeVisible()

    await page.getByLabel('Меню бази').click()
    await page.getByText('Експорт').click()

    await expect(page.getByText('Формат файлу')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Завантажити PDF' })).toBeVisible()
    // No crash / error state
    await expect(page.getByText('Помилка')).toHaveCount(0)
  })

  test('CollectionsScreen shows a collection card (owner opens own shared collection via deep link)', async ({ page }) => {
    const json = (route: Route, body: unknown) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

    await setupApp(page, { user: USER, startParam: 'col_cc00112233445566778899bb' })
    await baseFixtures(page)

    await page.route('**/rest/v1/rpc/lookup_shared_collection', (route) =>
      json(route, [{ id: COL_ID, realtor_id: USER.id }]))

    await page.route('**/rest/v1/collections**', (route) => {
      const accept = route.request().headers()['accept'] ?? ''
      const row = { ...COLLECTION, collection_properties: [{ count: 0 }] }
      return json(route, accept.includes('object') ? row : [row])
    })
    await page.route('**/rest/v1/collection_properties**', (route) => json(route, []))

    await page.goto('/')

    // Deep link skips db-list entirely and auto-navigates straight into the
    // owner's own collection (detail view) — no "Мої бази" is ever shown.
    await expect(page.getByText('Підбірка для клієнта')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Немає об\'єктів')).toBeVisible()
  })

  test('CollectionsScreen (list view) creates a collection card when empty', async ({ page }) => {
    const json = (route: Route, body: unknown) =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

    // Deep-link to a collection id that matches nothing yet loaded — the owner
    // tab bar has no "Підбірки" entry, so this share-link path is the only way
    // to reach CollectionsScreen as an owner (mirrors useDeepLink's own-collection branch).
    await setupApp(page, { user: USER, startParam: 'col_cc00112233445566778899bb' })
    await baseFixtures(page)

    await page.route('**/rest/v1/rpc/lookup_shared_collection', (route) =>
      json(route, [{ id: COL_ID, realtor_id: USER.id }]))

    await page.route('**/rest/v1/collections**', (route) => {
      const method = route.request().method()
      const accept = route.request().headers()['accept'] ?? ''
      if (method === 'POST') {
        return json(route, { ...COLLECTION, id: '40000000-0000-0000-0000-000000000002', name: 'Підбірка 1' })
      }
      // GET: empty list so the deep link's collectionId can't match — stays on list view
      return json(route, accept.includes('object') ? null : [])
    })
    await page.route('**/rest/v1/collection_properties**', (route) => json(route, []))

    await page.goto('/')

    await expect(page.getByText('Немає підбірок')).toBeVisible({ timeout: 20_000 })
    // FAB і нативна MainButton (DOM-фолбек .mbtn) тепер несуть той самий
    // підпис на ОДНОМУ екрані (на відміну від «Додати об'єкт»/«Створити
    // базу», де FAB веде на ІНШИЙ екран і колізії немає) — звужуємо до FAB.
    await page.locator('.fbtn').click()
    await expect(page.getByText('Підбірка 1')).toBeVisible()
  })
})
