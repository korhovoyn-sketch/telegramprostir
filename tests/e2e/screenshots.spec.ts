import { test, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, type HarnessUser } from './helpers/harness'

// ─── Screen audit: capture a screenshot of every reachable screen ─────────────
// Not an assertion suite — a visual tour. Each capture is wrapped so a missed
// selector logs and continues instead of aborting the whole tour. Output:
// screenshots/NN-name.png (gitignored).

const DIR = 'screenshots'
const NOW = new Date().toISOString()
let n = 0
async function shot(page: Page, name: string) {
  n += 1
  const file = `${DIR}/${String(n).padStart(2, '0')}-${name}.png`
  await page.screenshot({ path: file })
  console.log('shot:', file)
}
async function tryShot(page: Page, name: string, nav: () => Promise<void>) {
  try {
    await nav()
    await page.waitForTimeout(450) // let transitions/anim settle
    await shot(page, name)
  } catch (e) {
    console.warn(`SKIP ${name}:`, (e as Error).message.split('\n')[0])
  }
}
const json = (route: Route, body: unknown) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

// ── Owner fixtures ────────────────────────────────────────────────────────────
const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.', phone: '+380670000000' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'occupied', rent_rate: 2500, area_useful: 80, rent_type: 'fixed' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}
function prop(i: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    utilities: null, description: 'Світлий офіс у центрі міста.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01' }),
  prop(2, { status: 'occupied', tenant_name: 'ФОП Іванов', rent_type: 'fixed', rent_rate: 2500, area_useful: 80, area_total: 90 }),
  prop(3, { status: 'free', sale_price: null }),
]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
    db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
    guest_user_id: null, status: 'pending', claimed_at: null, created_at: NOW,
  }]))
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, []))
  await page.route('**/rest/v1/rent_payment_records**', (r) => json(r, []))
  await page.route('**/rest/v1/property_views**', (r) => json(r, []))
  await page.route('**/rest/v1/rpc/manage_share', (r) => json(r, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('screens · owner journey', async ({ page }) => {
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  await tryShot(page, 'db-list', async () => {
    await page.goto('/')
    await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'db-objects', async () => {
    await page.getByText('БЦ Рубін').first().click()
    await page.getByText('Всі (3)').waitFor()
  })
  await tryShot(page, 'property-detail', async () => {
    await page.locator('.obj-card', { hasText: 'Офіс 101' }).click()
    await page.getByText('Назад', { exact: true }).first().waitFor()
  })
  await tryShot(page, 'property-form-edit', async () => {
    await page.getByLabel(/Редагувати|Змінити/).first().click().catch(() => page.getByText('Редагувати').first().click())
    await page.getByText(/Редагування|Зберегти зміни/).first().waitFor()
  })
  // back to objects for the menu-driven screens
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await tryShot(page, 'property-form-new', async () => {
    await page.getByLabel("Додати об'єкт").click()
    await page.getByText("Новий об'єкт").waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await tryShot(page, 'sharing-analytics', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Аналітика і поширення').click()
    await page.getByText(/Аналітика|Поділитись/).first().waitFor()
  })
  await tryShot(page, 'share-sheet', async () => {
    await page.getByRole('button', { name: /Поділитися/ }).click()
    await page.getByText('Поділитися').first().waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await tryShot(page, 'payment-calendar', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Календар платежів').click()
    await page.getByText(/Календар платежів|Прострочено/).first().waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await tryShot(page, 'manage-guests', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Управління гостями').click()
    await page.getByLabel('Запросити гостя').waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await tryShot(page, 'export', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Експорт').click()
    await page.getByText(/Формат файлу|Завантажити/).first().waitFor()
  })
  await tryShot(page, 'create-db', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.getByLabel('Створити базу').click()
    await page.getByText('Нова база').waitFor()
  })
  await tryShot(page, 'notifications', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.locator('.tabbar [aria-label="Сповіщення"]').click()
    await page.getByText(/Сповіщення|Немає сповіщень/).first().waitFor()
  })
  await tryShot(page, 'profile', async () => {
    await page.locator('.tabbar [aria-label="Профіль"]').click()
    await page.getByText('Налаштування').waitFor()
  })
})

// ── Realtor ───────────────────────────────────────────────────────────────────
test('screens · realtor', async ({ page }) => {
  const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }
  const RDB = { ...DB, owner_id: '00000000-0000-0000-0000-000000000099' }
  await setupApp(page, { user: REALTOR })
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000009', realtor_id: REALTOR.id, db_id: DB_ID, created_at: NOW, database: RDB,
  }]))
  await page.route('**/rest/v1/properties**', (r) => json(r, PROPERTIES))
  await page.route('**/rest/v1/collections**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

  await tryShot(page, 'realtor-dashboard', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'realtor-database', async () => {
    await page.getByText('БЦ Рубін').first().click()
    await page.getByText(/Всі \(/).first().waitFor()
  })
  await tryShot(page, 'qr-scanner', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor()
    await page.getByRole('button', { name: 'Додати базу за QR' }).click()
    await page.getByText(/Сканер|Відскануйте/).first().waitFor()
  })
  await tryShot(page, 'collections', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor()
    await page.locator('.tabbar [aria-label="Підбірки"]').click()
    await page.getByText(/Підбірки|Немає підбірок/).first().waitFor()
  })
})

// ── Guest ─────────────────────────────────────────────────────────────────────
test('screens · guest', async ({ page }) => {
  const GUEST = { ...DEFAULT_USER, first_name: 'Гість' } as unknown as HarnessUser
  ;(GUEST as unknown as { role: string }).role = 'guest'
  const PROPERTY = { ...PROPERTIES[0], owner_id: '00000000-0000-0000-0000-000000000099' }
  await setupApp(page, { user: GUEST })
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '50000000-0000-0000-0000-000000000001', owner_id: PROPERTY.owner_id,
    property_id: PROPERTY.id, db_id: null, invite_token: 'gg000000000000000000001',
    label: 'Мій орендар', guest_user_id: GUEST.id, status: 'active', claimed_at: NOW,
    created_at: NOW, property: PROPERTY, database: null,
  }]))
  await page.route('**/rest/v1/properties**', (r) => json(r, [PROPERTY]))

  await tryShot(page, 'guest-home', async () => {
    await page.goto('/'); await page.getByText("Мої об'єкти").waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'guest-property', async () => {
    await page.getByText('Офіс 101').first().click()
    await page.waitForTimeout(400)
  })
})

// ── Auth / onboarding ─────────────────────────────────────────────────────────
test('screens · welcome', async ({ page }) => {
  await tryShot(page, 'welcome', async () => {
    await setupApp(page, { user: { ...DEFAULT_USER, role: null }, noAutoLogin: true })
    await page.goto('/?fromLogout=1')
    await page.waitForTimeout(1600)
  })
})

test('screens · onboarding', async ({ page }) => {
  // A role:null user auto-logs-in and lands on role-select (useAuth navigateRoot).
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
  await tryShot(page, 'role-select', async () => {
    await page.goto('/')
    await page.getByText('Власник').first().waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'profile-setup', async () => {
    await page.getByText('Власник').first().click()
    await page.getByText('Продовжити →').click()
    await page.getByPlaceholder('you@email.com').waitFor()
  })
})

// ── Public /v viewer ──────────────────────────────────────────────────────────
test('screens · public /v', async ({ page }) => {
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram = { WebApp: { openTelegramLink() {}, ready() {}, expand() {} } }
  })
  const PROP_PREVIEW = {
    property_id: '2', property_name: 'Офіс 101', property_status: 'free',
    property_floor: '3', property_area_useful: 100, property_area_total: 120,
    property_rent_type: 'per_m2', property_rent_rate: 18, property_utilities_rate: 2.5,
    property_description: 'Світлий офіс у центрі.', property_address: 'вул. Хрещатик, 1',
    property_has_parking: false, property_parking_spaces: 0, property_parking_type: null,
    property_ev_charger: false, property_sale_price: null, share_expires_at: null,
    db_id: '1', db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
    owner_first_name: 'Микола', owner_last_name: 'К.', owner_tg_username: 'mykola',
    owner_phone: '+380670000000', photos: [],
  }
  const DB_ROWS = [{
    db_id: '1', db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
    share_expires_at: null, property_id: '2', property_name: 'Офіс 101',
    property_status: 'free', property_floor: '3', property_area_useful: 100,
    property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
    property_description: null, owner_first_name: 'Микола', owner_last_name: 'К.',
    owner_tg_username: 'mykola', owner_phone: '+380670000000', first_photo: null,
  }]
  const COL_ROWS = [{
    collection_id: '4', collection_name: 'Підбірка для клієнта', share_expires_at: null,
    realtor_first_name: 'Олена', realtor_last_name: 'Р.', realtor_tg_username: 'olena',
    realtor_phone: '+380670000001', property_id: '2', property_name: 'Квартира 12',
    property_status: 'free', property_floor: '5', property_area_useful: 60,
    property_area_total: 65, property_rent_type: 'per_m2', property_rent_rate: 15,
    property_description: null, db_id: '1', db_name: 'ЖК Липки', db_type: 'residential',
    db_color: 'blue', first_photo: null,
  }]
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) => json(r, [PROP_PREVIEW]))
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, DB_ROWS))
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (r) => json(r, COL_ROWS))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, true))

  await tryShot(page, 'v-property', async () => {
    await page.goto('/v/?prop=aabbccddeeff001122334455')
    await page.getByText('Офіс 101').first().waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'v-database', async () => {
    await page.goto('/v/?db=aabbccddeeff001122334455')
    await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  })
  await tryShot(page, 'v-collection', async () => {
    await page.goto('/v/?col=aabbccddeeff001122334455')
    await page.getByText('Підбірка для клієнта').first().waitFor({ timeout: 20_000 })
  })
})
