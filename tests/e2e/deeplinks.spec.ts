import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Вхідні воркфлоу ролей через deep links ────────────────────────────────────
// guest_<token> → claim_guest_link → гість бачить розшарений об'єкт;
// db_<token> → subscribe_to_shared_db → рієлтор підключає базу.
// (team_<token> покритий у team.spec.ts; prop_/col_ — лукапи тих самих рейок.)

const NOW = new Date().toISOString()
const FOREIGN_OWNER = '00000000-0000-0000-0000-000000000099'
const DB_ID = '10000000-0000-0000-0000-000000000005'
const PROP_ID = '20000000-0000-0000-0000-000000000005'

const DB = {
  id: DB_ID, owner_id: FOREIGN_OWNER, name: 'ЖК Світанок', address: 'вул. Ясна, 3',
  type: 'residential_complex', color: 'green',
  share_token: 'ff00112233445566778899aa', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: FOREIGN_OWNER, name: 'Квартира 12', floor: '3',
  status: 'occupied', area_useful: 60, area_total: 65, rent_type: 'per_m2',
  rent_rate: 15, utilities_rate: null, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, utilities: null, description: null,
  address: null, sale_price: null, tenant_name: 'Орендар', lease_start_date: null,
  lease_end_date: null, sort_order: 100, share_token: 'aa00112233445566778899bb',
  share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [],
}

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

// Кешований профіль → Fast Path 0 відновлює сесію миттєво. Без сесії Splash
// веде db_/guest_ на публічний превʼю-екран (окремий флоу «подивись → підключи»);
// нам потрібна гілка залогіненого користувача, яку обробляє useDeepLink.
function seedSession(page: Page, user: Record<string, unknown>) {
  return page.addInitScript((u) => {
    localStorage.setItem('ps_user', JSON.stringify(u))
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  }, user)
}

// ─── guest_<invite_token> ───────────────────────────────────────────────────────

test('guest deep link: claim lands on the shared property with a success toast', async ({ page }) => {
  // Новий користувач без ролі — claim_guest_link виставляє role='guest' у БД,
  // клієнт це підхоплює рефетчем users.
  const newUser = { ...DEFAULT_USER, role: null }
  await setupApp(page, { user: newUser, startParam: 'guest_gg000000000000000000001' })
  await seedSession(page, newUser)

  let claimed: string | null = null
  await page.route('**/rest/v1/rpc/claim_guest_link', (route) => {
    claimed = JSON.parse(route.request().postData() ?? '{}').p_token
    return json(route, { property_id: PROP_ID, db_id: DB_ID })
  })
  // Рефетч users після клейму повертає роль guest — перекриваємо users-стаб
  // харнеса власним хендлером (останній зареєстрований виграє)
  await page.route('**/rest/v1/users**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    const guestUser = { ...DEFAULT_USER, role: 'guest' }
    return json(route, accept.includes('object') ? guestUser : [guestUser])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
  await page.route('**/rest/v1/guest_links**', (route) => json(route, []))

  await page.goto('/')
  await expect(page.getByText('Доступ отримано! 🎉')).toBeVisible({ timeout: 20_000 })
  // Лендинг: детальна розшареного об'єкта
  await expect(page.getByText('Квартира 12').first()).toBeVisible()
  expect(claimed).toBe('gg000000000000000000001')
})

test('guest deep link: already-claimed invite shows the error and falls back home', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setupApp(page, { user: owner, startParam: 'guest_deadbeef' })
  await seedSession(page, owner)

  await page.route('**/rest/v1/rpc/claim_guest_link', (route) =>
    json(route, { error: 'already_claimed' }))

  await page.goto('/')
  await expect(page.getByText('Це запрошення вже використано')).toBeVisible({ timeout: 20_000 })
  // Фолбек: власник лишається на своєму домашньому екрані
  await expect(page.getByText('Мої бази')).toBeVisible()
})

// ─── db_<share_token> ───────────────────────────────────────────────────────────

test('db share deep link: realtor subscribes and lands inside the database', async ({ page }) => {
  const realtor = { ...DEFAULT_USER, role: 'realtor' as const }
  await setupApp(page, { user: realtor, startParam: `db_${DB.share_token}` })
  await seedSession(page, realtor)

  let subscribedToken: string | null = null
  await page.route('**/rest/v1/rpc/subscribe_to_shared_db', (route) => {
    subscribedToken = JSON.parse(route.request().postData() ?? '{}').p_token
    return json(route, [{ db_id: DB_ID, db_name: DB.name, error: null }])
  })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => json(route, [PROP]))
  await page.route('**/rest/v1/realtor_subscriptions**', (route) => json(route, []))

  await page.goto('/')
  await expect(page.getByText('Базу підключено! 🎉')).toBeVisible({ timeout: 20_000 })
  // Лендинг: екран підключеної бази з її назвою і об'єктами
  await expect(page.getByText('ЖК Світанок').first()).toBeVisible()
  await expect(page.getByText('Квартира 12').first()).toBeVisible()
  expect(subscribedToken).toBe(DB.share_token)
})

test('db share deep link: expired/unknown token shows the error and falls back home', async ({ page }) => {
  const realtor = { ...DEFAULT_USER, role: 'realtor' as const }
  await setupApp(page, { user: realtor, startParam: 'db_0000000000000000000000ff' })
  await seedSession(page, realtor)

  await page.route('**/rest/v1/rpc/subscribe_to_shared_db', (route) =>
    json(route, [{ db_id: null, db_name: null, error: 'not_found' }]))
  await page.route('**/rest/v1/realtor_subscriptions**', (route) => json(route, []))

  await page.goto('/')
  await expect(page.getByText('Базу не знайдено')).toBeVisible({ timeout: 20_000 })
  // Фолбек: домашній екран рієлтора
  await expect(page.getByText(/Робочі бази|Немає підписок/).first()).toBeVisible({ timeout: 10_000 })
})

test('db share deep link: owner tapping their own link opens the db directly (no subscription)', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setupApp(page, { user: owner, startParam: `db_${DB.share_token}` })
  await seedSession(page, owner)

  const OWN_DB = { ...DB, owner_id: DEFAULT_USER.id, name: 'БЦ Власний' }
  await page.route('**/rest/v1/rpc/subscribe_to_shared_db', (route) =>
    json(route, [{ db_id: OWN_DB.id, db_name: OWN_DB.name, error: 'own_db' }]))
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? OWN_DB : [OWN_DB])
  })
  await page.route('**/rest/v1/properties**', (route) => json(route, [{ ...PROP, owner_id: DEFAULT_USER.id, name: 'Офіс 1' }]))

  await page.goto('/')
  // Без тосту підписки — одразу власні об'єкти бази
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 1').first()).toBeVisible()
})
