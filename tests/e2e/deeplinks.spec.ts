import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession, jsonRoute as json } from './helpers/harness'

// ─── Вхідні воркфлоу ролей через deep links ────────────────────────────────────
// guest_ → claim_guest_link; db_ → subscribe_to_shared_db; prop_/col_ — лукапи
// шерених об'єктів/підбірок. (team_ покритий у team.spec.ts.)

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

// ─── prop_<share_token> та col_<share_token> ────────────────────────────────────

test('prop share deep link: lookup lands on the property detail', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setupApp(page, { user: owner, startParam: `prop_${PROP.share_token}` })
  await seedSession(page, owner)

  await page.route('**/rest/v1/rpc/lookup_shared_property', (route) =>
    json(route, [{ id: PROP_ID, db_id: DB_ID }]))
  await page.route('**/rest/v1/properties**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })

  await page.goto('/')
  await expect(page.getByText('Квартира 12').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible()
})

test('col share deep link: foreign collection opens the read-only shared view', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  const COL_ID = '90000000-0000-0000-0000-000000000001'
  await setupApp(page, { user: owner, startParam: 'col_cc00112233445566778899dd' })
  await seedSession(page, owner)

  await page.route('**/rest/v1/rpc/lookup_shared_collection', (route) =>
    json(route, [{ id: COL_ID, realtor_id: FOREIGN_OWNER }]))
  await page.route('**/rest/v1/rpc/get_shared_collection', (route) =>
    json(route, { id: COL_ID, name: 'Топ офіси', description: null, properties: [] }))

  await page.goto('/')
  // Чужа підбірка → read-only SharedCollectionScreen з її назвою
  await expect(page.getByText('Топ офіси')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText("0 об'єктів")).toBeVisible()
})
