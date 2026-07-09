import { test, expect, type Page, type Route } from '@playwright/test'

// ─── Public share viewer (/v) — the standalone page every share-link recipient
// hits in a plain browser (no Telegram). It calls get_public_*_preview RPCs
// directly and had zero e2e coverage. This drives all three preview types plus
// the invalid-token, not-found, and network-retry states.

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

// PostgREST network failure surfaces as status 0 in postgrest-js — Playwright's
// route.abort() makes supabase-js resolve with status 0, exactly the real signal.
const NOW_PLUS = new Date(Date.now() + 30 * 86400000).toISOString()

const PROP_PREVIEW = {
  property_id: '20000000-0000-0000-0000-000000000001',
  property_name: 'Офіс 101',
  property_status: 'occupied',
  property_floor: '3',
  property_area_useful: 100,
  property_area_total: 120,
  property_rent_type: 'per_m2',
  property_rent_rate: 18,
  property_utilities_rate: 2.5,
  property_description: 'Світлий офіс у центрі',
  property_address: 'вул. Хрещатик, 1',
  property_has_parking: true,
  property_parking_spaces: 2,
  property_sale_price: null,
  share_expires_at: NOW_PLUS,
  db_id: '10000000-0000-0000-0000-000000000001',
  db_name: 'БЦ Рубін',
  db_type: 'business_center',
  db_color: 'pink',
  owner_first_name: 'Микола',
  owner_last_name: 'К.',
  owner_tg_username: 'mykola',
  owner_phone: '+380670000000',
  photos: [],
}

const DB_ROWS = [
  {
    db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін',
    db_type: 'business_center', db_color: 'pink', share_expires_at: NOW_PLUS,
    property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
    property_status: 'free', property_floor: '3', property_area_useful: 100,
    property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
    property_description: null,
    owner_first_name: 'Микола', owner_last_name: 'К.',
    owner_tg_username: 'mykola', owner_phone: '+380670000000',
    first_photo: null,
  },
]

const COL_ROWS = [
  {
    collection_id: '40000000-0000-0000-0000-000000000001', collection_name: 'Підбірка для клієнта',
    share_expires_at: NOW_PLUS, realtor_first_name: 'Олена', realtor_last_name: 'Р.',
    realtor_tg_username: 'olena', realtor_phone: null,
    property_id: '20000000-0000-0000-0000-000000000002', property_name: 'Квартира 12',
    property_status: 'free', property_floor: '5', property_area_useful: 60,
    property_area_total: 65, property_rent_type: 'per_m2', property_rent_rate: 15,
    property_description: null, db_id: '10000000-0000-0000-0000-000000000001',
    db_name: 'ЖК Липки', db_type: 'residential', db_color: 'blue', first_photo: null,
  },
]

// Inject a Telegram stub so buildDeepLink()'s "Open in Telegram" button has an
// env; the /v page itself doesn't require Telegram to render.
async function stubTelegram(page: Page) {
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram = { WebApp: { openTelegramLink() {}, ready() {}, expand() {} } }
  })
}

test('/v?prop — renders a shared property preview', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_property_preview', (route) => json(route, [PROP_PREVIEW]))
  await page.route('**/rest/v1/rpc/record_public_view', (route) => json(route, true))

  await page.goto('/v/?prop=aabbccddeeff001122334455')

  await expect(page.getByText('Офіс 101')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('БЦ Рубін', { exact: false })).toBeVisible()
  await expect(page.getByText('Зайнято')).toBeVisible() // occupied status label
})

test('/v?db — renders a shared database preview with its objects', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (route) => json(route, DB_ROWS))

  await page.goto('/v/?db=aabbccddeeff001122334455')

  await expect(page.getByText('БЦ Рубін')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 101')).toBeVisible()
  // Owner contact must be reachable for a visitor without Telegram (037/P1)
  await expect(page.getByText('Микола К.', { exact: true })).toBeVisible()
  await expect(page.getByText('@mykola')).toBeVisible()
})

test('/v?col — renders a shared collection preview', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (route) => json(route, COL_ROWS))

  await page.goto('/v/?col=aabbccddeeff001122334455')

  await expect(page.getByText('Підбірка для клієнта')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Квартира 12')).toBeVisible()
  await expect(page.getByText('Олена Р.', { exact: true })).toBeVisible() // realtor name
})

test('/v with no params shows a "no params" error', async ({ page }) => {
  await stubTelegram(page)
  await page.goto('/v/')
  await expect(page.getByText(/Параметри перегляду не вказані/)).toBeVisible({ timeout: 20_000 })
})

test('/v with a malformed token shows an invalid-link error (no RPC call)', async ({ page }) => {
  await stubTelegram(page)
  let rpcCalled = false
  await page.route('**/rest/v1/rpc/**', (route) => { rpcCalled = true; return json(route, []) })

  await page.goto('/v/?prop=%20bad') // fails TOKEN_RE

  await expect(page.getByText(/Посилання невалідне/)).toBeVisible({ timeout: 20_000 })
  expect(rpcCalled).toBe(false)
})

test('/v?prop not found (empty result) shows expired/not-found error', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_property_preview', (route) => json(route, []))

  await page.goto('/v/?prop=aabbccddeeff001122334455')

  await expect(page.getByText(/не знайдено або посилання застаріло/)).toBeVisible({ timeout: 20_000 })
})

test('/v?db network failure shows a retryable error, then succeeds on retry', async ({ page }) => {
  await stubTelegram(page)
  let firstCall = true
  await page.route('**/rest/v1/rpc/get_public_db_preview', (route) => {
    if (firstCall) { firstCall = false; return route.abort('failed') } // → postgrest status 0
    return json(route, DB_ROWS)
  })

  await page.goto('/v/?db=aabbccddeeff001122334455')

  // Retryable network state (📡 + retry button), not the "expired" message.
  // The retry button is the unambiguous signal it's the retryable branch.
  const retryBtn = page.getByRole('button', { name: /Спробувати ще раз/i })
  await expect(retryBtn).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText(/Перевір з'єднання та спробуй ще раз/)).toBeVisible()

  await retryBtn.click()
  await expect(page.getByText('БЦ Рубін')).toBeVisible({ timeout: 20_000 })
})
