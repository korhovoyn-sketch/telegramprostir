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
  owner_currency: 'USD',
  photos: [],
}

const DB_ROW_BASE = {
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін',
  db_type: 'business_center', db_color: 'pink', share_expires_at: NOW_PLUS,
  owner_first_name: 'Микола', owner_last_name: 'К.',
  owner_tg_username: 'mykola', owner_phone: '+380670000000',
  owner_currency: 'UAH',
  first_photo: null,
}

const DB_ROWS = [
  {
    ...DB_ROW_BASE,
    property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
    property_status: 'free', property_floor: '3', property_area_useful: 100,
    property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
    property_sale_price: null,
    property_description: 'Світлий офіс у самому центрі міста, панорамні вікна.',
  },
  {
    ...DB_ROW_BASE,
    property_id: '20000000-0000-0000-0000-000000000003', property_name: 'Офіс 202',
    property_status: 'for_sale', property_floor: '4', property_area_useful: 80,
    property_area_total: 90, property_rent_type: 'per_m2', property_rent_rate: null,
    property_sale_price: 85000,
    property_description: null,
  },
]

// A DB with zero objects: the RPC's LEFT JOIN returns one row with NULL
// property fields.
const DB_ROWS_EMPTY = [{
  ...DB_ROW_BASE,
  property_id: null, property_name: null, property_status: null,
  property_floor: null, property_area_useful: null, property_area_total: null,
  property_rent_type: null, property_rent_rate: null, property_sale_price: null,
  property_description: null,
}]

const COL_ROWS = [
  {
    collection_id: '40000000-0000-0000-0000-000000000001', collection_name: 'Підбірка для клієнта',
    share_expires_at: NOW_PLUS, realtor_first_name: 'Олена', realtor_last_name: 'Р.',
    realtor_tg_username: 'olena', realtor_phone: null,
    property_id: '20000000-0000-0000-0000-000000000002', property_name: 'Квартира 12',
    property_status: 'free', property_floor: '5', property_area_useful: 60,
    property_area_total: 65, property_rent_type: 'per_m2', property_rent_rate: 15,
    property_sale_price: null, owner_currency: 'EUR',
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
  let recordedKind: string | undefined
  await page.route('**/rest/v1/rpc/record_public_view', (route) => {
    recordedKind = JSON.parse(route.request().postData() ?? '{}').p_kind
    return json(route, true)
  })

  await page.goto('/v/?db=aabbccddeeff001122334455')

  await expect(page.getByText('БЦ Рубін')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 101')).toBeVisible()
  // Owner contact must be reachable for a visitor without Telegram (037/P1)
  await expect(page.getByText('Микола К.', { exact: true })).toBeVisible()
  await expect(page.getByText('@mykola')).toBeVisible()

  // 040: owner currency (UAH → ₴, not a hardcoded $) on the rent rate
  await expect(page.getByText(/₴18\/м²/)).toBeVisible()
  // 040: a for-sale object shows its sale price in the list
  await expect(page.getByText(/₴85/)).toBeVisible()
  // Correct Ukrainian plural for 2
  await expect(page.getByText(/2 об'єкти/)).toBeVisible()
  // Card description (clamped) renders
  await expect(page.getByText(/панорамні вікна/)).toBeVisible()
  // 040: the db open is recorded with p_kind='db'
  await expect.poll(() => recordedKind, { timeout: 10_000 }).toBe('db')
})

test('/v?db — empty database shows an explanatory empty state', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (route) => json(route, DB_ROWS_EMPTY))
  await page.route('**/rest/v1/rpc/record_public_view', (route) => json(route, true))

  await page.goto('/v/?db=aabbccddeeff001122334455')

  await expect(page.getByText('БЦ Рубін')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('У базі поки немає об\'єктів')).toBeVisible()
})

test('/v?col — renders a shared collection preview', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (route) => json(route, COL_ROWS))
  let recordedKind: string | undefined
  await page.route('**/rest/v1/rpc/record_public_view', (route) => {
    recordedKind = JSON.parse(route.request().postData() ?? '{}').p_kind
    return json(route, true)
  })

  await page.goto('/v/?col=aabbccddeeff001122334455')

  await expect(page.getByText('Підбірка для клієнта')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Квартира 12')).toBeVisible()
  await expect(page.getByText('Олена Р.', { exact: true })).toBeVisible() // realtor name
  // 040: property owner's currency (EUR), 1-object plural
  await expect(page.getByText(/€15\/м²/)).toBeVisible()
  await expect(page.getByText(/1 об'єкт(?!и|ів)/)).toBeVisible()
  await expect.poll(() => recordedKind, { timeout: 10_000 }).toBe('col')
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
  await page.route('**/rest/v1/rpc/record_public_view', (route) => json(route, true))
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

// ─── Галерея фото ─────────────────────────────────────────────────────────────
//
// ПРОГАЛИНА, ЯКА БУЛА СТРУКТУРНОЮ: усі фікстури вище віддають `photos: []` і
// `first_photo: null`, тож галерея не малювалась у жодному тесті — ні стрілки,
// ні смужка мініатюр, ні лічильник, ні свайп. Для сторінки, яка продає обʼєкт
// незнайомцю, це найважливіший елемент і водночас єдиний геть не покритий.

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64')

const PROP_WITH_PHOTOS = { ...PROP_PREVIEW, photos: ['p/1.jpg', 'p/2.jpg', 'p/3.jpg'] }

async function openGallery(page: Page) {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) => json(r, [PROP_WITH_PHOTOS]))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, true))
  await page.route('**/storage/v1/object/public/**', (r) =>
    r.fulfill({ status: 200, contentType: 'image/png', body: PNG }))
  await page.goto('/v/?prop=aabbccddeeff001122334455')
  await expect(page.getByText('Офіс 101')).toBeVisible({ timeout: 20_000 })
}

test('/v галерея: лічильник, стрілки і повернення назад', async ({ page }) => {
  await openGallery(page)

  await expect(page.getByText('1/3')).toBeVisible()
  // На першому кадрі «назад» не має бути взагалі — інакше тап у неї нічого не
  // робить, а кнопка виглядає живою.
  await expect(page.getByRole('button', { name: 'Попереднє фото' })).toBeHidden()

  await page.getByRole('button', { name: 'Наступне фото' }).click()
  await expect(page.getByText('2/3')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Попереднє фото' })).toBeVisible()

  await page.getByRole('button', { name: 'Наступне фото' }).click()
  await expect(page.getByText('3/3')).toBeVisible()
  // На останньому кадрі зникає «вперед».
  await expect(page.getByRole('button', { name: 'Наступне фото' })).toBeHidden()

  await page.getByRole('button', { name: 'Попереднє фото' }).click()
  await expect(page.getByText('2/3')).toBeVisible()
})

test('/v галерея: тап по мініатюрі відкриває саме те фото', async ({ page }) => {
  await openGallery(page)

  await page.getByRole('button', { name: 'Фото 3 з 3' }).click()
  await expect(page.getByText('3/3')).toBeVisible()

  await page.getByRole('button', { name: 'Фото 1 з 3' }).click()
  await expect(page.getByText('1/3')).toBeVisible()
})

test('/v галерея: свайп гортає, короткий рух — ні', async ({ page }) => {
  await openGallery(page)

  const stage = page.locator('img[alt="Фото обʼєкта 1 з 3"]').locator('..')
  const box = (await stage.boundingBox())!
  const y = box.y + box.height / 2

  // Свайп ліворуч — далі. Поріг у компоненті 40px, тож 120 — впевнений жест.
  await page.locator('body').evaluate((_, args) => {
    const el = document.elementFromPoint(args.x, args.y)!
    const mk = (type: string, cx: number) => new TouchEvent(type, {
      bubbles: true, cancelable: true,
      changedTouches: [new Touch({ identifier: 1, target: el, clientX: cx, clientY: args.y })],
      touches: type === 'touchend' ? [] : [new Touch({ identifier: 1, target: el, clientX: cx, clientY: args.y })],
    })
    el.dispatchEvent(mk('touchstart', args.x))
    el.dispatchEvent(mk('touchend', args.x - 120))
  }, { x: box.x + box.width / 2, y })
  await expect(page.getByText('2/3')).toBeVisible()

  // Рух нижче порога не має гортати: інакше будь-який дотик до фото зсуває кадр.
  await page.locator('body').evaluate((_, args) => {
    const el = document.elementFromPoint(args.x, args.y)!
    const mk = (type: string, cx: number) => new TouchEvent(type, {
      bubbles: true, cancelable: true,
      changedTouches: [new Touch({ identifier: 1, target: el, clientX: cx, clientY: args.y })],
      touches: type === 'touchend' ? [] : [new Touch({ identifier: 1, target: el, clientX: cx, clientY: args.y })],
    })
    el.dispatchEvent(mk('touchstart', args.x))
    el.dispatchEvent(mk('touchend', args.x - 12))
  }, { x: box.x + box.width / 2, y })
  await expect(page.getByText('2/3')).toBeVisible()
})

test('/v галерея: одне фото — без стрілок, лічильника і смужки', async ({ page }) => {
  await stubTelegram(page)
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) =>
    json(r, [{ ...PROP_PREVIEW, photos: ['p/1.jpg'] }]))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, true))
  await page.route('**/storage/v1/object/public/**', (r) =>
    r.fulfill({ status: 200, contentType: 'image/png', body: PNG }))
  await page.goto('/v/?prop=aabbccddeeff001122334455')
  await expect(page.getByText('Офіс 101')).toBeVisible({ timeout: 20_000 })

  await expect(page.getByRole('button', { name: 'Наступне фото' })).toHaveCount(0)
  await expect(page.getByText('1/1')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /^Фото \d+ з/ })).toHaveCount(0)
  // Саме фото при цьому МУСИТЬ бути — інакше тест «немає хрому» проходив би
  // і на зламаній галереї, що не показує нічого.
  await expect(page.locator('img[alt="Фото обʼєкта 1 з 1"]')).toBeVisible()
})
