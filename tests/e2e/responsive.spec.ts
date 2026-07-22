import { test, expect, type Page, type Route, type Browser } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Cross-device responsive check ────────────────────────────────────────────
// The default suite runs one profile (iphone-se 375×667). This spec renders the
// key surfaces across the real mobile width range and asserts the invariant that
// broke layouts before: the page body must NEVER scroll horizontally — wide
// content (tabs, tables, chips) scrolls inside its own container. Also captures
// a screenshot per device×screen for visual review (screenshots/resp-*, gitignored).

const NOW = new Date().toISOString()
const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

// Narrowest Android → largest iPhone. Chromium only (sandbox has no webkit).
const DEVICES = [
  { id: 'galaxy-s8', w: 360, h: 740, dpr: 3 },   // narrowest common Android
  { id: 'iphone-se', w: 375, h: 667, dpr: 2 },   // smallest iPhone
  { id: 'pixel-5', w: 393, h: 851, dpr: 2.75 },  // standard Android
  { id: 'iphone-13', w: 390, h: 844, dpr: 3 },   // standard modern iPhone
  { id: 'iphone-15-pro-max', w: 430, h: 932, dpr: 3 }, // largest iPhone
] as const

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.', phone: '+380670000000' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}
function prop(i: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    utilities: null, description: 'Світлий офіс у центрі міста, панорамні вікна.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5 }),
  prop(2, { status: 'free' }),
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
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, []))
  await page.route('**/rest/v1/rent_payment_records**', (r) => json(r, []))
  await page.route('**/rest/v1/property_views**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

// Assert the page body doesn't scroll sideways. A 1px rounding slack is allowed;
// anything wider is a real overflow (an element pushing past the viewport).
async function expectNoHScroll(page: Page, label: string) {
  const overflow = await page.evaluate(() => ({
    docScroll: document.documentElement.scrollWidth,
    docClient: document.documentElement.clientWidth,
    bodyScroll: document.body.scrollWidth,
    innerW: window.innerWidth,
  }))
  expect(overflow.docScroll, `${label}: html scrollWidth ≤ viewport`).toBeLessThanOrEqual(overflow.innerW + 1)
  expect(overflow.bodyScroll, `${label}: body scrollWidth ≤ viewport`).toBeLessThanOrEqual(overflow.innerW + 1)
}

async function newDevicePage(browser: Browser, d: typeof DEVICES[number]) {
  const ctx = await browser.newContext({
    viewport: { width: d.w, height: d.h },
    deviceScaleFactor: d.dpr,
    isMobile: true,
    hasTouch: true,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
  })
  return { ctx, page: await ctx.newPage() }
}

for (const d of DEVICES) {
  test(`responsive · ${d.id} (${d.w}×${d.h}) · app + public`, async ({ browser }) => {
    const { ctx, page } = await newDevicePage(browser, d)
    try {
      // ── In-app: home (db-list) ──────────────────────────────────────────────
      await setupApp(page, { user: OWNER })
      await ownerRoutes(page)
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await expectNoHScroll(page, `${d.id} db-list`)
      // FAB and tabbar must be within the viewport horizontally
      const fab = page.locator('.fab, [aria-label="Створити базу"]').first()
      if (await fab.count()) {
        const box = await fab.boundingBox()
        if (box) expect(box.x + box.width, `${d.id}: FAB within viewport`).toBeLessThanOrEqual(d.w + 1)
      }
      await page.screenshot({ path: `screenshots/resp-${d.id}-db-list.png` })

      // ── In-app: db-objects (tabs + stats panel + cards) ─────────────────────
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
      await expectNoHScroll(page, `${d.id} db-objects`)
      await page.screenshot({ path: `screenshots/resp-${d.id}-db-objects.png` })

      // ── Public /v database surface (bespoke CSS, different from app) ─────────
      await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, [{
        db_id: DB_ID, db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
        share_expires_at: null, property_id: PROPERTIES[0].id, property_name: 'Офіс 101',
        property_status: 'occupied', property_floor: '2', property_area_useful: 100,
        property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
        property_sale_price: null, property_description: 'Світлий офіс у центрі.',
        owner_first_name: 'Микола', owner_last_name: 'К.', owner_phone: '+380670000000',
        owner_tg_username: 'mykola', owner_currency: 'UAH', first_photo: null,
      }]))
      await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, null))
      await page.goto('/v/?db=aabbccddeeff001122334455')
      await expect(page.getByText('Публічний перегляд')).toBeVisible({ timeout: 15_000 })
      await expectNoHScroll(page, `${d.id} /v db`)
      await page.screenshot({ path: `screenshots/resp-${d.id}-v-database.png` })
    } finally {
      await ctx.close()
    }
  })
}
