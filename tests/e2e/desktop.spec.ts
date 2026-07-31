import { test, expect, type Page, type Route, type Browser } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Desktop presentation (Telegram Desktop / Web run Mini Apps in a wide window) ─
// On screens ≥680px the app must render as a centered phone-sized frame, NOT a
// full-width stretched layout. The public /v page is a separate web surface.

const NOW = new Date().toISOString()
const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

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
const PREVIEW = [{
  db_id: DB_ID, db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
  share_expires_at: null, property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
  property_status: 'occupied', property_floor: '2', property_area_useful: 100, property_area_total: 120,
  property_rent_type: 'per_m2', property_rent_rate: 18, property_sale_price: null,
  property_description: 'Світлий офіс у центрі міста, панорамні вікна.',
  owner_first_name: 'Микола', owner_last_name: 'К.', owner_phone: '+380670000000',
  owner_tg_username: 'mykola', owner_currency: 'UAH', first_photo: null,
}]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function desktopPage(browser: Browser) {
  // Laptop window — no isMobile/touch: this is Telegram Desktop / Web.
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 })
  return { ctx, page: await ctx.newPage() }
}

test('desktop · Mini App renders as a centered phone frame, not full-width', async ({ browser }) => {
  const { ctx, page } = await desktopPage(browser)
  try {
    await setupApp(page, { user: OWNER })
    await ownerRoutes(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

    // #app-root must be constrained to the phone frame (~430px), centered — not
    // stretched across the 1280px viewport.
    const root = page.locator('#app-root')
    const box = await root.boundingBox()
    expect(box, 'app-root has a box').not.toBeNull()
    expect(box!.width, 'app-root width ≈ 430px phone frame').toBeLessThanOrEqual(460)
    const centerX = box!.x + box!.width / 2
    expect(Math.abs(centerX - 640), 'app-root horizontally centered in 1280px').toBeLessThan(40)

    // No horizontal page scroll on desktop either.
    const over = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)
    expect(over, 'no horizontal overflow on desktop').toBe(true)

    await page.screenshot({ path: 'screenshots/desktop-app-db-list.png' })
  } finally {
    await ctx.close()
  }
})

test('desktop · public /v is width-capped and centered, not full-bleed', async ({ browser }) => {
  const { ctx, page } = await desktopPage(browser)
  try {
    await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, PREVIEW))
    await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, null))
    await page.goto('/v/?db=aabbccddeeff001122334455')
    await expect(page.getByText('Публічний перегляд')).toBeVisible({ timeout: 15_000 })

    // The content column must not span the whole 1280px desktop width — a public
    // listing stretched edge-to-edge reads as broken. Cap ~560px, centered
    // (the #app-root desktop frame constrains /v too).
    const header = page.getByText('Публічний перегляд').locator('xpath=ancestor::*[contains(@style,"border-radius")][1]')
    const box = await header.boundingBox()
    if (box) {
      expect(box.width, '/v content column is width-capped on desktop').toBeLessThanOrEqual(560)
    }
    await page.screenshot({ path: 'screenshots/desktop-v-database.png', fullPage: false })
  } finally {
    await ctx.close()
  }
})
