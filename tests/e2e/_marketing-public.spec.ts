import { test, type Browser, type Route } from '@playwright/test'
import { jsonRoute as json } from './helpers/harness'

/** ІНСТРУМЕНТ (PERF=1). Публічна `/v` у 3× — головний маркетинговий екран. */
const OUT = process.env.SHOTS || 'marketing/shots'
const NOW_PLUS = new Date(Date.now() + 30 * 864e5).toISOString()

const OWNER = {
  owner_first_name: 'Микола', owner_last_name: 'К.', owner_tg_username: 'mykola',
  owner_phone: null, owner_currency: 'USD', share_expires_at: NOW_PLUS,
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін',
  db_type: 'business_center', db_color: 'pink',
}
const PROP = {
  ...OWNER,
  property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
  property_status: 'free', property_floor: '3', property_area_useful: 100,
  property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
  property_utilities_rate: 2.5, property_area_basis: 'total',
  property_description: 'Світлий кутовий офіс з панорамними вікнами, окремий вхід, дві переговорні.',
  property_address: 'вул. Хрещатик, 1', property_has_parking: true,
  property_parking_spaces: 2, property_sale_price: null,
  // Порожньо СВІДОМО: фікстура галереї — 1×1 PNG, тобто в кадрі був би
  // розтягнутий піксель замість фото. Чистий лейаут чесніший за фейкове фото.
  photos: [], landlord_name: 'ТОВ «Рубін Капітал»',
}
const row = (id: string, name: string, status: string, floor: string, u: number, t: number, rate: number) => ({
  ...OWNER, property_id: id, property_name: name, property_status: status,
  property_floor: floor, property_area_useful: u, property_area_total: t,
  property_rent_type: 'per_m2', property_rent_rate: rate, property_utilities_rate: 2.5,
  property_area_basis: 'total', property_sale_price: null, first_photo: null,
})
const DB_ROWS = [
  row('a1', 'Офіс 101', 'free', '3', 100, 120, 18),
  row('a2', 'Офіс 102', 'free', '3', 80, 90, 20),
  row('a3', 'Офіс 205', 'free', '2', 140, 160, 17),
]

test('shots · public', async ({ browser }: { browser: Browser }) => {
  test.setTimeout(120_000)
  for (const [label, url] of [['v-property', '/v/?prop=aabbccddeeff001122334455'], ['v-database', '/v/?db=aabbccddeeff001122334455']] as const) {
    const ctx = await browser.newContext({
      viewport: { width: 375, height: 812 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
    })
    const page = await ctx.newPage()
    try {
      await page.emulateMedia({ reducedMotion: 'reduce' })
      await page.addInitScript(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ;(window as any).Telegram = { WebApp: { openTelegramLink() {}, ready() {}, expand() {} } }
      })
      await page.route('**/rest/v1/rpc/get_public_property_preview', (r: Route) => json(r, [PROP]))
      await page.route('**/rest/v1/rpc/get_public_db_preview', (r: Route) => json(r, DB_ROWS))
      await page.route('**/rest/v1/rpc/record_public_view', (r: Route) => json(r, true))
      await page.goto(url)
      await page.waitForTimeout(1500)
      await page.screenshot({ path: `${OUT}/${label}.png` })
      console.log(`✓ ${label}`)
    } catch (e) {
      console.log(`✗ ${label}: ${(e as Error).message.split('\n')[0]}`)
    } finally { await ctx.close() }
  }
})
