import { expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './harness'

/**
 * Фікстури власника з однією базою й двома обʼєктами (зайнятий і вільний) —
 * спільні для спеків, що водять основні дії: `server-failures` (сервер
 * відмовив) і `closing-confirmation` (свайп униз не губить набране).
 * `fail` ламає РІВНО ОДИН запит; без нього бекенд цілком живий.
 */
export const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
export const DB_ID = '10000000-0000-0000-0000-000000000001'
export const NOW = '2026-09-01T09:00:00.000Z'

export const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', landlord_name: null, created_at: NOW, updated_at: NOW, properties: [],
  share_token: 'aa00112233445566778899bb', share_expires_at: null,
}

const base = {
  db_id: DB_ID, owner_id: USER.id, floor: '2', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null,
  sale_price: null, landlord_name: null, created_at: NOW, updated_at: NOW, photos: [],
}
export const OCCUPIED = {
  ...base, id: '20000000-0000-0000-0000-000000000001', name: 'Офіс 101', status: 'occupied',
  tenant_name: 'ТОВ «Ромашка»', lease_start_date: '2026-01-01', lease_end_date: '2027-01-01', sort_order: 100,
}
export const FREE = {
  ...base, id: '20000000-0000-0000-0000-000000000002', name: 'Офіс 102', status: 'free',
  tenant_name: null, lease_start_date: null, lease_end_date: null, sort_order: 200,
}

export type Fail = { method: string; path: string }

export async function setup(page: Page, fail: Fail | null, extra?: (page: Page) => Promise<void>) {
  await page.clock.setFixedTime(new Date('2026-09-15T10:00:00Z'))
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() === 'GET') return jsonRoute(r, wantsObject ? DB : [DB])
    const body = rq.postData() ? JSON.parse(rq.postData()!) : {}
    const row = { ...DB, ...(Array.isArray(body) ? body[0] : body) }
    return jsonRoute(r, wantsObject ? row : [row])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    const url = decodeURIComponent(rq.url())
    const one = url.includes(`id=eq.${FREE.id}`) ? FREE : OCCUPIED
    if (rq.method() === 'GET') return jsonRoute(r, wantsObject ? one : [OCCUPIED, FREE])
    const body = rq.postData() ? JSON.parse(rq.postData()!) : {}
    const row = { ...one, ...(Array.isArray(body) ? body[0] : body) }
    return jsonRoute(r, wantsObject ? row : [row])
  })
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'db_members', 'tenancies', 'notifications', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => {
      const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? null : [])
    })
  }
  if (extra) await extra(page)
  // Зламаний запит — останнім, тож вирішує першим.
  await page.route('**/*', (r: Route) => {
    const rq = r.request()
    if (fail && rq.method() === fail.method && decodeURIComponent(rq.url()).includes(fail.path)) {
      return r.fulfill({ status: 500, contentType: 'application/json',
        body: JSON.stringify({ code: 'XX000', message: 'internal failure' }) })
    }
    return r.fallback()
  })
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

export async function openDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 10_000 })
}
