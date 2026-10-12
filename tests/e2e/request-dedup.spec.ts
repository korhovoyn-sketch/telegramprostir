import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession, seedSupabaseSession, jsonRoute } from './helpers/harness'

// Жоден запит теплого старту, входу в базу і картки обʼєкта не йде двічі.
//
// Заміряно `_optimize.spec.ts`: до раунду оптимізації теплий старт слав 11
// запитів, із них чотири — двічі. Два незалежні механізми, і кожен легко
// повертається непомітно, бо екран від дубля виглядає так само:
//
// 1. Ефект, що залежить від ОБʼЄКТА `user`. Теплий старт кладе в стор
//    кешований профіль, а за мить свіжий — ефект перезапускається (`databases`,
//    `db_members`). Джерельно це тримає `store-subscriptions.test.ts`; тут —
//    наслідок на дроті, бо дубль може прийти й іншим шляхом.
// 2. Секція, що МОНТУЄТЬСЯ за `!loading`. `useDatabases` стартує з
//    `loading:false`, тож «Інші доступи» вантажились на першому кадрі,
//    розмонтовувались і вантажились удруге (`realtor_subscriptions`,
//    `guest_links`).
//
// Перевіряється саме УНІКАЛЬНІСТЬ, а не кількість: число запитів законно
// зміниться з новою фічею, дубль — ні.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2026-09-01T09:00:00.000Z'
const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', landlord_name: null, created_at: NOW, updated_at: NOW,
  properties: [],
}
const PROPS = Array.from({ length: 3 }, (_, i) => ({
  id: `20000000-0000-0000-0000-${String(i).padStart(12, '0')}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс ${100 + i}`, floor: '2', status: 'free', area_useful: 40, area_total: 50,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false, folder_id: null,
  utilities: null, description: null, address: null, sale_price: null, landlord_name: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null, sort_order: i,
  created_at: NOW, updated_at: NOW, photos: [],
}))

async function backend(page: Page, hits: string[]) {
  await page.clock.setFixedTime(new Date('2026-09-15T10:00:00Z'))
  await setupApp(page, { user: USER })
  await seedSession(page, { ...USER })
  await seedSupabaseSession(page, { ...USER })
  page.on('request', (r) => {
    const u = r.url()
    if (r.method() !== 'GET' || !u.includes('/rest/v1/')) return
    hits.push(decodeURIComponent(u.replace(/^.*\/rest\/v1\//, '')))
  })
  const wantsObject = (r: { request(): { headers(): Record<string, string> } }) =>
    (r.request().headers()['accept'] ?? '').includes('object')
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, wantsObject(r) ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, wantsObject(r) ? PROPS[0] : PROPS))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'db_members', 'tenancies', 'notifications',
    'guest_links', 'realtor_subscriptions']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, wantsObject(r) ? null : []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

function duplicates(hits: string[]): string[] {
  const seen = new Map<string, number>()
  for (const h of hits) seen.set(h, (seen.get(h) ?? 0) + 1)
  return [...seen.entries()].filter(([, n]) => n > 1).map(([k, n]) => `×${n} ${k.slice(0, 90)}`)
}

test('теплий старт, вхід у базу і картка — без повторних запитів', async ({ page }) => {
  const hits: string[] = []
  await backend(page, hits)
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  // Лічильник сповіщень і префетч живуть на requestIdleCallback (таймаут 2с).
  await page.waitForTimeout(2600)
  // Антивакуум: обидві джерела колишніх дублів справді спрацювали. Без цього
  // «дублів немає» означало б «секція й не вантажилась».
  expect(hits.some((h) => h.startsWith('databases?'))).toBe(true)
  expect(hits.some((h) => h.startsWith('realtor_subscriptions?'))).toBe(true)
  expect(duplicates(hits)).toEqual([])

  hits.length = 0
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(1200)
  expect(hits.length).toBeGreaterThan(0)
  expect(duplicates(hits)).toEqual([])

  hits.length = 0
  await page.locator('.obj-card .obj-t').first().click()
  await expect(page.getByRole('button', { name: 'Редагувати обʼєкт' })).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(1200)
  expect(hits.length).toBeGreaterThan(0)
  expect(duplicates(hits)).toEqual([])
})
