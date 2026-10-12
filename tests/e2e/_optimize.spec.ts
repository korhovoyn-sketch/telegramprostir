import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession, seedSupabaseSession, jsonRoute } from './helpers/harness'

// ІНСТРУМЕНТ, не гард (`_`-префікс, `PERF=1`): цифри «до/після» для раунду
// оптимізації. Два заміри, і кожен про своє:
//
// 1. Запити теплого старту і входу в базу — дублікати й зайві round-trip-и.
// 2. Вартість ЗМІНИ СТОРУ, яка екрана не стосується. Подія `online` пише в стор
//    двічі (`isOnline` + тост), і жоден рядок списку від цього не міняється —
//    тобто вся робота скрипту тут є чистим ре-рендером підписаних компонентів.
//
// Запуск: `CI=1 PERF=1 npx playwright test _optimize --workers=1`.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2026-09-01T09:00:00.000Z'
const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', landlord_name: null, created_at: NOW, updated_at: NOW,
  properties: [], share_token: 'aabbccddeeff001122334455', share_expires_at: null,
}
const PROPS = Array.from({ length: 200 }, (_, i) => ({
  id: `20000000-0000-0000-0000-${String(i).padStart(12, '0')}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс ${100 + i}`, floor: String((i % 10) + 1), status: i % 3 === 0 ? 'free' : 'occupied',
  area_useful: 40 + i, area_total: 50 + i, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null, utilities: null,
  description: null, address: null, sale_price: null, landlord_name: null,
  tenant_name: i % 3 === 0 ? null : `ТОВ ${i}`, lease_start_date: null, lease_end_date: null,
  sort_order: i, created_at: NOW, updated_at: NOW, photos: [],
}))

async function backend(page: Page, hits: string[]) {
  await page.clock.setFixedTime(new Date('2026-09-15T10:00:00Z'))
  await setupApp(page, { user: USER })
  await seedSession(page, { ...USER })
  await seedSupabaseSession(page, { ...USER })
  page.on('request', (r) => {
    const u = r.url()
    if (!u.includes('/rest/v1/') && !u.includes('/functions/') && !u.includes('/auth/v1/')) return
    hits.push(`${r.method()} ${decodeURIComponent(u.replace(/^.*\/(rest|functions|auth)\/v1\//, '$1:')).slice(0, 110)}`)
  })
  const wantsObject = (h: Record<string, string>) => (h['accept'] ?? '').includes('object')
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, wantsObject(r.request().headers()) ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, wantsObject(r.request().headers()) ? PROPS[0] : PROPS))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'db_members', 'tenancies', 'notifications',
    'guest_links', 'realtor_subscriptions']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, wantsObject(r.request().headers()) ? null : []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

function summarize(hits: string[]) {
  const counts = new Map<string, number>()
  for (const h of hits) counts.set(h, (counts.get(h) ?? 0) + 1)
  return [...counts.entries()].map(([k, n]) => `${n > 1 ? `×${n}` : '  '} ${k}`).join('\n')
}

test('запити: теплий старт і вхід у базу', async ({ page }) => {
  test.skip(!process.env.PERF, 'інструмент')
  const hits: string[] = []
  await backend(page, hits)
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(2600) // idle-колбеки (лічильник сповіщень, префетч)
  console.log(`\n── теплий старт: ${hits.length} запитів\n${summarize(hits)}`)
  hits.length = 0
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(1500)
  console.log(`\n── вхід у базу: ${hits.length} запитів\n${summarize(hits)}`)
  hits.length = 0
  await page.locator('.obj-card .obj-t').first().click()
  await expect(page.getByRole('button', { name: 'Редагувати обʼєкт' })).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(1500)
  console.log(`\n── картка обʼєкта: ${hits.length} запитів\n${summarize(hits)}`)
})

test('ре-рендери: зміна стору, що екрана не стосується', async ({ page }) => {
  test.skip(!process.env.PERF, 'інструмент')
  await backend(page, [])
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(2500)

  const cdp = await page.context().newCDPSession(page)
  await cdp.send('Performance.enable')
  const metric = async () => {
    const { metrics } = await cdp.send('Performance.getMetrics')
    const m = Object.fromEntries(metrics.map((x) => [x.name, x.value]))
    return { script: m.ScriptDuration * 1000, task: m.TaskDuration * 1000, style: m.RecalcStyleCount, layout: m.LayoutCount }
  }
  const ROUNDS = 5
  const results: number[] = []
  for (let r = 0; r < ROUNDS; r++) {
    const a = await metric()
    await page.evaluate(async () => {
      for (let i = 0; i < 30; i++) {
        window.dispatchEvent(new Event('offline'))
        await new Promise((res) => setTimeout(res, 0))
        window.dispatchEvent(new Event('online'))
        await new Promise((res) => setTimeout(res, 0))
      }
    })
    await page.waitForTimeout(300)
    const b = await metric()
    results.push(b.script - a.script)
    console.log(`раунд ${r + 1}: script ${(b.script - a.script).toFixed(1)} мс, task ${(b.task - a.task).toFixed(1)} мс, style ${b.style - a.style}, layout ${b.layout - a.layout}`)
  }
  results.sort((x, y) => x - y)
  console.log(`МЕДІАНА script на 30 циклів offline/online: ${results[Math.floor(ROUNDS / 2)].toFixed(1)} мс`)
})
