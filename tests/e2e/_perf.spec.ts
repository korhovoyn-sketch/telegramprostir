import { test, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'

// Замір, не гард: скільки триває холодний старт і скільки в ньому ПОСЛІДОВНИХ
// round-trip-ів. Кожен запит штучно затримується — на LTE це реальність.

const LATENCY = 120
const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROPS = Array.from({ length: 25 }, (_, i) => ({
  id: `20000000-0000-0000-0000-0000000000${String(i + 10)}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс ${100 + i}`, floor: String((i % 10) + 1), status: i % 3 === 0 ? 'free' : 'occupied',
  area_useful: 40 + i, area_total: 50 + i, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null, utilities: null,
  description: null, address: null, sale_price: null,
  tenant_name: i % 3 === 0 ? null : `ТОВ ${i}`, lease_start_date: null, lease_end_date: null,
  sort_order: i, share_token: `bb000000000000000000${String(i + 10)}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}))

interface Hit { url: string; at: number }

async function slowSetup(page: Page): Promise<Hit[]> {
  const hits: Hit[] = []
  const t0 = Date.now()
  await setupApp(page, { user: USER })
  const slow = async (r: Route, body: unknown) => {
    hits.push({ url: r.request().url().replace(/^.*\/rest\/v1\//, '').slice(0, 70), at: Date.now() - t0 })
    await new Promise((res) => setTimeout(res, LATENCY))
    await r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  }
  await page.route('**/rest/v1/databases**', (r) =>
    slow(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    slow(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : PROPS))
  await page.route('**/rest/v1/users**', (r) =>
    slow(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => slow(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
  return hits
}

test('замір: холодний старт до списку баз', async ({ page }) => {
  const hits = await slowSetup(page)
  const all: string[] = []
  const t0 = Date.now()
  page.on('request', (r) => {
    const u = r.url()
    if (u.includes('/_next/') || u.endsWith('.svg')) return
    all.push(`+${String(Date.now() - t0).padStart(5)} ms  ${u.replace(/^https?:\/\/[^/]+/, '').slice(0, 60)}`)
  })
  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 30_000 })
  const tList = Date.now() - t0
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  const tCard = Date.now() - t0

  const nav = await page.evaluate(() => {
    const n = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming
    const paint = performance.getEntriesByType('paint')
    return {
      domContentLoaded: Math.round(n.domContentLoadedEventEnd),
      loadEvent: Math.round(n.loadEventEnd),
      fcp: Math.round(paint.find((p) => p.name === 'first-contentful-paint')?.startTime ?? 0),
      js: performance.getEntriesByType('resource')
        .filter((r) => r.name.endsWith('.js'))
        .reduce((s, r) => s + ((r as PerformanceResourceTiming).encodedBodySize || 0), 0),
    }
  })

  console.log('\n─── ХОЛОДНИЙ СТАРТ ───')
  console.log(`FCP:                 ${nav.fcp} ms`)
  console.log(`DOMContentLoaded:    ${nav.domContentLoaded} ms`)
  console.log(`екран «Мої бази»:    ${tList} ms`)
  console.log(`перша картка бази:   ${tCard} ms`)
  console.log(`JS завантажено:      ${Math.round(nav.js / 1024)} kB`)
  console.log(`\n─── ХВИЛЯ ЗАПИТІВ (затримка ${LATENCY}ms кожен) ───`)
  for (const h of hits) console.log(`  +${String(h.at).padStart(5)} ms  ${h.url}`)
  console.log(`усього запитів: ${hits.length}`)
  console.log('\n─── УСІ ЗАПИТИ (крім статики) ───')
  for (const a of all) console.log('  ' + a)
  const marks = await page.evaluate(() => (window as unknown as { __marks?: string[] }).__marks ?? [])
  if (marks.length) { console.log('\n─── ВІХИ ЗАСТОСУНКУ ───'); for (const m of marks) console.log('  ' + m) }
})

test('замір: перехід у базу з 25 обʼєктами', async ({ page }) => {
  const hits = await slowSetup(page)
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  hits.length = 0

  const t0 = Date.now()
  await page.getByText('БЦ Рубін').first().click()
  await page.getByText('Всі (25)').waitFor({ timeout: 30_000 })
  const tTabs = Date.now() - t0
  await page.locator('.obj-card').first().waitFor({ timeout: 30_000 })
  const tCards = Date.now() - t0

  console.log('\n─── ВХІД У БАЗУ ───')
  console.log(`вкладки:      ${tTabs} ms`)
  console.log(`перша картка: ${tCards} ms`)
  for (const h of hits) console.log(`  +${String(h.at).padStart(5)} ms  ${h.url}`)
})

test('замір: довгі задачі й кадри під час скролу списку', async ({ page }) => {
  await slowSetup(page)
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card').first().waitFor({ timeout: 30_000 })
  await page.waitForTimeout(800)

  const res = await page.evaluate(async () => {
    const long: number[] = []
    const po = new PerformanceObserver((l) => {
      for (const e of l.getEntries()) long.push(Math.round(e.duration))
    })
    try { po.observe({ entryTypes: ['longtask'] }) } catch { /* не всюди є */ }

    const frames: number[] = []
    let last = performance.now()
    let raf = 0
    const tick = () => {
      const now = performance.now()
      frames.push(now - last)
      last = now
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)

    const body = document.querySelector('.body') as HTMLElement
    for (let i = 0; i < 24; i++) {
      body.scrollTop += 60
      await new Promise((r) => setTimeout(r, 32))
    }
    cancelAnimationFrame(raf)
    po.disconnect()

    const sorted = [...frames].sort((a, b) => a - b)
    return {
      longTasks: long,
      frames: frames.length,
      medianFrame: Math.round(sorted[Math.floor(sorted.length / 2)] ?? 0),
      worstFrame: Math.round(sorted[sorted.length - 1] ?? 0),
      dropped: frames.filter((f) => f > 32).length,
      glassNodes: document.querySelectorAll('.glass,.glass-s,.glass-d').length,
    }
  })

  console.log('\n─── ПЛАВНІСТЬ СКРОЛУ (25 карток) ───')
  console.log(`кадрів:              ${res.frames}`)
  console.log(`медіанний кадр:      ${res.medianFrame} ms`)
  console.log(`найгірший кадр:      ${res.worstFrame} ms`)
  console.log(`кадрів > 32 ms:      ${res.dropped}`)
  console.log(`довгі задачі (>50ms): ${res.longTasks.length ? res.longTasks.join(', ') : 'немає'}`)
  console.log(`скляних шарів у DOM: ${res.glassNodes}`)
})

test('замір: ТЕПЛИЙ старт (кешований профіль — щоденний сценарій)', async ({ page }) => {
  const hits = await slowSetup(page)
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const all: string[] = []
  const t0 = Date.now()
  page.on('request', (r) => {
    const u = r.url()
    if (u.includes('/_next/') || u.endsWith('.svg')) return
    all.push(`+${String(Date.now() - t0).padStart(5)} ms  ${u.replace(/^https?:\/\/[^/]+/, '').slice(0, 60)}`)
  })
  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 30_000 })
  const tList = Date.now() - t0
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  const tCard = Date.now() - t0

  const fcp = await page.evaluate(() => Math.round(
    performance.getEntriesByType('paint').find((p) => p.name === 'first-contentful-paint')?.startTime ?? 0))

  console.log('\n─── ТЕПЛИЙ СТАРТ ───')
  console.log(`FCP:               ${fcp} ms`)
  console.log(`екран «Мої бази»:  ${tList} ms`)
  console.log(`перша картка:      ${tCard} ms`)
  console.log(`запитів у хвилі:   ${hits.length}`)
  for (const a of all) console.log('  ' + a)
})

test('замір: ЩО САМЕ вантажиться на теплому старті', async ({ page }) => {
  await slowSetup(page)
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  await page.waitForTimeout(600)

  const res = await page.evaluate(() => performance.getEntriesByType('resource')
    .map((r) => r as PerformanceResourceTiming)
    .filter((r) => /\.(js|css)$/.test(r.name))
    .map((r) => ({
      name: r.name.replace(/^.*\/(?:chunks\/(?:app\/)?|css\/)/, ''),
      kb: Math.round((r.encodedBodySize || r.transferSize || 0) / 102.4) / 10,
      start: Math.round(r.startTime),
    }))
    .sort((a, b) => b.kb - a.kb))

  const total = res.reduce((s, r) => s + r.kb, 0)
  console.log('\n─── РЕСУРСИ ТЕПЛОГО СТАРТУ ───')
  for (const r of res) console.log(`  ${String(r.kb).padStart(6)} kB  +${String(r.start).padStart(4)} ms  ${r.name}`)
  console.log(`  ${'─'.repeat(40)}`)
  console.log(`  ${String(Math.round(total * 10) / 10).padStart(6)} kB  усього JS+CSS`)
})

test('замір: МЕЖА — 200 обʼєктів у базі', async ({ page }) => {
  test.setTimeout(120_000)
  const BIG = Array.from({ length: 200 }, (_, i) => ({
    ...PROPS[0], id: `20000000-0000-0000-0000-${String(100000 + i)}`,
    name: `Офіс ${100 + i}`, sort_order: i,
    status: i % 3 === 0 ? 'free' : 'occupied',
    tenant_name: i % 3 === 0 ? null : `ТОВ ${i}`,
  }))
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? BIG[0] : BIG))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 30_000 })
  const t0 = Date.now()
  await page.getByText('БЦ Рубін').first().click()
  await page.getByText('Всі (200)').waitFor({ timeout: 30_000 })
  const tTabs = Date.now() - t0
  await page.locator('.obj-card').first().waitFor({ timeout: 30_000 })
  const tCards = Date.now() - t0
  await page.waitForTimeout(700)

  const res = await page.evaluate(async () => {
    const long: number[] = []
    const po = new PerformanceObserver((l) => { for (const e of l.getEntries()) long.push(Math.round(e.duration)) })
    try { po.observe({ entryTypes: ['longtask'] }) } catch { /* нема */ }
    const frames: number[] = []
    let last = performance.now(); let raf = 0
    const tick = () => { const n = performance.now(); frames.push(n - last); last = n; raf = requestAnimationFrame(tick) }
    raf = requestAnimationFrame(tick)
    const body = document.querySelector('.body') as HTMLElement
    for (let i = 0; i < 40; i++) { body.scrollTop += 200; await new Promise((r) => setTimeout(r, 24)) }
    cancelAnimationFrame(raf); po.disconnect()
    const sorted = [...frames].sort((a, b) => a - b)
    return {
      cardsInDom: document.querySelectorAll('.obj-card').length,
      glass: document.querySelectorAll('.glass,.glass-s,.glass-d').length,
      domNodes: document.querySelectorAll('*').length,
      medianFrame: Math.round(sorted[Math.floor(sorted.length / 2)] ?? 0),
      p95: Math.round(sorted[Math.floor(sorted.length * 0.95)] ?? 0),
      worst: Math.round(sorted[sorted.length - 1] ?? 0),
      dropped: frames.filter((f) => f > 32).length,
      total: frames.length,
      longTasks: long,
    }
  })

  console.log('\n─── 200 ОБʼЄКТІВ ───')
  console.log(`вкладки:            ${tTabs} ms`)
  console.log(`перша картка:       ${tCards} ms`)
  console.log(`карток у DOM:       ${res.cardsInDom}`)
  console.log(`скляних шарів:      ${res.glass}`)
  console.log(`вузлів DOM:         ${res.domNodes}`)
  console.log(`медіанний кадр:     ${res.medianFrame} ms`)
  console.log(`p95 кадр:           ${res.p95} ms`)
  console.log(`найгірший кадр:     ${res.worst} ms`)
  console.log(`кадрів > 32ms:      ${res.dropped} з ${res.total}`)
  console.log(`довгі задачі:       ${res.longTasks.length ? res.longTasks.join(', ') : 'немає'}`)
  const h = await page.evaluate(() => {
    const cards = [...document.querySelectorAll('.obj-card')].slice(0, 40) as HTMLElement[]
    const hs = cards.map((c) => Math.round(c.getBoundingClientRect().height)).sort((a, b) => a - b)
    return { min: hs[0], median: hs[Math.floor(hs.length / 2)], max: hs[hs.length - 1] }
  })
  console.log(`висота картки:      min ${h.min} / median ${h.median} / max ${h.max} px`)
})
