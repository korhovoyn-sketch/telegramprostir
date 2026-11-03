import { test, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

/**
 * ІНСТРУМЕНТ (не гард): аудит акордеона папок.
 *   CI=1 PERF=1 npx playwright test _fold-audit --workers=1
 *
 * Друкує JSON по кожному сценарію (рядок `FOLD_AUDIT`): покадрова ВИДИМА
 * висота тіла (частина, що влазить у скролер), кут стрілки, тап по заголовку
 * під час пошуку, порожня папка, позиція заголовка при згортанні й повторному
 * розгортанні внизу сторінки, зона дотику заголовка.
 *
 * Ручки для розслідувань:
 *   ONLY_BOTTOM=1        лише сценарій «внизу сторінки»;
 *   START_COLLAPSED=1    ...і стартувати там зі згорнутої секції (без
 *                        попереднього згортання — інший випадок якоріння);
 *   EXTRA_CSS='…'        домішати CSS перед заміром (напр. `overflow-anchor`).
 */

test.use({ contextOptions: { reducedMotion: 'no-preference' } })

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const A = '40000000-0000-0000-0000-0000000000a1'
const B = '40000000-0000-0000-0000-0000000000b1'
const C = '40000000-0000-0000-0000-0000000000c1'
const NOW = new Date().toISOString()
const DB = { id: DB_ID, owner_id: USER.id, name: 'Міком Палац', address: 'a', type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455', share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [] }
function prop(n: number, folder: string | null) {
  return { id: `20000000-0000-0000-0000-0000000000${String(n).padStart(2, '0')}`, db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n), status: 'occupied', area_useful: 292, area_total: 324, area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false, folder_id: folder, utilities: null, description: null, address: null, sale_price: null, tenant_name: 'ФОП Бригинець', lease_start_date: '2025-07-01', lease_end_date: '2027-06-30', sort_order: n, share_token: `bb00000000000000000${String(n).padStart(5, '0')}`, share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [] }
}
const PROPERTIES = [
  ...Array.from({ length: 8 }, (_, i) => prop(i + 1, A)),
  prop(9, B),
  prop(10, null), prop(11, null),
]
const FOLDERS = [
  { id: A, db_id: DB_ID, owner_id: USER.id, name: 'Великий', sort_order: 100, created_at: NOW, updated_at: NOW },
  { id: B, db_id: DB_ID, owner_id: USER.id, name: 'Малий', sort_order: 200, created_at: NOW, updated_at: NOW },
  { id: C, db_id: DB_ID, owner_id: USER.id, name: 'Порожній', sort_order: 300, created_at: NOW, updated_at: NOW },
]
const KEY = `ps:foldCollapse:${USER.id}:${DB_ID}`

async function open(page: Page, collapsed: string[] = []) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, PROPERTIES))
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, FOLDERS))
  await page.route('**/rest/v1/db_members**', (r) => jsonRoute(r, []))
  await page.addInitScript(([k, v]) => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
    if (!sessionStorage.getItem('__seeded')) { localStorage.setItem(k, v); sessionStorage.setItem('__seeded', '1') }
  }, [KEY, JSON.stringify(collapsed)])
  await page.goto('/')
  await page.getByText('Міком Палац').first().click()
  await page.getByText('Всі (11)').waitFor()
  await page.locator('.fold-hd', { hasText: 'Порожній' }).waitFor()
  await page.waitForTimeout(800)
}

/** Тапає заголовок секції `name` і пише покадрово: висоту тіла, видиму частину, верх заголовка. */
function profile(page: Page, name: string, frames = 26) {
  return page.evaluate(async ({ name, frames }) => {
    const hd = [...document.querySelectorAll('.fold-hd')].find((h) => h.textContent?.includes(name)) as HTMLElement
    const wrap = document.getElementById(hd.getAttribute('aria-controls')!)!
    const scroller = hd.closest('.body') as HTMLElement
    const sr = scroller.getBoundingClientRect()
    const vis = () => {
      const r = wrap.getBoundingClientRect()
      return Math.max(0, Math.min(r.bottom, sr.bottom) - Math.max(r.top, sr.top))
    }
    const chev = hd.querySelector('.fold-hd-chev') as HTMLElement
    const ang = () => { const m = new DOMMatrix(getComputedStyle(chev).transform); return Math.round(Math.atan2(m.b, m.a) * 180 / Math.PI) }
    const out: { t: number; h: number; vis: number; hdTop: number; scroll: number; chev: number }[] = []
    const t0 = performance.now()
    out.push({ t: 0, h: Math.round(wrap.getBoundingClientRect().height), vis: Math.round(vis()), hdTop: Math.round(hd.getBoundingClientRect().top), scroll: scroller.scrollTop, chev: ang() })
    hd.click()
    for (let i = 0; i < frames; i++) {
      await new Promise((r) => requestAnimationFrame(() => r(null)))
      out.push({ t: Math.round(performance.now() - t0), h: Math.round(wrap.getBoundingClientRect().height), vis: Math.round(vis()), hdTop: Math.round(hd.getBoundingClientRect().top), scroll: Math.round(scroller.scrollTop), chev: ang() })
    }
    const steps = out.slice(1).map((f, i) => Math.abs(f.vis - out[i].vis))
    return { viewport: Math.round(sr.height), maxVisStep: Math.max(...steps), firstVisStep: steps[0], frames: out }
  }, { name, frames })
}

test('акордеон: заміри', async ({ page }) => {
  test.setTimeout(180_000)
  const log: Record<string, unknown> = {}

  if (!process.env.ONLY_BOTTOM) {
  // 1. Розгортання і згортання великої й малої папки (стартують згорнутими).
  await open(page, [A, B])
  log.expandBig = await profile(page, 'Великий')
  await page.waitForTimeout(500)
  log.collapseBig = await profile(page, 'Великий')
  await page.waitForTimeout(500)
  log.expandSmall = await profile(page, 'Малий')
  await page.waitForTimeout(500)
  log.collapseSmall = await profile(page, 'Малий')

  // 2. Заголовок: геометрія і зона дотику.
  log.header = await page.evaluate(() => {
    const hd = document.querySelector('.fold-hd') as HTMLElement
    const r = hd.getBoundingClientRect()
    return { w: Math.round(r.width), h: Math.round(r.height * 10) / 10 }
  })

  // 3. Порожня папка: що в тілі після розгортання.
  await page.goto('/')
  await open(page, [])
  log.empty = await page.evaluate(() => {
    const hd = [...document.querySelectorAll('.fold-hd')].find((h) => h.textContent?.includes('Порожній')) as HTMLElement
    const wrap = document.getElementById(hd.getAttribute('aria-controls')!)!
    return { expanded: hd.getAttribute('aria-expanded'), bodyH: Math.round(wrap.getBoundingClientRect().height), text: wrap.textContent, children: wrap.firstElementChild?.childElementCount }
  })

  // 4. Тап під час пошуку.
  const before = await page.evaluate((k) => localStorage.getItem(k), KEY)
  await page.getByPlaceholder('Пошук обʼєкту...').fill('Офіс')
  await page.waitForTimeout(400)
  const hdA = page.locator('.fold-hd', { hasText: 'Великий' })
  const expBefore = await hdA.getAttribute('aria-expanded')
  await hdA.click()
  await page.waitForTimeout(400)
  const expAfter = await hdA.getAttribute('aria-expanded')
  const lsAfter = await page.evaluate((k) => localStorage.getItem(k), KEY)
  await page.getByPlaceholder('Пошук обʼєкту...').fill('')
  await page.waitForTimeout(600)
  const expCleared = await hdA.getAttribute('aria-expanded')
  log.search = { lsBefore: before, expBefore, expAfter, lsAfter, expAfterClear: expCleared }

  // 5. Згортання великої папки, прокрученої до кінця.
  await page.evaluate((k) => localStorage.setItem(k, '[]'), KEY)
  await page.goto('/')
  await open(page, [])
  await page.evaluate(() => { const b = document.querySelector('.body') as HTMLElement; b.scrollTop = b.scrollHeight })
  await page.waitForTimeout(300)
  log.collapseScrolled = await page.evaluate(async () => {
    const hd = [...document.querySelectorAll('.fold-hd')].find((h) => h.textContent?.includes('Великий')) as HTMLElement
    const b = document.querySelector('.body') as HTMLElement
    const sr = b.getBoundingClientRect()
    // прокрутити так, щоб заголовок «Великий» був угорі вʼюпорта, а тіло — під ним
    b.scrollTop += hd.getBoundingClientRect().top - sr.top - 8
    await new Promise((r) => setTimeout(r, 200))
    const top0 = hd.getBoundingClientRect().top
    hd.click()
    await new Promise((r) => setTimeout(r, 600))
    return { scrollH: b.scrollHeight, client: b.clientHeight, top0: Math.round(top0), top1: Math.round(hd.getBoundingClientRect().top), scroll: b.scrollTop }
  })

  }
  // 5б. Згортання ОСТАННЬОЇ секції, коли сторінка прокручена до низу.
  await page.goto('/')
  await open(page, process.env.ONLY_BOTTOM ? (process.env.START_COLLAPSED ? [A, '__none__'] : [A]) : [])
  await page.evaluate(() => { const b = document.querySelector('.body') as HTMLElement; b.scrollTop = b.scrollHeight })
  await page.waitForTimeout(300)
  if (process.env.EXTRA_CSS) await page.addStyleTag({ content: process.env.EXTRA_CSS })
  if (!process.env.START_COLLAPSED) log.collapseLastAtBottom = await profile(page, 'Без папки')
  await page.waitForTimeout(500)
  log.expandLastAtBottom = await profile(page, 'Без папки')

  // 6. Під час руху: що фокусне всередині тіла і чи кільце фокуса не зрізане.
  log.focusInside = await page.evaluate(() => {
    const wrap = document.querySelector('.fold-wrap') as HTMLElement
    const f = wrap.querySelectorAll('button, a, input, [tabindex]')
    return { focusables: f.length, overflow: getComputedStyle(wrap).overflow }
  })

  console.log('FOLD_AUDIT ' + JSON.stringify(log, null, 1))
})
