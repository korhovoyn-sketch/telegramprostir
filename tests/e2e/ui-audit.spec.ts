import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// UI/UX regression audit під ворожими даними (дуже довгі назви, величезні суми)
// з програмними інваріантами, а не лише скріншотами:
//   • нуль горизонтального скролу сторінки;
//   • жоден бокс не вилазить за в'юпорт (крім навмисних h-скролерів);
//   • цілі тапу ≥32px (WCAG 2.5.8 AA — 24px, беремо із запасом);
//   • останній елемент списку не під FAB/таббаром;
//   • числові значення (гроші/тотали) НЕ обрізані — ловило «₴149 99…».

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', currency: 'UAH' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const F1 = '40000000-0000-0000-0000-0000000000a1'
const NOW = new Date().toISOString()

const LONG_NAME = 'Офіс представництва компанії «Український Промисловий Альянс Інвест Груп» блок Б'
const LONG_TENANT = 'ТОВ «Науково-виробниче об\'єднання Агропромислові Технології України»'
// Довгий рядок БЕЗ пробілів — окремий клас, якого фікстури вище не відтворюють:
// вони довгі, але переносяться по словах, тож жодного разу не перевіряли, що
// станеться з тим, чого перенести НІЧИМ. А саме таке користувач вставляє
// найчастіше — посилання, e-mail, кадастровий номер, назву з буфера без пробілів.
// Проти цього в CSS існував рівно один захист (`.link-mono`), тобто носії імен
// (назва бази, обʼєкта, орендаря, папки) не мали жодного.
const UNBREAKABLE = 'https://maps.example.com/place/1234567890abcdefghijklmnop'

const DB = {
  id: DB_ID, owner_id: USER.id,
  name: 'Багатофункціональний бізнес-центр «Рубін Плаза» на Хрещатику',
  address: 'вул. Велика Васильківська 100-А, корпус 3, поверх 12, офіс 1201',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, o: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-0000000000${String(n).padStart(2, '0')}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n),
    status: 'occupied', area_useful: 197.7, area_total: 219.2, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: 13, utilities_rate: 2.5,
    has_parking: true, parking_spaces: 2, parking_type: null, ev_charger: false,
    folder_id: null, utilities: ['water', 'power'], description: null, address: null,
    sale_price: null, tenant_name: 'ТОВ Тест',
    lease_start_date: '2026-04-22', lease_end_date: '2029-02-28',
    sort_order: n, share_token: `bb000000000000000000${String(n).padStart(4, '0')}`,
    share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [],
    ...o,
  }
}

const PROPERTIES = [
  // Stress row: very long name + long tenant + huge money
  prop(1, { name: LONG_NAME, tenant_name: LONG_TENANT, folder_id: F1, rent_rate: 9999, area_useful: 12345.6, area_total: 15000.9, parking_spaces: 150 }),
  prop(2, { folder_id: F1 }),
  prop(3, { status: 'free', tenant_name: null, lease_start_date: null, lease_end_date: null, rent_rate: 18 }),
  prop(4, { status: 'for_sale', tenant_name: null, lease_start_date: null, lease_end_date: null, sale_price: 12500000 }),
  prop(5, { name: UNBREAKABLE, tenant_name: UNBREAKABLE, address: UNBREAKABLE, description: UNBREAKABLE }),
]

const FOLDERS = [
  { id: F1, db_id: DB_ID, owner_id: USER.id, name: 'Перший поверх — комерційні приміщення та шоуруми', sort_order: 100, created_at: NOW, updated_at: NOW },
]

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() !== 'GET') return r.fallback()
    if ((rq.headers()['accept'] ?? '').includes('object')) {
      const m = rq.url().match(/id=eq\.([0-9a-f-]+)/)
      return jsonRoute(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return jsonRoute(r, PROPERTIES)
  })
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, FOLDERS))
  await page.route('**/rest/v1/property_files**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/rent_payments**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/property_views**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/db_members**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/notifications**', (r) => jsonRoute(r, []))
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** No element may push the page sideways. */
async function noHScroll(page: Page, label: string) {
  const o = await page.evaluate(() => ({
    doc: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
    inner: window.innerWidth,
  }))
  expect(o.doc, `${label}: html scrollWidth`).toBeLessThanOrEqual(o.inner + 1)
  expect(o.body, `${label}: body scrollWidth`).toBeLessThanOrEqual(o.inner + 1)
}

/** Any element whose own box escapes the viewport horizontally. */
async function noEscapingBoxes(page: Page, label: string) {
  const bad = await page.evaluate(() => {
    const out: { cls: string; text: string; right: number; left: number }[] = []
    const vw = window.innerWidth
    document.querySelectorAll<HTMLElement>('.scr *').forEach((el) => {
      const s = getComputedStyle(el)
      if (s.display === 'none' || s.visibility === 'hidden' || s.position === 'fixed') return
      // skip nodes inside a horizontally-scrollable container (intentional)
      let p: HTMLElement | null = el.parentElement
      while (p) {
        const ps = getComputedStyle(p)
        if (ps.overflowX === 'auto' || ps.overflowX === 'scroll') return
        p = p.parentElement
      }
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return
      if (r.right > vw + 1 || r.left < -1) {
        out.push({ cls: el.className?.toString().slice(0, 40) ?? '', text: (el.textContent ?? '').slice(0, 30), right: Math.round(r.right), left: Math.round(r.left) })
      }
    })
    return out.slice(0, 8)
  })
  expect(bad, `${label}: elements escaping viewport → ${JSON.stringify(bad)}`).toEqual([])
}

/** Interactive controls must be comfortably tappable (iOS HIG 44, allow 36 for chips). */
async function tapTargets(page: Page, label: string, min = 32) {
  const small = await page.evaluate((min) => {
    const out: { cls: string; text: string; w: number; h: number }[] = []
    document.querySelectorAll<HTMLElement>('button,[role="button"],a[href],input[type="checkbox"]').forEach((el) => {
      const s = getComputedStyle(el)
      if (s.display === 'none' || s.visibility === 'hidden' || (el as HTMLButtonElement).disabled) return
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return
      if (r.height < min || r.width < min) {
        out.push({ cls: el.className?.toString().slice(0, 36) ?? '', text: (el.textContent ?? '').trim().slice(0, 24), w: Math.round(r.width), h: Math.round(r.height) })
      }
    })
    return out.slice(0, 10)
  }, min)
  expect(small, `${label}: tap targets under ${min}px → ${JSON.stringify(small)}`).toEqual([])
}

/** Last list item must not sit under the fixed FAB / tabbar. */
async function noOcclusion(page: Page, label: string) {
  const res = await page.evaluate(() => {
    const items = [...document.querySelectorAll<HTMLElement>('.list > *, .list .obj-card, .list .row')]
    const last = items[items.length - 1]
    if (!last) return null
    const lr = last.getBoundingClientRect()
    const fab = document.querySelector<HTMLElement>('.fbtn')
    const bar = document.querySelector<HTMLElement>('.tabbar')
    const overlaps = (a: DOMRect, b?: DOMRect | null) =>
      !!b && a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top
    return {
      overFab: overlaps(lr, fab?.getBoundingClientRect()),
      overBar: overlaps(lr, bar?.getBoundingClientRect()),
    }
  })
  if (!res) return
  expect(res.overFab, `${label}: last item under the FAB`).toBe(false)
  expect(res.overBar, `${label}: last item under the tabbar`).toBe(false)
}

async function openObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText(/Рубін Плаза/).first().click()
  await expect(page.getByText('Всі (5)')).toBeVisible()
  await page.waitForTimeout(600)
}

// ── Screens under hostile data ───────────────────────────────────────────────

test('QA: db-list with long names', async ({ page }, ti) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(400)
  await noHScroll(page, 'db-list')
  await noEscapingBoxes(page, 'db-list')
  await tapTargets(page, 'db-list')
  await page.screenshot({ path: ti.outputPath('db-list.png') })
})

test('QA: db-objects cards with long names + big numbers', async ({ page }, ti) => {
  await setup(page)
  await openObjects(page)
  await noHScroll(page, 'objects')
  await noEscapingBoxes(page, 'objects')
  await tapTargets(page, 'objects')
  // KPI numbers must never be clipped — you have to be able to read your income.
  const clipped = await page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>('.dash-n, .obj-tot-v, .row-tot')]
      .filter(el => el.scrollWidth > el.clientWidth + 1)
      .map(el => ({ cls: el.className, text: el.textContent, sw: el.scrollWidth, cw: el.clientWidth })))
  expect(clipped, `clipped numeric values → ${JSON.stringify(clipped)}`).toEqual([])
  await page.screenshot({ path: ti.outputPath('objects-cards.png'), fullPage: true })
  // scroll to the bottom of the internal body and re-check occlusion
  await page.locator('.body').evaluate((el) => { el.scrollTop = el.scrollHeight })
  await page.waitForTimeout(400)
  await noOcclusion(page, 'objects bottom')
  await page.screenshot({ path: ti.outputPath('objects-bottom.png') })
})

test('QA: compact list with long names', async ({ page }, ti) => {
  await setup(page)
  await openObjects(page)
  await page.getByLabel('Компактно').click()
  await page.waitForTimeout(400)
  await noHScroll(page, 'compact')
  await noEscapingBoxes(page, 'compact')
  await page.screenshot({ path: ti.outputPath('compact.png'), fullPage: true })
})

test('QA: property detail with long tenant + big money', async ({ page }, ti) => {
  await setup(page)
  await openObjects(page)
  await page.locator('.obj-t').first().click()
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible()
  await page.waitForTimeout(500)
  await noHScroll(page, 'detail')
  await noEscapingBoxes(page, 'detail')
  await tapTargets(page, 'detail')
  await page.screenshot({ path: ti.outputPath('detail.png'), fullPage: true })
})

test('QA: folder modal with a very long folder name', async ({ page }, ti) => {
  await setup(page)
  await openObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText('Групуйте').first()).toBeVisible()
  await page.waitForTimeout(500)
  await noHScroll(page, 'folder-modal')
  await tapTargets(page, 'folder-modal')
  // modal must not overflow sideways either
  const mo = await page.evaluate(() => {
    const m = document.querySelector('.modal') as HTMLElement
    const r = m.getBoundingClientRect()
    return { left: Math.round(r.left), right: Math.round(r.right), vw: window.innerWidth,
             scrollW: m.scrollWidth, clientW: m.clientWidth }
  })
  expect(mo.left, 'modal left edge').toBeGreaterThanOrEqual(-1)
  expect(mo.right, 'modal right edge').toBeLessThanOrEqual(mo.vw + 1)
  expect(mo.scrollW, 'modal inner h-overflow').toBeLessThanOrEqual(mo.clientW + 1)
  await page.screenshot({ path: ti.outputPath('folder-modal.png') })
})

test('QA: property form long values + all sections', async ({ page }, ti) => {
  await setup(page)
  await openObjects(page)
  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()
  await page.waitForTimeout(500)
  await noHScroll(page, 'form')
  await noEscapingBoxes(page, 'form')
  await tapTargets(page, 'form')
  await page.screenshot({ path: ti.outputPath('form.png'), fullPage: true })
})

test('QA: empty database state', async ({ page }, ti) => {
  await setup(page)
  await page.route('**/rest/v1/properties**', (r) =>
    r.request().method() === 'GET' ? jsonRoute(r, []) : r.fallback())
  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, []))
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText(/Рубін Плаза/).first().click()
  await expect(page.getByText('Всі (0)')).toBeVisible()
  await page.waitForTimeout(400)
  await noHScroll(page, 'empty')
  await noEscapingBoxes(page, 'empty')
  await page.screenshot({ path: ti.outputPath('empty.png') })
})
