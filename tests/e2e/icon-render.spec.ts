import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'

/**
 * Іконки по РЕНДЕРУ, не по джерелу.
 *
 * `tests/unit/icon-system.test.ts` тримає дисципліну джерела: одна база `<Icon>`,
 * розміри зі шкали, ніяких власних `<svg>` поза allowlist. Чого він не бачить:
 * чи іконка справді МАЛЮЄТЬСЯ. Порожній `<Icon>` без дітей, шлях, що вилазить за
 * viewBox і обрізається viewport-ом, товщина обведення, задана руками повз
 * `strokeFor(size)` — усе це валідний TSX і зламана картинка.
 */

const NOW = '2025-09-01T09:00:00.000Z'
const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'

const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROPS = [1, 2].map((i) => ({
  id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс 10${i}`, floor: String(i), status: i === 1 ? 'occupied' : 'free',
  area_useful: 100, area_total: 120, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: true, parking_spaces: 2,
  parking_type: 'covered', ev_charger: true, folder_id: null,
  utilities: null, description: 'Світлий офіс.', address: null, sale_price: 250000,
  tenant_name: i === 1 ? 'ТОВ «Ромашка»' : null, lease_start_date: '2025-01-01',
  lease_end_date: '2026-01-01', sort_order: i,
  share_token: `bb0000000000000000001${i}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
}))

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : PROPS))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

interface IconInfo {
  cls: string
  /** Оголошений розмір (атрибут), а НЕ бокс: `.fab` масштабує іконку анімацією
   *  появи, тож бокс під час неї 23–25px при `size={20}` — це рух, не дефект. */
  size: number
  /** Оголошена висота — квадратність перевіряється по атрибутах, не по боксу. */
  sizeH: number
  viewBox: string
  stroke: string
  kids: number
  /** Геометрія в користувацьких координатах — чи вміщується у viewBox. */
  bbox: { x: number; y: number; w: number; h: number } | null
}

/** Усі іконки бібліотеки, що зараз у DOM. */
const icons = (page: Page) => page.evaluate<IconInfo[]>(() =>
  [...document.querySelectorAll('svg.ico')].map((el) => {
    const svg = el as SVGSVGElement
    let bbox: IconInfo['bbox'] = null
    try {
      const b = svg.getBBox()
      bbox = { x: b.x, y: b.y, w: b.width, h: b.height }
    } catch { /* нульова геометрія кидає в деяких рушіях */ }
    return {
      cls: svg.getAttribute('class') ?? '',
      size: Number(svg.getAttribute('width')),
      sizeH: Number(svg.getAttribute('height')),
      viewBox: svg.getAttribute('viewBox') ?? '',
      stroke: svg.getAttribute('stroke-width') ?? '',
      kids: svg.querySelectorAll('path,polyline,line,circle,rect,polygon,ellipse').length,
      bbox,
    }
  }))

/** Обхід екранів, де іконок найбільше. */
async function walk(page: Page, visit: (label: string) => Promise<void>) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await visit('db-list')

  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
  await visit('db-objects')

  await page.locator('.obj-card').first().locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
  await visit('property-detail')

  await page.locator('.hdr-back').click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
  await page.locator('.fbtn').click()
  await expect(page.getByText('Новий об\'єкт')).toBeVisible({ timeout: 15_000 })
  await visit('property-form')

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
  await visit('profile')

  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await page.waitForTimeout(500)
  await visit('notifications')
}

test('кожна відрендерена іконка малюється і не обрізана', async ({ page }) => {
  test.setTimeout(150_000)
  await setup(page)

  const empty: string[] = []
  const badViewBox: string[] = []
  const clipped: string[] = []
  const notSquare: string[] = []
  let total = 0

  await walk(page, async (label) => {
    for (const i of await icons(page)) {
      total++
      if (i.kids === 0) empty.push(`${label}: .${i.cls} без жодного шляху`)
      if (i.viewBox !== '0 0 24 24') badViewBox.push(`${label}: .${i.cls} viewBox="${i.viewBox}"`)
      if (!Number.isFinite(i.size) || i.size !== i.sizeH) {
        notSquare.push(`${label}: .${i.cls} ${i.size}×${i.sizeH}`)
      }
      // Геометрія за межами viewBox обрізається viewport-ом SVG — саме так
      // виглядає «гігантський обрізаний гліф», який уже ловили на герої обʼєкта.
      // Півпіксельний допуск: округлення координат кривих.
      if (i.bbox && i.size > 0) {
        const b = i.bbox
        if (b.x < -0.5 || b.y < -0.5 || b.x + b.w > 24.5 || b.y + b.h > 24.5) {
          clipped.push(`${label}: .${i.cls} геометрія [${b.x.toFixed(1)},${b.y.toFixed(1)} ${b.w.toFixed(1)}×${b.h.toFixed(1)}] за межами viewBox 24`)
        }
      }
    }
  })

  expect(total, 'жодної іконки не знайдено — селектор .ico застарів').toBeGreaterThan(50)
  expect([...new Set(empty)], 'порожня іконка: <Icon> без дітей').toEqual([])
  expect([...new Set(badViewBox)], 'viewBox іконки мусить бути 0 0 24 24').toEqual([])
  expect([...new Set(notSquare)], 'іконка не квадратна — width ≠ height').toEqual([])
  expect([...new Set(clipped)], 'іконка обрізана межами viewBox').toEqual([])
})

test('товщина обведення виводиться з розміру, а не пишеться руками', async ({ page }) => {
  test.setTimeout(150_000)
  await setup(page)
  // `strokeFor`: 2px до 24px, 1.7px від 24px — оптична вага. Захардкоджена
  // товщина ламає саме те, для чого правило й існує: іконка 26px з 2px читається
  // важчою за сусідню 20px.
  const wrong = new Set<string>()
  const sizes = new Set<number>()

  await walk(page, async (label) => {
    for (const i of await icons(page)) {
      if (!i.size) continue
      sizes.add(i.size)
      const expected = i.size >= 24 ? '1.7' : '2'
      // `strokeWidth="0"` — залитий гліф, свідомий виняток бібліотеки.
      if (i.stroke !== '0' && i.stroke !== expected) {
        wrong.add(`${label}: .${i.cls} ${i.size}px має stroke-width=${i.stroke}, очікується ${expected}`)
      }
    }
  })

  expect([...wrong]).toEqual([])
  // Шкала парних розмірів: 2px обведення на непарному боксі дає півпіксельні краї.
  const odd = [...sizes].filter((s) => s % 2 !== 0)
  expect(odd, `непарні розміри іконок у рендері: ${odd.join(',')}`).toEqual([])
})
