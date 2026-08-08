import { test, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'
import sharp from 'sharp'

/**
 * Замір КОНТРАСТУ тексту, як його бачить око, а не як записано в токенах.
 *
 * Аналітично тут не порахувати: увесь текст — біле з альфою (.46–.72), а під ним
 * шари скла над градієнтом, який СВІТЛІШАЄ донизу (низ `.bg-blue` — це #5480dc).
 * Тож фон беремо з реального рендера: знімок робиться двічі — звичайний і з
 * прозорим текстом. Другий дає чистий фон, у ньому й усереднюємо пікселі під
 * кожним текстовим блоком.
 *
 * Не гард (не входить у прогін): друкує таблицю найгірших місць.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 10 поверху ( мале крило )', floor: '10', status: 'occupied',
  area_useful: 175.8, area_total: 195.13, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 12.8, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null,
  utilities: ['electricity', 'water', 'heating', 'gas'], description: 'Світлий офіс.',
  address: 'Дегтярівська 27-Т', sale_price: null, tenant_name: 'Фоп Плотко',
  lease_start_date: '2025-08-15', lease_end_date: '2026-08-31',
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
}

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

interface TextBox {
  text: string
  cls: string
  color: [number, number, number, number]
  size: number
  weight: number
  x: number; y: number; w: number; h: number
}

/** Видимі текстові блоки з їхнім кольором і геометрією. */
const textBoxes = (page: Page) => page.evaluate((): TextBox[] => {
  const out: TextBox[] = []
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  const seen = new Set<Element>()
  let n: Node | null
  while ((n = walker.nextNode())) {
    const txt = (n.textContent ?? '').trim()
    if (txt.length < 2) continue
    const el = n.parentElement
    if (!el || seen.has(el)) continue
    seen.add(el)
    const r = el.getBoundingClientRect()
    if (r.width < 6 || r.height < 6 || r.top < 0 || r.bottom > window.innerHeight) continue
    const cs = getComputedStyle(el)
    if (cs.visibility === 'hidden' || cs.opacity === '0') continue
    const m = cs.color.match(/[\d.]+/g)
    if (!m) continue
    out.push({
      text: txt.slice(0, 28),
      cls: el.className?.toString().slice(0, 22) || el.tagName.toLowerCase(),
      color: [Number(m[0]), Number(m[1]), Number(m[2]), m[3] === undefined ? 1 : Number(m[3])],
      size: Math.round(parseFloat(cs.fontSize)),
      weight: Number(cs.fontWeight) || 400,
      x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height),
    })
  }
  return out
})

const lum = (r: number, g: number, b: number) => {
  const f = (v: number) => {
    const s = v / 255
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
  }
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
const ratio = (a: number, b: number) => (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)

async function audit(page: Page, label: string) {
  const boxes = await textBoxes(page)
  // Другий знімок — той самий кадр, але БЕЗ тексту: дає чистий фон під літерами.
  await page.addStyleTag({ content: '*{color:transparent !important;text-shadow:none !important}' })
  const bg = await page.screenshot()
  const { data, info } = await sharp(bg).ensureAlpha().raw().toBuffer({ resolveWithObject: true })
  const scale = info.width / (page.viewportSize()?.width ?? 375)

  const rows: { r: number; text: string; cls: string; size: number; weight: number }[] = []
  for (const b of boxes) {
    let sr = 0, sg = 0, sb = 0, cnt = 0
    const x0 = Math.max(0, Math.round(b.x * scale)), x1 = Math.min(info.width, Math.round((b.x + b.w) * scale))
    const y0 = Math.max(0, Math.round(b.y * scale)), y1 = Math.min(info.height, Math.round((b.y + b.h) * scale))
    for (let y = y0; y < y1; y += 2) {
      for (let x = x0; x < x1; x += 2) {
        const i = (y * info.width + x) * info.channels
        sr += data[i]; sg += data[i + 1]; sb += data[i + 2]; cnt++
      }
    }
    if (!cnt) continue
    const [br, bgc, bb] = [sr / cnt, sg / cnt, sb / cnt]
    // Текст із альфою компонується на цей фон.
    const a = b.color[3]
    const tr = b.color[0] * a + br * (1 - a)
    const tg = b.color[1] * a + bgc * (1 - a)
    const tb = b.color[2] * a + bb * (1 - a)
    rows.push({
      r: Math.round(ratio(lum(tr, tg, tb), lum(br, bgc, bb)) * 100) / 100,
      text: b.text, cls: b.cls, size: b.size, weight: b.weight,
    })
  }

  // WCAG AA: 4.5 для звичайного тексту, 3.0 для «великого» (≥18.66px bold або ≥24px).
  const need = (s: number, w: number) => (s >= 24 || (s >= 18.66 && w >= 700) ? 3 : 4.5)
  const bad = rows.filter((x) => x.r < need(x.size, x.weight)).sort((a, b) => a.r - b.r)
  console.log(`\n─── ${label}: ${rows.length} текстових блоків, нижче AA — ${bad.length} ───`)
  for (const x of bad.slice(0, 12)) {
    console.log(`  ${String(x.r).padStart(5)}:1  (треба ${need(x.size, x.weight)})  ${String(x.size).padStart(2)}px/${x.weight}  «${x.text}»  .${x.cls}`)
  }
}

test('контраст: екрани власника', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)

  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  await page.waitForTimeout(700)
  await audit(page, 'db-list')

  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'db-objects')

  await page.goto('/')
  await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await page.getByRole('button', { name: /Звільнити/ }).waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'property-detail')

  await page.goto('/')
  await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await audit(page, 'profile')
})

/**
 * Тап-таргети проти Apple HIG (44×44). Наш гард в `ui-audit` стоїть на 32 —
 * тобто на 12px лояльніше за стандарт, який проєкт сам цитує в коді. Тут видно
 * реальний розрив: що саме менше за 44 і наскільки.
 */
const smallTargets = (page: Page, min: number) => page.evaluate((m) => {
  const out: { cls: string; label: string; w: number; h: number }[] = []
  document.querySelectorAll('button,[role="button"],a,input[type="checkbox"],.sheet-row,.notif-tab,.seg-b,.fr-seg-b,.tab,.obj-act-btn').forEach((el) => {
    const e = el as HTMLElement
    const r = e.getBoundingClientRect()
    if (r.width < 4 || r.height < 4) return
    if (r.top < 0 || r.bottom > window.innerHeight) return
    if (getComputedStyle(e).visibility === 'hidden') return
    if (r.width < m || r.height < m) {
      out.push({
        cls: e.className?.toString().slice(0, 24) || e.tagName.toLowerCase(),
        label: (e.getAttribute('aria-label') || e.textContent || '').trim().slice(0, 22),
        w: Math.round(r.width), h: Math.round(r.height),
      })
    }
  })
  return out
}, min)

test('тап-таргети проти Apple HIG 44×44', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  const steps: [string, () => Promise<void>][] = [
    ['db-list', async () => {
      await page.goto('/'); await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
    }],
    ['db-objects', async () => {
      await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (1)').waitFor({ timeout: 15_000 })
    }],
    ['property-detail', async () => {
      await page.locator('.obj-card').first().locator('.obj-t').click()
      await page.getByRole('button', { name: /Звільнити/ }).waitFor({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/'); await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await page.getByText('Налаштування').waitFor({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await page.getByText('Сповіщення').first().waitFor({ timeout: 15_000 })
    }],
  ]
  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const bad = await smallTargets(page, 44)
    console.log(`\n─── ${label}: менших за 44×44 — ${bad.length} ───`)
    const uniq = new Map<string, { cls: string; label: string; w: number; h: number }>()
    for (const b of bad) uniq.set(`${b.cls}|${b.w}x${b.h}`, b)
    for (const b of [...uniq.values()].slice(0, 10)) {
      console.log(`  ${String(b.w).padStart(3)}×${String(b.h).padStart(3)}  «${b.label}»  .${b.cls}`)
    }
  }
})
