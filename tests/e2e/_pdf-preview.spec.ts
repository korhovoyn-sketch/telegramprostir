import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'
import fs from 'node:fs'
import path from 'node:path'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс — у прогін не входить).
 *
 * `PERF=1 SHOTS_DIR=/tmp/pdf npx playwright test _pdf-preview` генерує PDF
 * експорту з реалістичною фікстурою, зберігає його і РЕНДЕРИТЬ сторінки в PNG
 * через pdf.js — єдиний спосіб побачити документ звідси: `pdftoppm` у
 * пісочниці не ставиться, а текст усередині PDF закодований гліфами субсету
 * шрифту, тож витягти його з файлу назад неможливо.
 *
 * Потрібен `pdfjs-dist`, встановлений ПОЗА репозиторієм:
 *   mkdir -p /tmp/pdfr && cd /tmp/pdfr && npm i pdfjs-dist@4
 */

const OUT = process.env.SHOTS_DIR ?? '/tmp/pdf'
const PDFJS = '/tmp/pdfr/node_modules/pdfjs-dist/build/pdf.min.mjs'
const PDFJS_WORKER = '/tmp/pdfr/node_modules/pdfjs-dist/build/pdf.worker.min.mjs'

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.', phone: '+380670000000', email: 'owner@example.com' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1, Київ',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

/** Три статуси — щоб побачити кожну гілку верстки, включно зі сторінкою продажу. */
const PROPS = [
  {
    id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
    name: 'Офіс 101, 5 поверх', floor: '5', status: 'occupied',
    area_useful: 100, area_total: 120, area_basis: 'useful',
    rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: true, parking_spaces: 3, parking_type: 'underground', ev_charger: true,
    folder_id: null, utilities: ['electricity', 'water', 'heating'],
    description: 'Світлий кутовий офіс із панорамними вікнами на дві сторони. Свіжий ремонт, окремий вхід, кухня-зона на 8 осіб.',
    address: 'вул. Хрещатик, 1, 5 поверх', sale_price: null,
    tenant_name: 'ТОВ «Ромашка»', lease_start_date: '2025-01-01', lease_end_date: '2026-06-30',
    sort_order: 100, created_at: NOW, updated_at: NOW,
    photos: [
      { id: 'p1', property_id: '20000000-0000-0000-0000-000000000001', storage_path: 'a/1.jpg', sort_order: 0, created_at: NOW },
      { id: 'p2', property_id: '20000000-0000-0000-0000-000000000001', storage_path: 'a/2.jpg', sort_order: 1, created_at: NOW },
      { id: 'p3', property_id: '20000000-0000-0000-0000-000000000001', storage_path: 'a/3.jpg', sort_order: 2, created_at: NOW },
    ],
  },
  {
    id: '20000000-0000-0000-0000-000000000002', db_id: DB_ID, owner_id: USER.id,
    name: 'Приміщення 2', floor: '1', status: 'free',
    area_useful: 45, area_total: 52, area_basis: 'total',
    rent_type: 'fixed', rent_rate: 25000, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: ['electricity'], description: null,
    address: null, sale_price: null, tenant_name: null,
    lease_start_date: null, lease_end_date: null,
    sort_order: 200, created_at: NOW, updated_at: NOW, photos: [],
  },
  {
    id: '20000000-0000-0000-0000-000000000003', db_id: DB_ID, owner_id: USER.id,
    name: 'Торгове приміщення 3', floor: '1', status: 'for_sale',
    area_useful: 210, area_total: 240, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: true, parking_spaces: 10, parking_type: 'open', ev_charger: false,
    folder_id: null, utilities: ['electricity', 'water', 'gas', 'backup'],
    description: 'Окрема будівля з власним двором і вітриною на першу лінію.',
    address: 'просп. Перемоги, 40', sale_price: 450000, tenant_name: null,
    lease_start_date: null, lease_end_date: null,
    sort_order: 300, created_at: NOW, updated_at: NOW,
    photos: [{ id: 'p9', property_id: '20000000-0000-0000-0000-000000000003', storage_path: 'c/1.jpg', sort_order: 0, created_at: NOW }],
  },
]

/**
 * Справжній PNG-прямокутник замість фото.
 *
 * SVG тут НЕ годиться, і це не дрібниця: jsPDF векторів не декодує взагалі —
 * рамки виходили порожні, і на око це читалось як «фото не працюють», хоч
 * причина була у фікстурі. Заодно перевіряє гілку формату PNG.
 */
function png(r: number, g: number, b: number, w = 800, h = 500): Buffer {
  const crc = (buf: Buffer) => {
    let c = ~0
    for (const byte of buf) {
      c ^= byte
      for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1))
    }
    return ~c >>> 0
  }
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length)
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data])
    const cr = Buffer.alloc(4); cr.writeUInt32BE(crc(td))
    return Buffer.concat([len, td, cr])
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4)
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0
  const raw = Buffer.alloc((w * 3 + 1) * h)
  for (let yy = 0; yy < h; yy++) {
    const off = yy * (w * 3 + 1)
    raw[off] = 0
    for (let xx = 0; xx < w; xx++) {
      const i = off + 1 + xx * 3
      const band = yy > h * 0.72 ? 0.6 : 1
      raw[i] = Math.round(r * band); raw[i + 1] = Math.round(g * band); raw[i + 2] = Math.round(b * band)
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    chunk('IHDR', ihdr), chunk('IDAT', zlibDeflate(raw)), chunk('IEND', Buffer.alloc(0)),
  ])
}
function zlibDeflate(buf: Buffer): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('node:zlib').deflateSync(buf)
}

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, PROPS))
  await page.route('**/rest/v1/users**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  const PALETTE: [number, number, number][] = [[72, 118, 168], [168, 120, 72], [96, 152, 108], [150, 96, 160]]
  let n = 0
  await page.route('**/storage/v1/object/public/photos/**', (r) =>
    r.fulfill({ status: 200, contentType: 'image/png', body: png(...PALETTE[n++ % PALETTE.length]) }))
  // Перехоплюємо файл замість share: у headless-браузері шита немає.
  await page.addInitScript(() => {
    const w = window as unknown as { __pdf?: string }
    Object.defineProperty(navigator, 'canShare', { value: () => true, configurable: true })
    Object.defineProperty(navigator, 'share', {
      configurable: true,
      value: async (data: { files?: File[] }) => {
        const f = data.files?.[0]
        if (!f) return
        const buf = await f.arrayBuffer()
        let s = ''
        const b = new Uint8Array(buf)
        for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
        w.__pdf = btoa(s)
      },
    })
  })
}

for (const theme of ['Класик', 'Нічний']) {
  test(`ПРЕВʼЮ PDF: ${theme}`, async ({ page }) => {
    test.setTimeout(180_000)
    await setup(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
    await page.getByLabel('Меню бази').click()
    await page.waitForTimeout(420)
    await page.getByText('Експорт', { exact: true }).click()
    await page.getByText(theme, { exact: true }).click()
    await page.getByRole('button', { name: /Завантажити PDF/ }).click()
    await expect(page.getByText(/PDF збережено/)).toBeVisible({ timeout: 40_000 })

    const b64 = await page.evaluate(() => (window as unknown as { __pdf?: string }).__pdf)
    expect(b64, 'PDF не дійшов до share').toBeTruthy()
    fs.mkdirSync(OUT, { recursive: true })
    const file = path.join(OUT, `${theme}.pdf`)
    fs.writeFileSync(file, Buffer.from(b64!, 'base64'))
    console.log(`PDF: ${file} (${(fs.statSync(file).size / 1024).toFixed(0)} КБ)`)

    // Рендер сторінок через pdf.js — прямо в цій же сторінці браузера.
    await page.addScriptTag({ path: PDFJS, type: 'module' })
    // pdf.js вимагає воркер навіть коли рендерить одну сторінку. Найдешевше —
    // віддати той самий бандл через route і вказати на нього.
    const WORKER = '/__pdfworker.mjs'
    await page.route(`**${WORKER}`, (r) =>
      r.fulfill({ status: 200, contentType: 'text/javascript', body: fs.readFileSync(PDFJS_WORKER, 'utf8') }))
    await page.evaluate((src) => {
      ;(window as unknown as { pdfjsLib: { GlobalWorkerOptions: { workerSrc: string } } })
        .pdfjsLib.GlobalWorkerOptions.workerSrc = src
    }, WORKER)
    const pngs = await page.evaluate(async (data) => {
      const pdfjs = (window as unknown as { pdfjsLib: {
        getDocument: (o: unknown) => { promise: Promise<{ numPages: number; getPage: (n: number) => Promise<{
          getViewport: (o: { scale: number }) => { width: number; height: number }
          render: (o: unknown) => { promise: Promise<void> } }> }> }
      } }).pdfjsLib
      const bin = Uint8Array.from(atob(data), (c) => c.charCodeAt(0))
      const doc = await pdfjs.getDocument({ data: bin }).promise
      const out: string[] = []
      for (let i = 1; i <= Math.min(doc.numPages, 4); i++) {
        const pg = await doc.getPage(i)
        const vp = pg.getViewport({ scale: 1.4 })
        const cv = document.createElement('canvas')
        cv.width = vp.width; cv.height = vp.height
        const ctx = cv.getContext('2d')!
        await pg.render({ canvasContext: ctx, viewport: vp }).promise
        out.push(cv.toDataURL('image/png'))
      }
      return out
    }, b64!)

    pngs.forEach((d, i) => {
      fs.writeFileSync(path.join(OUT, `${theme}-p${i + 1}.png`), Buffer.from(d.split(',')[1], 'base64'))
    })
    console.log(`сторінок відрендерено: ${pngs.length} → ${OUT}`)
  })
}
