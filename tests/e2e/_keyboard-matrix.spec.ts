import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * ІНСТРУМЕНТ (не гард): взаємодія шитів із клавіатурою на РІЗНИХ екранах.
 *   PERF=1 CI=1 npx playwright test _keyboard-matrix --workers=1
 *
 * Матриця — пристрої × три режими клавіатури. Три режими, а не два, і це
 * принципово (див. CLAUDE.md): перекриття (visualViewport вужчає, вікно ні),
 * стискання ЗІ звітом від Telegram, і стискання БЕЗ звіту — саме третій є
 * прод-клієнтом користувача, і саме він колись і пропустив баг.
 *
 * Що перевіряється в кожній клітинці: шит не за екраном, шит не під клавіатурою,
 * між шитом і клавіатурою немає ДІРИ (ознака подвійного ліфта), поле у фокусі
 * повністю видиме і не під sticky-кнопками, заголовок не зрізаний, немає
 * горизонтального переповнення.
 */

type Mode = 'overlay' | 'resize-reported' | 'resize-silent'

/** Реальні геометрії + типова висота клавіатури для кожної. */
const DEVICES = [
  { name: 'iPhone SE1/5s',    w: 320, h: 568, kb: 216 },
  { name: 'Android бюджет',   w: 360, h: 640, kb: 270 },
  { name: 'iPhone SE2/3, 8',  w: 375, h: 667, kb: 260 },
  { name: 'iPhone 13/14/15',  w: 390, h: 844, kb: 291 },
  { name: 'Pixel 7/8',        w: 393, h: 873, kb: 300 },
  { name: 'Galaxy S20+/A54',  w: 412, h: 915, kb: 310 },
  { name: 'iPhone 15 Pro Max',w: 430, h: 932, kb: 320 },
]

const NOW = '2025-09-01T09:00:00.000Z'
const OWNER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = { id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW }
const json = (r: Route, b: unknown) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(b) })

function prop(i: number, over: Record<string, unknown> = {}) {
  return { id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i), status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 20, utilities_rate: 2, has_parking: false,
    parking_spaces: 0, parking_type: null, ev_charger: false, folder_id: null, utilities: null,
    description: 'Світлий офіс.', address: null, sale_price: null, tenant_name: null,
    lease_start_date: null, lease_end_date: null, sort_order: i,
    share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over }
}
const OCCUPIED = prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18,
  area_useful: 100, area_total: 120, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01' })
const PROPS = [OCCUPIED, prop(2)]
const SCHEDULE = [{ id: '80000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id,
  owner_id: OWNER.id, due_day: 5, notify_days_before: 3, is_active: true,
  created_at: NOW, updated_at: NOW }]

async function fixtures(page: Page) {
  await setupApp(page, { user: OWNER })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    if ((r.request().headers()['accept'] ?? '').includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPS.find((p) => p.id === m?.[1]) ?? PROPS[0])
    }
    return json(r, PROPS)
  })
  await page.route('**/rest/v1/property_folders**', (r) => json(r, [
    { id: '50000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: OWNER.id,
      name: 'Орендарі', sort_order: 1, created_at: NOW, updated_at: NOW }]))
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, SCHEDULE))
  await page.route('**/rest/v1/guest_links**', (r) => {
    if (r.request().method() === 'POST') return json(r, { invite_token: 'ee00112233445566778899bb' })
    return json(r, [])
  })
  for (const t of ['rent_payment_records','property_views','property_files','property_photos',
                   'notifications','collections','db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab','obj-fab','realtor-qr','col-fab'])))
}

/**
 * Відкриває клавіатуру у заданому режимі. Порядок дій — як у житті: спершу фокус
 * (від тапу по полю), і лише за ~150мс платформа реагує. Саме ця затримка й
 * створює гонку з пробою `kbFallback` (350мс + 200мс підтвердження).
 */
async function openKeyboard(page: Page, mode: Mode, dev: { w: number; h: number; kb: number }) {
  await page.waitForTimeout(150)
  if (mode === 'overlay') {
    // iOS у Telegram: вікно НЕ ресайзиться, вужчає лише visualViewport. Підміна
    // мусить бути саме такою — пряма запись у `--keyboard-h` не працює, бо
    // applyKeyboardFromVV перерахував би 0 із незміненого visualViewport і стер її.
    await page.evaluate((kb) => {
      const vv = window.visualViewport!
      Object.defineProperty(vv, 'height', { configurable: true, get: () => window.innerHeight - kb })
      vv.dispatchEvent(new Event('resize'))
    }, dev.kb)
  } else if (mode === 'resize-reported') {
    await page.setViewportSize({ width: dev.w, height: dev.h - dev.kb })
    await page.evaluate(({ h, kb }) => {
      const w = window as unknown as { __tgViewportStable: (n: number) => void; __tgKeyboard: (n: number) => void }
      w.__tgViewportStable(h)
      w.__tgKeyboard(kb)
    }, { h: dev.h, kb: dev.kb })
  } else {
    // Telegram МОВЧИТЬ: ріжемо лише реальну висоту вікна.
    await page.setViewportSize({ width: dev.w, height: dev.h - dev.kb })
  }
  // padding-bottom і max-height їдуть .25s; плюс запас на пробу фолбека.
  await page.waitForTimeout(900)
}

interface Violation { cell: string; problem: string }

/** Короткий опис геометрії клітинки — щоб у логу були ЦИФРИ, а не лише «0 порушень». */
async function describe(page: Page, mode: Mode, kb: number): Promise<string> {
  return page.evaluate(({ mode, kb }) => {
    const sheet = document.querySelector('.modal') as HTMLElement | null
    if (!sheet) return 'шита немає'
    const r = sheet.getBoundingClientRect()
    const band = mode === 'overlay' ? window.innerHeight - kb : window.innerHeight
    const af = document.activeElement as HTMLElement | null
    const f = af && sheet.contains(af) ? af.getBoundingClientRect() : null
    const kbh = getComputedStyle(document.documentElement).getPropertyValue('--keyboard-h').trim()
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return `шит ${Math.round(r.top)}–${Math.round(r.bottom)} смуга→${band} ` +
           `зазор=${Math.round(band - r.bottom)} поле=${f ? Math.round(f.bottom) : '—'} ` +
           `--keyboard-h=${kbh || '0'} локальний=${ov.style.getPropertyValue('--keyboard-h') || '—'}`
  }, { mode, kb })
}

/**
 * Заміряє одну клітинку матриці. `bandBottom` — низ ВИДИМОЇ смуги: у режимі
 * перекриття клавіатура з'їдає низ вікна, у режимах стискання вікно вже без неї.
 */
async function audit(page: Page, cell: string, mode: Mode, kb: number, out: Violation[]) {
  const m = await page.evaluate(({ mode, kb }) => {
    const sheet = document.querySelector('.modal') as HTMLElement | null
    if (!sheet) return { missing: true } as const
    const r = sheet.getBoundingClientRect()
    const bandBottom = mode === 'overlay' ? window.innerHeight - kb : window.innerHeight
    const acts = sheet.querySelector('.modal-actions') as HTMLElement | null
    const body = sheet.querySelector('.modal-body') as HTMLElement | null
    const title = sheet.querySelector('.modal-h') as HTMLElement | null
    const af = document.activeElement as HTMLElement | null
    const focused = af && sheet.contains(af) && /^(INPUT|TEXTAREA)$/.test(af.tagName)
      ? af.getBoundingClientRect() : null
    return {
      missing: false as const,
      bandBottom,
      top: r.top, bottom: r.bottom, height: r.height,
      titleTop: title ? title.getBoundingClientRect().top : null,
      actionsTop: acts ? acts.getBoundingClientRect().top : null,
      focusedTop: focused ? focused.top : null,
      focusedBottom: focused ? focused.bottom : null,
      overflowX: body ? body.scrollWidth - body.clientWidth : 0,
      innerH: window.innerHeight,
    }
  }, { mode, kb })

  if (m.missing) { out.push({ cell, problem: 'шита немає в DOM' }); return }

  // ГАРД ВІД ВАКУУМНОСТІ. Якщо симуляція клавіатури нічого не робить, усі
  // перевірки нижче проходять самі собою і матриця не означає нічого. Тому кожна
  // клітинка мусить довести: (а) знайдено поле у фокусі, (б) смуга справді
  // вужча за вікно, тобто клавіатура «є».
  if (m.focusedTop === null) {
    out.push({ cell, problem: 'ВАКУУМ: поля у фокусі не знайдено — перевірки перекриття нічого не міряли' })
  }
  if (m.innerH - m.bandBottom < 100 && mode === 'overlay') {
    out.push({ cell, problem: `ВАКУУМ: клавіатура не подіяла (смуга ${m.bandBottom} при вікні ${m.innerH})` })
  }
  if (mode !== 'overlay' && m.innerH > 700 && kb > 200) {
    out.push({ cell, problem: `ВАКУУМ: вікно не стиснулось (innerHeight=${m.innerH})` })
  }

  // 1. Шит не виїхав за верх екрана.
  if (m.top < -1) out.push({ cell, problem: `верх шита за екраном: top=${Math.round(m.top)}` })
  // 2. Заголовок мусить бути видимий — інакше користувач не знає, що це за шит.
  if (m.titleTop !== null && m.titleTop < -1) {
    out.push({ cell, problem: `заголовок зрізаний зверху: ${Math.round(m.titleTop)}` })
  }
  // 3. Шит не під клавіатурою.
  if (m.bottom - m.bandBottom > 2) {
    out.push({ cell, problem: `низ шита під клавіатурою на ${Math.round(m.bottom - m.bandBottom)}px` })
  }
  // 4. …і не відірваний від неї (діра = подвійний ліфт).
  if (m.bandBottom - m.bottom > 8) {
    out.push({ cell, problem: `ДІРА між шитом і клавіатурою: ${Math.round(m.bandBottom - m.bottom)}px (подвійний ліфт)` })
  }
  // 5. Поле у фокусі повністю у видимій смузі.
  if (m.focusedBottom !== null && m.focusedBottom - m.bandBottom > 2) {
    out.push({ cell, problem: `поле у фокусі ПІД клавіатурою на ${Math.round(m.focusedBottom - m.bandBottom)}px` })
  }
  if (m.focusedTop !== null && m.focusedTop < -1) {
    out.push({ cell, problem: `поле у фокусі вище екрана: ${Math.round(m.focusedTop)}` })
  }
  // 6. …і не під sticky-кнопками: вміст ПРОЇЖДЖАЄ під ними, тож це реальний кейс.
  if (m.focusedBottom !== null && m.actionsTop !== null && m.focusedBottom - m.actionsTop > 2) {
    out.push({ cell, problem: `поле у фокусі під кнопками дій на ${Math.round(m.focusedBottom - m.actionsTop)}px` })
  }
  // 7. Горизонтального переповнення бути не має на жодній ширині.
  if (m.overflowX > 1) out.push({ cell, problem: `горизонтальне переповнення ${m.overflowX}px` })
  // 8. Шит не має бути вищим за видиму смугу.
  if (m.height - m.bandBottom > 2) {
    out.push({ cell, problem: `шит вищий за видиму смугу на ${Math.round(m.height - m.bandBottom)}px` })
  }
}

async function toRentSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: /Здати в оренду/ }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(450)
}

for (const mode of ['overlay', 'resize-reported', 'resize-silent'] as Mode[]) {
  test(`шит оренди × клавіатура (${mode}) на 7 екранах`, async ({ page }) => {
    test.setTimeout(300_000)
    const out: Violation[] = []
    for (const dev of DEVICES) {
      await page.setViewportSize({ width: dev.w, height: dev.h })
      await fixtures(page)
      await toRentSheet(page)

      // Фокус у ПЕРШЕ поле (Орендар) — верх форми.
      await page.locator('.modal input').first().focus()
      await openKeyboard(page, mode, dev)
      await audit(page, `${dev.name} ${dev.w}×${dev.h} · ${mode} · перше поле`, mode, dev.kb, out)
      console.log(`  ${dev.name.padEnd(19)} ${String(dev.w).padStart(3)}×${dev.h}  kb=${dev.kb}  ${await describe(page, mode, dev.kb)}`)

      // …і в ОСТАННЄ поле: саме воно найглибше в тілі й найлегше опиняється під
      // клавіатурою або під sticky-кнопками.
      const inputs = page.locator('.modal input')
      const n = await inputs.count()
      if (n > 1) {
        await inputs.nth(n - 1).focus()
        await page.waitForTimeout(700)
        await audit(page, `${dev.name} ${dev.w}×${dev.h} · ${mode} · останнє поле`, mode, dev.kb, out)
      }
    }
    for (const v of out) console.log(`  ✗ ${v.cell}: ${v.problem}`)
    console.log(`[${mode}] порушень: ${out.length} на ${DEVICES.length} екранах`)
    expect(out, `порушення взаємодії шита з клавіатурою (${mode})`).toEqual([])
  })
}

test('інші шити з полями × клавіатура на двох найпоширеніших екранах', async ({ page }) => {
  test.setTimeout(300_000)
  const out: Violation[] = []
  const sizes = [DEVICES[2], DEVICES[3]] // 375×667 і 390×844
  // «Розклад платежів»/«Підтвердження платежу» прибрано (фаза 2 переробки
  // модалок): це тепер повноекранні маршрути (payment-schedule/payment-confirm),
  // без `.modal` узагалі — цикл нижче явно чекає на `.modal`, тож інструмент,
  // чиє призначення саме клавіатура В МОДАЛКАХ, тут не узагальнюється під
  // геометрію екрана. Еквівалентне покриття — генерично в
  // field-obstruction.spec.ts/keyboard-viewport.spec.ts.
  const sheets: Array<{ name: string; open: (p: Page) => Promise<void> }> = [
    { name: 'запросити гостя', open: async (p) => {
      await p.goto('/')
      await expect(p.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await p.getByText('БЦ Рубін').first().click()
      await expect(p.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
      await p.getByLabel('Меню бази').click()
      await p.getByText('Управління гостями', { exact: true }).click()
      await expect(p.getByText(/Гост/).first()).toBeVisible({ timeout: 15_000 })
      await p.getByLabel('Запросити гостя').click()
    } },
    { name: 'папки', open: async (p) => {
      await p.goto('/')
      await expect(p.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await p.getByText('БЦ Рубін').first().click()
      await expect(p.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
      await p.getByLabel('Меню бази').click()
      await p.getByText('Папки', { exact: true }).click()
    } },
  ]

  for (const dev of sizes) {
    for (const mode of ['overlay', 'resize-silent'] as Mode[]) {
      for (const s of sheets) {
        await page.setViewportSize({ width: dev.w, height: dev.h })
        await fixtures(page)
        await s.open(page)
        await expect(page.locator('.modal')).toBeVisible({ timeout: 15_000 })
        await page.waitForTimeout(450)
        const inputs = page.locator('.modal input')
        if (await inputs.count() === 0) continue
        await inputs.first().focus()
        await openKeyboard(page, mode, dev)
        await audit(page, `${s.name} · ${dev.w}×${dev.h} · ${mode}`, mode, dev.kb, out)
      }
    }
  }
  for (const v of out) console.log(`  ✗ ${v.cell}: ${v.problem}`)
  console.log(`[інші шити] порушень: ${out.length}`)
  expect(out, 'порушення взаємодії шитів із клавіатурою').toEqual([])
})

/**
 * АНІМАЦІЯ, а не лише кінцева точка. Оригінальна скарга користувача звучала як
 * «пригає вверх, а потім взагалі стискається» — тобто дефект був у ТРАЄКТОРІЇ:
 * шит перелітав своє місце і повертався. Кінцевий замір такого не бачить, тому
 * тут траєкторія семплюється щокадру.
 */
test('шит не ПЕРЕЛІТАЄ своє місце, поки відкривається клавіатура', async ({ page }) => {
  test.setTimeout(300_000)
  const bad: string[] = []
  for (const dev of [DEVICES[0], DEVICES[2], DEVICES[3], DEVICES[6]]) {
    for (const mode of ['overlay', 'resize-reported', 'resize-silent'] as Mode[]) {
      await page.setViewportSize({ width: dev.w, height: dev.h })
      await fixtures(page)
      await toRentSheet(page)

      // ОБОВ'ЯЗКОВА синхронізація ПЕРЕД стартом заміру. Харнес хардкодить
      // мок viewportStableHeight=568 незалежно від dev.h, тож для будь-якого
      // іншого екрана початковий (до клавіатури) стан УЖЕ неконсистентний:
      // --tg-vh стоїть на 568, а справжнє вікно — dev.h. Без цього кроку
      // будь-яка наступна корекція (яку робить сам застосунок, побачивши
      // справжній dev.h) читалась би як «переліт», хоч насправді це полагодження
      // ЧУЖОЇ помилки тесту, а не рух самого шита під клавіатуру.
      await page.evaluate((h) => {
        const w = window as unknown as { __tgViewportStable: (n: number) => void }
        w.__tgViewportStable(h)
      }, dev.h)
      await page.waitForTimeout(400) // .25s max-height transition + запас

      // Починаємо семплювати ДО фокуса — щоб зловити весь рух.
      await page.evaluate(() => {
        const w = window as unknown as { __traj: number[] }
        w.__traj = []
        const sheet = document.querySelector('.modal') as HTMLElement
        const tick = () => {
          if (!document.body.contains(sheet)) return
          w.__traj.push(sheet.getBoundingClientRect().top)
          requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      })
      await page.locator('.modal input').first().focus()
      await openKeyboard(page, mode, dev)

      const traj = await page.evaluate(() => (window as unknown as { __traj: number[] }).__traj)
      if (traj.length < 10) { bad.push(`${dev.name} · ${mode}: траєкторія не зібрана`); continue }
      const final = traj[traj.length - 1]
      const highest = Math.min(...traj)
      const overshoot = final - highest
      // Шит їде вгору один раз і зупиняється. Переліт понад 12px = той самий
      // «стрибок», через який усе й почалось.
      if (overshoot > 12) {
        bad.push(`${dev.name} ${dev.w}×${dev.h} · ${mode}: ПЕРЕЛІТ на ${Math.round(overshoot)}px ` +
                 `(найвище ${Math.round(highest)}, спокій ${Math.round(final)})`)
      }
      console.log(`  ${dev.name.padEnd(19)} ${mode.padEnd(16)} кадрів=${String(traj.length).padStart(3)} ` +
                  `переліт=${Math.round(overshoot)}px спокій=${Math.round(final)}`)
    }
  }
  for (const b of bad) console.log(`  ✗ ${b}`)
  expect(bad, 'шит перелітає своє місце під час відкриття клавіатури').toEqual([])
})
