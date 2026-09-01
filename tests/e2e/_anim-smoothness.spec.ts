import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * ІНСТРУМЕНТ (не гард): друкує розподіл кадрів під час кожної анімації.
 * PERF=1 npx playwright test _anim-smoothness --workers=1
 *
 * ЧОГО ЦІ ЦИФРИ НЕ ДОВОДЯТЬ. Headless Chromium на сервері тримає кадр ~17мс
 * навіть там, де iOS давно захлинувся б (те саме вже задокументовано для списку
 * з 200 обʼєктів). Тобто «зелено тут» ≠ «плавно на телефоні». Що ці заміри
 * ЛОВЛЯТЬ надійно — довгі кадри від рефлоу й перемальовки, тобто клас, який на
 * пристрої лише ГІРШИЙ. Тому головний висновок про плавність дає не цей файл, а
 * те, ЯКІ властивості анімуються (`transform`/`opacity` проти лейаутних).
 */

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
const PROPS = [prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18,
  area_useful: 100, area_total: 120, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01' }),
  ...Array.from({ length: 5 }, (_, i) => prop(i + 2))]

async function routes(page: Page) {
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
  for (const t of ['property_folders','property_files','property_photos','rent_payments',
                   'rent_payment_records','property_views','db_members','notifications','collections']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab','obj-fab','realtor-qr','col-fab'])))
}

/** Пише інтервали між кадрами у window.__frames, поки не викличемо stop. */
async function startFrames(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __frames: number[]; __stop?: () => void }
    w.__frames = []
    let last = performance.now()
    let on = true
    const tick = () => {
      if (!on) return
      const now = performance.now()
      w.__frames.push(now - last)
      last = now
      requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
    w.__stop = () => { on = false }
  })
}

async function report(page: Page, label: string) {
  const f = await page.evaluate(() => {
    const w = window as unknown as { __frames: number[]; __stop?: () => void }
    w.__stop?.()
    return w.__frames.slice(1) // перший інтервал — від старту спостерігача, не кадр анімації
  })
  if (!f.length) { console.log(`${label.padEnd(34)} — кадрів не зібрано`); return }
  const sorted = [...f].sort((a, b) => a - b)
  const p50 = sorted[Math.floor(sorted.length * 0.5)]
  const p95 = sorted[Math.floor(sorted.length * 0.95)]
  const worst = sorted[sorted.length - 1]
  const janky = f.filter((d) => d > 32).length
  console.log(
    `${label.padEnd(34)} кадрів=${String(f.length).padStart(3)}  p50=${p50.toFixed(1)}мс  ` +
    `p95=${p95.toFixed(1)}мс  гірший=${worst.toFixed(1)}мс  >32мс: ${janky}`)
}

test('плавність: анімації екранів, шитів і жестів', async ({ page }) => {
  test.setTimeout(180_000)
  page.on('console', (m) => { if (m.type() === 'error') console.log('CONSOLE:', m.text().slice(0, 300)) })
  page.on('pageerror', (e) => console.log('PAGEERROR:', String(e).slice(0, 400)))
  await routes(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // 1. Перехід між екранами (.nav-forward, .28s)
  await startFrames(page)
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(400)
  await report(page, 'перехід екрана (nav-forward)')

  // 2. Відкриття шита (modalSlideUp, .38s + backdrop-filter 48px)
  //
  // Шитом тут ВЖЕ НЕ «Здати в оренду»: фаза 5 переробки модалок перевела ту
  // дію на повноекранний маршрут, і цей крок мовчки чекав на `.modal`, якого
  // більше не буває. Оскільки `_`-інструменти в CI не біжать, плавність шитів
  // не мірялась ВІД ТІЄЇ ПЕРЕРОБКИ. Тепер міряємо живий `ActionSheet` — дії
  // обʼєкта за «⋯», той самий носій, що вибрав `modal-a11y`.
  const sheetOpener = page.locator('.obj-card').first().locator('.obj-more')
  await startFrames(page)
  await sheetOpener.click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(500)
  await report(page, 'відкриття шита (modalSlideUp)')

  // 3. Закриття шита (modalSlideDown, .24s)
  await startFrames(page)
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)
  await page.waitForTimeout(350)
  await report(page, 'закриття шита (modalSlideDown)')

  // 4. Свайп шита за пальцем — кадри під САМИМ жестом, найгірший випадок:
  //    кожен кадр рухає transform і перемальовує блюр.
  await sheetOpener.click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(450)
  await startFrames(page)
  await page.locator('.modal-head').evaluate(async (el) => {
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2
    const y0 = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, { touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true }))
    }
    fire('touchstart', y0)
    for (let i = 1; i <= 12; i++) {
      await new Promise((res) => requestAnimationFrame(() => res(null)))
      fire('touchmove', y0 + i * 5)
    }
    fire('touchend', y0 + 60, true)
  })
  await page.waitForTimeout(400)
  await report(page, 'свайп шита (transform + блюр)')
  await page.keyboard.press('Escape').catch(() => {})
  await page.waitForTimeout(400)

  // Повертатись у базу більше не треба: шит відкривається З НЕЇ, тож кроки 5-6
  // вже стоять на потрібному екрані.
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })

  // 5. Ховання плаваючої кнопки на скролі (.fbtn transition)
  await startFrames(page)
  await page.mouse.wheel(0, 400)
  await page.waitForTimeout(600)
  await report(page, 'ховання .fbtn на скролі')

  // 6. Акордеон папок / перемикання сегментів
  await startFrames(page)
  await page.getByText(/Зайнято \(/).click()
  await page.waitForTimeout(400)
  await page.getByText(/Всі \(/).first().click()
  await page.waitForTimeout(400)
  await report(page, 'перемикання сегментів')
})

test('плавність: смуга прогресу і лінія сканера — колишні лейаутні анімації', async ({ page }) => {
  test.setTimeout(120_000)
  await routes(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })

  // Смуга строку договору — .anim-progress (була width, тепер scaleX)
  await startFrames(page)
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await expect(page.locator('.anim-progress')).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(800)
  await report(page, 'смуга договору (.anim-progress)')
  const pb = await page.locator('.anim-progress').evaluate((el) => ({
    animated: getComputedStyle(el).animationName,
    transform: getComputedStyle(el).transform,
    width: getComputedStyle(el).width,
  }))
  console.log('  .anim-progress:', JSON.stringify(pb))

  // Лінія сканера — 2s infinite (була top, тепер translateY)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.evaluate(() => {
    const el = document.createElement('div')
    el.id = 'scan-probe'
    el.style.cssText = 'position:fixed;left:0;width:100px;height:2px;top:0;--scan-h:240px;animation:scanLine 2s ease-in-out infinite'
    document.body.appendChild(el)
  })
  await startFrames(page)
  await page.waitForTimeout(1200)
  await report(page, 'лінія сканера (scanLine 2s)')
  const sl = await page.locator('#scan-probe').evaluate((el) => ({
    top: getComputedStyle(el).top,
    transform: getComputedStyle(el).transform,
  }))
  console.log('  scanLine:', JSON.stringify(sl))
})
