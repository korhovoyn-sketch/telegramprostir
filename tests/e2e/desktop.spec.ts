import { test, expect, type Page, type Route, type Browser } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Desktop presentation (Telegram Desktop / Web run Mini Apps in a wide window) ─
// On screens ≥680px the app must render as a centered phone-sized frame, NOT a
// full-width stretched layout. The public /v page is a separate web surface.

const NOW = new Date().toISOString()
const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.', phone: '+380670000000' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}
const PREVIEW = [{
  db_id: DB_ID, db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
  share_expires_at: null, property_id: '20000000-0000-0000-0000-000000000001', property_name: 'Офіс 101',
  property_status: 'occupied', property_floor: '2', property_area_useful: 100, property_area_total: 120,
  property_rent_type: 'per_m2', property_rent_rate: 18, property_sale_price: null,
  property_description: 'Світлий офіс у центрі міста, панорамні вікна.',
  owner_first_name: 'Микола', owner_last_name: 'К.', owner_phone: '+380670000000',
  owner_tg_username: 'mykola', owner_currency: 'UAH', first_photo: null,
}]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function desktopPage(browser: Browser) {
  // Laptop window — no isMobile/touch: this is Telegram Desktop / Web.
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 })
  return { ctx, page: await ctx.newPage() }
}

test('desktop · Mini App renders as a centered phone frame, not full-width', async ({ browser }) => {
  const { ctx, page } = await desktopPage(browser)
  try {
    await setupApp(page, { user: OWNER })
    await ownerRoutes(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

    // #app-root must be constrained to the phone frame (~430px), centered — not
    // stretched across the 1280px viewport.
    const root = page.locator('#app-root')
    const box = await root.boundingBox()
    expect(box, 'app-root has a box').not.toBeNull()
    expect(box!.width, 'app-root width ≈ 430px phone frame').toBeLessThanOrEqual(460)
    const centerX = box!.x + box!.width / 2
    expect(Math.abs(centerX - 640), 'app-root horizontally centered in 1280px').toBeLessThan(40)

    // No horizontal page scroll on desktop either.
    const over = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)
    expect(over, 'no horizontal overflow on desktop').toBe(true)

    await page.screenshot({ path: 'screenshots/desktop-app-db-list.png' })
  } finally {
    await ctx.close()
  }
})

test('desktop · public /v is width-capped and centered, not full-bleed', async ({ browser }) => {
  const { ctx, page } = await desktopPage(browser)
  try {
    await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, PREVIEW))
    await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, null))
    await page.goto('/v/?db=aabbccddeeff001122334455')
    await expect(page.getByText('Публічний перегляд')).toBeVisible({ timeout: 15_000 })

    // The content column must not span the whole 1280px desktop width — a public
    // listing stretched edge-to-edge reads as broken. Cap ~560px, centered
    // (the #app-root desktop frame constrains /v too).
    const header = page.getByText('Публічний перегляд').locator('xpath=ancestor::*[contains(@style,"border-radius")][1]')
    const box = await header.boundingBox()
    if (box) {
      expect(box.width, '/v content column is width-capped on desktop').toBeLessThanOrEqual(560)
    }
    await page.screenshot({ path: 'screenshots/desktop-v-database.png', fullPage: false })
  } finally {
    await ctx.close()
  }
})

/**
 * ШИТ НЕ СМІЄ ВИХОДИТИ ЗА РАМКУ ЗАСТОСУНКУ.
 *
 * `ActionSheet` монтується в `<body>` навмисно — усередині оболонки він не зміг
 * би накрити її власні фіксовані елементи. Наслідок на десктопі був видимий
 * одразу: заміряно на 1440×900 — рядки меню й кнопка «Скасувати» завширшки
 * ~1400px при рамці 430px, а нижні пункти обрізані краєм ВІКНА, а не рамки.
 * Тобто шит виглядав частиною монітора, а не застосунку.
 *
 * Лікується CSS-ом у десктопному медіа-блоці: оверлей бере ту саму геометрію,
 * що й оболонка (спільні `--frame-*`). `FilePreviewModal` цього не потребує —
 * він уже монтується в `#app-root`.
 */
test('desktop · шит лишається в межах рамки, а не на весь монітор', async ({ browser }) => {
  const { ctx, page } = await desktopPage(browser)
  try {
    await setupApp(page, { user: OWNER })
    await ownerRoutes(page)
    await page.route('**/rest/v1/properties**', (r) => json(r, []))
    for (const t of ['property_folders', 'property_views', 'notifications',
                     'rent_payments', 'rent_payment_records', 'collections', 'guest_links']) {
      await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
    }
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
    await page.getByLabel('Меню бази').click()
    await page.waitForTimeout(500)

    const geo = await page.evaluate(() => {
      const root = document.getElementById('app-root')!.getBoundingClientRect()
      const ov = document.querySelector<HTMLElement>('.modal-overlay')!.getBoundingClientRect()
      const sheet = document.querySelector<HTMLElement>('.modal')!.getBoundingClientRect()
      return {
        root: { l: Math.round(root.left), r: Math.round(root.right), w: Math.round(root.width) },
        ov: { l: Math.round(ov.left), r: Math.round(ov.right) },
        sheet: { l: Math.round(sheet.left), r: Math.round(sheet.right), w: Math.round(sheet.width) },
        winW: window.innerWidth,
      }
    })

    // АНТИВАКУУМ: рамка мусить бути ВУЖЧОЮ за вікно, інакше «шит у межах рамки»
    // виконувалось би тривіально — на телефоні вони збігаються.
    expect(geo.root.w, 'десктопна рамка не зʼявилась — далі перевіряти нічого')
      .toBeLessThan(geo.winW - 100)

    expect(geo.ov.l, 'оверлей вилазить за ліву межу рамки').toBeGreaterThanOrEqual(geo.root.l - 1)
    expect(geo.ov.r, 'оверлей вилазить за праву межу рамки').toBeLessThanOrEqual(geo.root.r + 1)
    expect(geo.sheet.w, `шит ${geo.sheet.w}px при рамці ${geo.root.w}px`)
      .toBeLessThanOrEqual(geo.root.w + 1)
  } finally {
    await ctx.close()
  }
})

/**
 * ПІДПИС ПІД РАМКОЮ — лише коли під нею СПРАВДІ є місце.
 *
 * `body::after` стоїть `fixed; bottom:22px`, тобто від низу ВІКНА, а рамка має
 * `min(100vh,930px)`. На екрані, нижчому за ~1010px, вона займає всю висоту —
 * місця «під рамкою» немає, і підпис лягав просто на таббар, поверх іконок
 * (заміряно на 1440×900).
 */
test('desktop · підпис не лягає на таббар, коли рамка займає всю висоту', async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 })
  const page = await ctx.newPage()
  try {
    await setupApp(page, { user: OWNER })
    await ownerRoutes(page)
    await page.route('**/rest/v1/properties**', (r) => json(r, []))
    for (const t of ['property_folders', 'property_views', 'notifications',
                     'rent_payments', 'rent_payment_records', 'collections', 'guest_links']) {
      await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
    }
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })

    const hit = await page.evaluate(() => {
      const mark = getComputedStyle(document.body, '::after')
      const tab = document.querySelector<HTMLElement>('.tabbar')?.getBoundingClientRect()
      return {
        content: mark.content,
        tabTop: tab ? Math.round(tab.top) : -1,
        winH: window.innerHeight,
      }
    })

    // АНТИВАКУУМ: таббар мусить бути на екрані — інакше перевірка про
    // накладання нічого не означає.
    expect(hit.tabTop, 'таббар не знайдено').toBeGreaterThan(0)
    // Підпис або відсутній, або стоїть НИЖЧЕ за таббар. На 900px висоти рамка
    // займає весь екран, тож єдина правильна відповідь — його немає.
    expect(hit.content, `підпис малюється при висоті ${hit.winH}px, де під рамкою немає місця`)
      .toMatch(/^(none|normal|"")$/)
  } finally {
    await ctx.close()
  }
})
