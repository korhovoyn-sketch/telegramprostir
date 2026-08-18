import { test, expect, type Page, type Route, type Browser } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Telegram theme independence ──────────────────────────────────────────────
// The app is dark-only by design: whatever theme the user picks in Telegram
// (light or dark), the UI must stay dark with white text and gradient
// backgrounds, and the native chrome (header/bg/bottom bar) must be forced dark
// — a light Telegram theme historically painted WHITE bars over the dark UI and,
// via a stray [data-tg-theme=light] token override, turned text black. This spec
// drives both schemes and asserts the invariants hold.

const NOW = new Date().toISOString()
const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
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

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

// Registered AFTER installTelegram, so it overrides the stub's colorScheme and
// records every native-chrome colour the app sets.
async function overrideTheme(page: Page, scheme: 'light' | 'dark') {
  await page.addInitScript((s) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tg = (window as any).Telegram?.WebApp
    if (!tg) return
    tg.colorScheme = s
    tg.themeParams = s === 'light'
      ? { bg_color: '#ffffff', secondary_bg_color: '#efeff3', text_color: '#000000', hint_color: '#707579', button_color: '#3390ec' }
      : { bg_color: '#212121', secondary_bg_color: '#181818', text_color: '#ffffff', hint_color: '#aaaaaa', button_color: '#8774e1' }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).__tgColors = []
    for (const m of ['setHeaderColor', 'setBackgroundColor', 'setBottomBarColor']) {
      tg[m] = (c: string) => { (window as any).__tgColors.push([m, c]) } // eslint-disable-line @typescript-eslint/no-explicit-any
    }
  }, scheme)
}

// Perceived luminance (0..255) of a CSS colour — accepts "rgb(r,g,b)"/"rgba(...)"
// and "#rgb"/"#rrggbb" (the app pushes hex to Telegram, computed styles read rgb).
function luminance(color: string): number {
  let r: number, g: number, b: number
  if (color.startsWith('#')) {
    let hex = color.slice(1)
    if (hex.length === 3) hex = hex.split('').map((c) => c + c).join('')
    r = parseInt(hex.slice(0, 2), 16); g = parseInt(hex.slice(2, 4), 16); b = parseInt(hex.slice(4, 6), 16)
  } else {
    const m = color.match(/\d+(\.\d+)?/g)
    if (!m) return -1
    ;[r, g, b] = m.map(Number)
  }
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

async function newDevicePage(browser: Browser) {
  const ctx = await browser.newContext({
    viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
  })
  return { ctx, page: await ctx.newPage() }
}

for (const scheme of ['light', 'dark'] as const) {
  test(`theme · Telegram ${scheme} — UI stays dark, text white, верх темний / низ за градієнтом`, async ({ browser }) => {
    const { ctx, page } = await newDevicePage(browser)
    try {
      await setupApp(page, { user: OWNER })
      await overrideTheme(page, scheme)
      await ownerRoutes(page)
      await page.goto('/')
      const heading = page.getByText('Мої бази')
      await expect(heading).toBeVisible({ timeout: 20_000 })

      // 1. The theme branch ran: data-tg-theme reflects Telegram's choice.
      await expect(page.locator('html')).toHaveAttribute('data-tg-theme', scheme)

      // 2. Body text is WHITE regardless of theme (the token-override regression
      //    turned it black under light). Heading luminance must be high.
      const headingColor = await heading.evaluate((el) => getComputedStyle(el).color)
      expect(luminance(headingColor), `heading color ${headingColor} should be light`).toBeGreaterThan(200)

      // 3. Screen background is a gradient (.bg-*), never a flat light colour.
      const bg = page.locator('.scr').first()
      const bgImage = await bg.evaluate((el) => getComputedStyle(el).backgroundImage)
      expect(bgImage, 'screen background should be a gradient').toContain('gradient')

      // 4. Native chrome forced dark: every colour the app pushed to Telegram is
      //    near-black, never the light theme's #ffffff bg.
      // 4. Нативний хром — але вже НЕ «увесь чорний»: це правило розділилось.
      //    ВЕРХ лишається темним (там градієнт екрана справді майже чорний), а
      //    НИЗ мусить дорівнювати кінцю градієнта. Заміряно на записі з
      //    пристрою: чорна смуга під світлим низом — це рамка, що проглядає
      //    навколо панелі клавіатури в iOS 26.
      const chrome = await page.evaluate(() => (window as { __tgColors?: [string, string][] }).__tgColors ?? [])
      expect(chrome.length, 'app set native chrome colours').toBeGreaterThan(0)
      const end = await page.locator('#app-root .scr[class*="bg-"]').first()
        .evaluate((el) => getComputedStyle(el).getPropertyValue('--bg-end').trim().toLowerCase())
      expect(end, 'екран без --bg-end — перевірка низу стала б порожньою').toMatch(/^#[0-9a-f]{6}$/)
      const last = new Map(chrome.map(([m, c]) => [m, c.toLowerCase()]))
      expect(luminance(last.get('setHeaderColor') ?? '#000'), 'верхня смуга мусить лишатись темною')
        .toBeLessThan(30)
      expect(last.get('setBottomBarColor'), 'нижня смуга мусить брати кінець градієнта').toBe(end)
      expect(last.get('setBackgroundColor'), 'фон webview мусить брати кінець градієнта').toBe(end)

      await page.screenshot({ path: `screenshots/theme-${scheme}-db-list.png` })
    } finally {
      await ctx.close()
    }
  })
}

// Edge case: old Telegram clients / cold start where the SDK exposes NO
// colorScheme and NO themeParams at all. The app must still render dark and
// readable — never blank or default-browser-light.
test('theme · missing colorScheme + themeParams (old client / cold start) stays dark', async ({ browser }) => {
  const { ctx, page } = await newDevicePage(browser)
  try {
    await setupApp(page, { user: OWNER })
    await page.addInitScript(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tg = (window as any).Telegram?.WebApp
      if (!tg) return
      delete tg.colorScheme
      delete tg.themeParams
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(window as any).__tgColors = []
      for (const m of ['setHeaderColor', 'setBackgroundColor', 'setBottomBarColor']) {
        tg[m] = (c: string) => { (window as any).__tgColors.push([m, c]) } // eslint-disable-line @typescript-eslint/no-explicit-any
      }
    })
    await ownerRoutes(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

    // No colorScheme → page.tsx guards, so data-tg-theme is never set.
    await expect(page.locator('html')).not.toHaveAttribute('data-tg-theme', /.+/)
    // Text still white, background still a gradient, chrome still dark.
    const headingColor = await page.getByText('Мої бази').evaluate((el) => getComputedStyle(el).color)
    expect(luminance(headingColor), `heading ${headingColor} light without themeParams`).toBeGreaterThan(200)
    const bgImage = await page.locator('.scr').first().evaluate((el) => getComputedStyle(el).backgroundImage)
    expect(bgImage).toContain('gradient')
    const chrome = await page.evaluate(() => (window as { __tgColors?: [string, string][] }).__tgColors ?? [])
    const last2 = new Map(chrome.map(([m, c]) => [m, c.toLowerCase()]))
    expect(luminance(last2.get('setHeaderColor') ?? '#000'), 'верх темний і без themeParams')
      .toBeLessThan(30)
    const end2 = await page.locator('#app-root .scr[class*="bg-"]').first()
      .evaluate((el) => getComputedStyle(el).getPropertyValue('--bg-end').trim().toLowerCase())
    expect(last2.get('setBottomBarColor'), 'низ бере кінець градієнта і без themeParams').toBe(end2)
  } finally {
    await ctx.close()
  }
})
