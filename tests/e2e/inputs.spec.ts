import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Input fields across device sizes ─────────────────────────────────────────
// The load-bearing rule (CLAUDE.md): every focusable input renders at >= 16px so
// iOS Safari / the Telegram webview never auto-zooms on focus. This drives the
// real forms at three widths and asserts the computed font-size of every input,
// plus that inputs actually fill (value updates) and drive derived UI.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '3', status: 'free', area_useful: 45, area_total: 52,
  rent_type: 'per_m2', rent_rate: null, utilities_rate: null, has_parking: false,
  parking_spaces: 0, parking_type: null, ev_charger: false, utilities: null,
  description: null, address: null, sale_price: null, tenant_name: null,
  lease_start_date: null, lease_end_date: null, sort_order: 1,
  share_token: 'bb000000000000000000000001', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const VIEWPORTS = [
  { name: 'iPhone SE (320)', width: 320, height: 568 },
  { name: 'iPhone (375)', width: 375, height: 667 },
  { name: 'Large phone (414)', width: 414, height: 896 },
]

async function setupFixtures(page: Page) {
  await setupApp(page, { user: USER })
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

// Every visible input/textarea must compute to >= 16px (iOS anti-zoom).
async function assertNoZoomInputs(page: Page, where: string) {
  const sizes = await page.locator('input:visible, textarea:visible').evaluateAll((els) =>
    els.map((el) => ({
      fs: parseFloat(getComputedStyle(el).fontSize),
      tag: el.tagName.toLowerCase(),
      type: (el as HTMLInputElement).type ?? '',
    })),
  )
  expect(sizes.length, `${where}: expected some inputs`).toBeGreaterThan(0)
  for (const s of sizes) {
    expect(s.fs, `${where}: <${s.tag}${s.type ? ` type=${s.type}` : ''}> font-size ${s.fs}px must be >= 16 (iOS zoom guard)`).toBeGreaterThanOrEqual(16)
  }
}

for (const vp of VIEWPORTS) {
  test(`inputs @ ${vp.name}: no iOS-zoom sizes + fields fill`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height })
    await setupFixtures(page)
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

    // ── Create-database form ──────────────────────────────────────────────
    await page.getByLabel('Створити базу').click()
    await expect(page.getByText('Нова база')).toBeVisible()
    await assertNoZoomInputs(page, `${vp.name} · create-db`)

    const dbName = page.getByPlaceholder('БЦ Олімп')
    await dbName.fill('БЦ Тест')
    await expect(dbName).toHaveValue('БЦ Тест')       // filled
    const dbAddr = page.getByPlaceholder('Хрещатик 22')
    await dbAddr.fill('вул. Тестова, 5')
    await expect(dbAddr).toHaveValue('вул. Тестова, 5')

    // Reset to the list (create-db's back label is 'Бази', not 'Назад'; a fresh
    // load is the robust way back), then open a property form — more input types
    // (number / date / text).
    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText(/Всі \(\d\)/)).toBeVisible()
    await page.getByLabel("Додати об'єкт").click()
    await expect(page.getByText("Новий об'єкт")).toBeVisible()
    await assertNoZoomInputs(page, `${vp.name} · property-form`)

    // Fill numeric fields and confirm the derived rent preview reacts (заповненість)
    await page.getByPlaceholder('Офіс 101').fill('Тест-101')
    await page.getByPlaceholder('47').fill('50')       // useful area
    await page.getByPlaceholder('18').fill('20')       // rent rate ($/m²)
    await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Тест-101')
    await expect(page.getByPlaceholder('47')).toHaveValue('50')
    await expect(page.getByPlaceholder('18')).toHaveValue('20')
    // Filling area + rate drives the derived preview — the 'Розрахунок' row
    // appears only when rentCalc > 0 (locale-independent, unlike the $ number).
    await expect(page.getByText('Розрахунок').first()).toBeVisible()
  })
}

/**
 * Правила полів вводу, вистраждані на iOS. Три інваріанти, які раніше не
 * перевірялись жодним тестом і кожен уже ламався в проді:
 *
 * 1. **ЖОДНОГО `type="number"`.** Контрольований number-інпут повертає `''` на
 *    проміжному стані (друга крапка/кома) — «введене зникає»; скрол міняє
 *    значення. Правильно: `type="text"` + `inputMode` + санітайзер.
 * 2. **Числове поле має `inputMode`** — інакше на телефоні відкривається повна
 *    QWERTY замість цифрової панелі, і саме там користувач і друкує «1,200,000».
 * 3. **Каретковому полю потрібен власний композитний шар** (`translateZ(0)`):
 *    під `backdrop-filter` WebKit малює каретку зі зміщенням. date/select свідомо
 *    виключені — у них немає каретки, а стекінг-контекст клiпає нативні поповери.
 */
const fields = (page: Page) => page.evaluate(() =>
  [...document.querySelectorAll('input,textarea')]
    .filter((el) => (el as HTMLElement).offsetParent !== null || el.tagName === 'TEXTAREA')
    .map((el) => {
      const i = el as HTMLInputElement
      const cs = getComputedStyle(i)
      return {
        tag: i.tagName.toLowerCase(),
        type: i.type ?? '',
        inputMode: i.getAttribute('inputmode') ?? '',
        placeholder: i.placeholder ?? '',
        label: i.getAttribute('aria-label') ?? '',
        transform: cs.transform,
        fs: parseFloat(cs.fontSize),
      }
    }))

/** Екрани й модалки, де живуть усі види полів застосунку. */
async function walkForms(page: Page, visit: (label: string) => Promise<void>) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await visit('db-list')

  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible()
  await visit('create-db')

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(\d\)/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible({ timeout: 15_000 })
  await visit('property-form')

  // Частина полів існує лише в певному СТАНІ форми — «Ціна продажу» з'являється
  // тільки для статусу «Продаж». Без цього кроку гард до неї не дотягується:
  // навмисно зламане там `type="number"` не валило прогін.
  await page.locator('.fr-seg-b', { hasText: 'Продаж' }).click()
  await expect(page.getByLabel('Ціна продажу')).toBeVisible({ timeout: 10_000 })
  await visit('property-form/продаж')

  // Модалка оренди — найбільше числових і датових полів у застосунку.
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Здати в оренду/ })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Здати в оренду/ }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await visit('rent-modal')
}

test('поля вводу: жодного type=number, правильний inputMode, свій шар', async ({ page }) => {
  test.setTimeout(150_000)
  await setupFixtures(page)

  const numberType: string[] = []
  const noInputMode: string[] = []
  const noLayer: string[] = []
  const small: string[] = []
  let seen = 0

  await walkForms(page, async (label) => {
    for (const f of await fields(page)) {
      seen++
      const name = f.label || f.placeholder || `${f.tag}[${f.type}]`
      if (f.type === 'number') numberType.push(`${label}: «${name}»`)
      // Числове поле впізнаємо за санітайзером на вході: у проєкті це завжди
      // text+inputMode, тож ознакою слугує сам inputMode. Перевіряємо ЗВОРОТНЕ —
      // поле з числовим плейсхолдером, але без inputMode: там і буде QWERTY.
      if (f.type === 'text' && /^[\d\s.,]+$/.test(f.placeholder.trim()) && f.placeholder.trim() &&
          !['decimal', 'numeric'].includes(f.inputMode)) {
        noInputMode.push(`${label}: «${name}» плейсхолдер «${f.placeholder}» без inputMode`)
      }
      if (f.inputMode && !['decimal', 'numeric', 'text', 'search', 'tel', 'email', 'url', 'none'].includes(f.inputMode)) {
        noInputMode.push(`${label}: «${name}» невідомий inputMode="${f.inputMode}"`)
      }
      // Каретка є в text/tel/search/textarea; date/checkbox/radio/file — ні.
      const hasCaret = f.tag === 'textarea' || ['text', 'tel', 'search', 'email', 'url', 'password', ''].includes(f.type)
      if (hasCaret && f.transform === 'none') {
        noLayer.push(`${label}: «${name}» (${f.tag}[${f.type}]) без власного шару — каретка поїде під blur`)
      }
      if (f.fs < 16) small.push(`${label}: «${name}» ${f.fs}px`)
    }
  })

  expect(seen, 'полів не знайдено — обхід форм застарів').toBeGreaterThan(8)
  expect([...new Set(numberType)], 'type="number" заборонений: контрольований number губить проміжне введення').toEqual([])
  expect([...new Set(noInputMode)], 'числове поле без inputMode відкриває QWERTY замість цифр').toEqual([])
  expect([...new Set(noLayer)], 'каретковому полю потрібен translateZ(0) — інакше каретка зміщена під backdrop-filter').toEqual([])
  expect([...new Set(small)], 'поле дрібніше 16px — iOS зумить екран на фокусі').toEqual([])
})

test('тап по полю НЕ малює кільце фокуса, і платформа знає, що застосунок темний', async ({ page }) => {
  // Скріншот власника: тап по «Назва» давав синю рамку навколо поля. Причина —
  // мій же коментар у CSS стверджував, що «тач кільця не отримує». Для КНОПОК
  // це правда, для текстових полів ні: за специфікацією елемент, що очікує
  // введення тексту, матчить `:focus-visible` ЗАВЖДИ, хоч би як його
  // сфокусували. Тому кільце тепер за медіа-гейтом `pointer: fine`, а цей
  // проєкт (`isMobile+hasTouch`) дає саме `coarse` — тобто міряємо прод-випадок.
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // Антивакуумність: гейт мусить бути ВИМКНЕНИЙ саме тут, інакше тест «проходить»
  // на будь-якому CSS.
  const coarse = await page.evaluate(() => window.matchMedia('(pointer: coarse)').matches)
  expect(coarse, 'проєкт більше не тач — гард міряє не той випадок').toBe(true)

  // Клавіатура платформи бере вигляд звідси; без цього iOS малює СВІТЛУ плиту
  // поверх темного скла.
  const scheme = await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)
  expect(scheme, 'платформі не сказано, що застосунок темний — клавіатура і нативні поповери будуть світлі').toBe('dark')

  await page.getByRole('button', { name: /Створити базу|Нова база/ }).first().click()
  const name = page.locator('input.fr-i').first()
  await expect(name).toBeVisible({ timeout: 10_000 })
  await name.click()
  await expect(name).toBeFocused()

  const ring = await name.evaluate((el) => {
    const cs = getComputedStyle(el)
    return { w: parseFloat(cs.outlineWidth) || 0, style: cs.outlineStyle }
  })
  expect(ring.style === 'none' || ring.w === 0, `тап намалював кільце ${ring.w}px/${ring.style}`).toBe(true)
})

test('нижня смуга Telegram бере колір НИЗУ градієнта, а не чорний', async ({ page }) => {
  // Знайдено на записі з пристрою: коли клавіатура стискає webview, навколо її
  // панелі (в iOS 26 вона з заокругленими кутами) лишається ЧОРНА рамка.
  // Заміряно по кадру — `#070610` ліворуч і праворуч від клавіатури, тобто
  // рівно наш власний колір хрому, а не «баг Telegram»: ми ставили `#06050e`
  // і на ВЕРХ, і на НИЗ, хоч кожен градієнт закінчується світлим
  // (`.bg-blue` → #5480dc). Верх лишається темним — там градієнт справді
  // майже чорний.
  await setupFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  const bars = await page.evaluate(() => {
    const w = window as unknown as Record<string, string | undefined>
    const el = document.querySelector('#app-root .scr[class*="bg-"]') as HTMLElement | null
    return {
      bottom: (w.__tgBottomBarColor ?? '').toLowerCase(),
      bg: (w.__tgBgColor ?? '').toLowerCase(),
      header: (w.__tgHeaderColor ?? '').toLowerCase(),
      end: el ? getComputedStyle(el).getPropertyValue('--bg-end').trim().toLowerCase() : '',
    }
  })

  expect(bars.end, 'екран не має токена --bg-end — гард став би порожнім').toMatch(/^#[0-9a-f]{6}$/)
  expect(bars.bottom, 'нижня смуга лишилась чорною під світлим низом градієнта').toBe(bars.end)
  expect(bars.bg, 'фон webview лишився чорним — саме він і проглядає навколо клавіатури').toBe(bars.end)
  // Верх — навпаки, мусить лишатись темним разом із початком градієнта.
  expect(bars.header, 'верхня смуга не має брати колір низу').not.toBe(bars.end)
})
