import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'
import { readFileSync } from 'node:fs'

/**
 * Єдність дизайн-системи по РЕНДЕРУ, а не по джерелу.
 *
 * `design-tokens.test.ts` читає CSS/TSX як текст. Він не побачить двох «майже
 * однакових» скляних поверхонь із різним блюром, радіуса, доданого інлайн-стилем
 * у TSX, чи розміру шрифту поза шкалою — бо все це існує лише в computed style.
 * Саме такий дрейф і виглядає як «дизайн розʼїхався», хоч кожен окремий файл
 * проходить перевірку.
 *
 * Джерело правди — `:root` у globals.css: шкали парсяться звідти, а не
 * дублюються тут. Інакше гард сам став би другим джерелом правди.
 */

const CSS = readFileSync('src/app/globals.css', 'utf8')
const stripComments = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, '')
const root = stripComments(CSS).match(/:root\{([\s\S]*?)\n\}/)![1]

/** Значення токенів зі шкали за префіксом: `--fs-` → {10,11,12,…}. */
function scale(prefix: string): Set<number> {
  const out = new Set<number>()
  for (const m of root.matchAll(new RegExp(`${prefix}[a-z0-9]+\\s*:\\s*([\\d.]+)px`, 'g'))) {
    out.add(Number(m[1]))
  }
  return out
}
const FS = scale('--fs-')
const RADII = scale('--r-')

/**
 * Класи з ПЛАВНИМ розміром шрифту (`clamp(...)` / `vw`): їхнє значення
 * інтерполюється від ширини екрана, тож у шкалу воно не попадає в принципі —
 * `.display` це `clamp(22px,6vw,26px)`, на 375px дає 22.5px. Межі clamp на
 * шкалі, проміжне значення ні, і це навмисно.
 *
 * Перелік виводиться з ДЖЕРЕЛА, не хардкодиться: новий плавний клас пройде
 * автоматично, а новий ФІКСОВАНИЙ розмір поза шкалою — впаде.
 */
const FLUID = new Set(
  [...stripComments(CSS).matchAll(/\.([a-z][a-z0-9-]*)\{[^}]*font-size:\s*(?:clamp\(|[^;}]*vw)/g)]
    .map((m) => m[1]),
)

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const FOLDER_ID = '50000000-0000-0000-0000-000000000001'
const FOLDERS = [{
  id: FOLDER_ID, db_id: DB_ID, owner_id: USER.id, name: 'Орендарі',
  sort_order: 1, created_at: NOW, updated_at: NOW,
}]
const PROPS = [1, 2].map((i) => ({
  id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс 10${i}`, floor: String(i), status: i === 1 ? 'occupied' : 'free',
  area_useful: 100, area_total: 120, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: i === 1 ? FOLDER_ID : null,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: i === 1 ? 'ТОВ «Ромашка»' : null, lease_start_date: '2025-01-01',
  lease_end_date: '2026-01-01', sort_order: i,
  share_token: `bb0000000000000000001${i}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}))

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : PROPS))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  await page.route('**/rest/v1/property_folders**', (r) => json(r, FOLDERS))
  for (const t of ['property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

/** Екрани, на яких збираємо computed styles. */
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

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
  await visit('profile')
}

test('РЕЦЕПТ скла однієї родини ідентичний на всіх екранах', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  // Стверджуємо саме `backdrop-filter` — рецепт скла. Він і є тим, що тихо
  // дрейфує: два «майже однакові» блюри виглядають як розʼїхана система, а в
  // джерелі кожен файл окремо валідний.
  //
  // СВІДОМО не змішуємо сюди фон і радіус: фон несе СЕМАНТИКУ (зелена плитка
  // доходу — це `--ok-bg`, не дрейф), а радіус контекстний (16px картка проти
  // 12px рядок налаштувань) і перевіряється окремим тестом проти шкали токенів.
  const seen = new Map<string, Map<string, string[]>>()

  await walk(page, async (label) => {
    const found = await page.evaluate(() => {
      const out: { cls: string; sig: string }[] = []
      for (const cls of ['glass-s', 'glass', 'glass-d']) {
        document.querySelectorAll(`.${cls}`).forEach((el) => {
          // Точний клас: `.glass-s` не має потрапляти у вибірку `.glass`.
          if (!el.classList.contains(cls)) return
          if (cls === 'glass' && (el.classList.contains('glass-s') || el.classList.contains('glass-d'))) return
          const cs = getComputedStyle(el)
          out.push({ cls, sig: cs.backdropFilter })
        })
      }
      return out
    })
    for (const { cls, sig } of found) {
      const m = seen.get(cls) ?? new Map<string, string[]>()
      m.set(sig, [...(m.get(sig) ?? []), label])
      seen.set(cls, m)
    }
  })

  for (const [cls, sigs] of seen) {
    const variants = [...sigs.entries()].map(([sig, where]) => `${sig} @ ${[...new Set(where)].join(',')}`)
    expect(variants, `.${cls}: рецепт скла мусить бути один, а варіантів ${variants.length}`)
      .toHaveLength(1)
  }
  expect(seen.size, 'жодної скляної поверхні не знайдено — селектори застаріли').toBeGreaterThan(0)
})

test('радіуси й розміри шрифту — лише зі шкали токенів', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  const badRadius = new Set<string>()
  const badFont = new Set<string>()

  await walk(page, async (label) => {
    const res = await page.evaluate(() => {
      const radii: { v: string; cls: string }[] = []
      const fonts: { v: number; cls: string; text: string }[] = []
      document.querySelectorAll('*').forEach((el) => {
        const cs = getComputedStyle(el)
        const cls = (el.className?.toString() || el.tagName.toLowerCase()).slice(0, 24)
        // Радіус: беремо лише однорідні (усі кути рівні) — інакше рядок
        // «14px 14px 0 0» не порівняти зі шкалою, а такі форми свідомі.
        const r = cs.borderRadius
        if (r && r !== '0px' && !r.includes(' ') && !r.includes('%')) radii.push({ v: r, cls })
        const fs = parseFloat(cs.fontSize)
        // Тільки елементи з ВЛАСНИМ текстом: успадкований розмір перевіряти
        // безглуздо, він уже перевірений на батькові.
        const own = [...el.childNodes].some((n) => n.nodeType === 3 && (n.textContent ?? '').trim().length > 1)
        if (own && fs) fonts.push({ v: fs, cls, text: (el.textContent ?? '').trim().slice(0, 18) })
      })
      return { radii, fonts }
    })
    for (const r of res.radii) {
      const px = parseFloat(r.v)
      // ПОХІДНА геометрія: радіус обчислений із розміру елемента, а не обраний зі
      // шкали. `.dash-bar` — 2px на смузі висотою 3px (волосинка); `.view-seg-b` —
      // 9px усередині обгортки з радіусом 11 і падінгом 2 (11−2). Ставити тут
      // токен означало б зламати геометрію, а не вирівняти систему.
      const derived = (px === 2 && r.cls.startsWith('dash-bar')) || (px === 9 && r.cls.startsWith('view-seg-b'))
      if (!RADII.has(px) && !derived) badRadius.add(`${label}: ${r.v} на .${r.cls}`)
    }
    for (const f of res.fonts) {
      const fluid = f.cls.split(/\s+/).some((c) => FLUID.has(c))
      if (!FS.has(f.v) && !fluid) badFont.add(`${label}: ${f.v}px «${f.text}» на .${f.cls}`)
    }
  })

  expect([...badRadius], `радіус поза шкалою --r-* (${[...RADII].sort((a, b) => a - b).join('/')}px)`).toEqual([])
  expect([...badFont], `розмір шрифту поза шкалою --fs-* (${[...FS].sort((a, b) => a - b).join('/')}px)`).toEqual([])
})

test('неактивна кнопка — нейтральне скло, а не привид', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible()

  // Правило проєкту: над темним шитом `opacity:.45` робив кнопку невидимою, тож
  // неактивна лишається повністю непрозорою, змінюючи лише заливку.
  const disabled = await page.evaluate(() => {
    const btns = [...document.querySelectorAll('button')] as HTMLButtonElement[]
    return btns.filter((b) => b.disabled).map((b) => ({
      cls: b.className.slice(0, 28),
      opacity: Number(getComputedStyle(b).opacity),
      label: (b.textContent || '').trim().slice(0, 20),
    }))
  })
  for (const d of disabled) {
    expect(d.opacity, `«${d.label}» (.${d.cls}) неактивна через прозорість — над темним фоном вона зникне`)
      .toBeGreaterThanOrEqual(0.9)
  }
})
