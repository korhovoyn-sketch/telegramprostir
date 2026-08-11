import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'
import { measureContrast, belowAA, smallTargets } from './helpers/contrast'

/**
 * Читабельність і досяжність — ГАРД, а не замір.
 *
 * До цього обидві метрики жили в `_contrast.spec.ts`, який не входить у прогін:
 * друкував таблицю і нічого не блокував. Тобто відомий борг (8 текстових блоків
 * нижче WCAG AA, `.view-seg-b` 38px) міг тихо рости — девʼятого ніхто б не
 * помітив.
 *
 * Тому база ЗАМОРОЖЕНА: кожен наявний борг перелічений із причиною, а будь-який
 * НОВИЙ блок нижче AA або новий контрол під 44px валить прогін. Кількість на
 * екран теж зафіксована — щоб борг не розростався всередині вже дозволеного
 * класу.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'

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
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * Заморожений борг контрасту. Ключ — власний клас блока (або «батько>тег» для
 * безкласового вузла). Жоден із них НЕ лікується альфою тексту: це або білий
 * підпис на світлому тонованому блоці (брайтити нікуди), або тонований бейдж із
 * власною заливкою, або свідомо приглушений неактивний сегмент.
 *
 * Окреме рішення власника проєкту: правити ДАНІ, підписи лишити. Усе нижче —
 * підписи й допоміжні капшени; самі цифри (`.dash-n`, `.obj-tot-v`, ставки)
 * порогу відповідають.
 */
const CONTRAST_DEBT: ReadonlySet<string> = new Set([
  // Плитки дашборда бази: 11px капшен `--t4` над СВІТЛИМ тонованим блоком.
  'dash-sub',
  // Підпис плитки дашборда, 11px/600 — той самий світлий блок.
  'dash-l',
  // Неактивний сегмент мови/валюти в Профілі: приглушеність тут і є станом.
  'fr-seg-b',
  // Тонований бейдж «Скоро» — foreground на тлі власної заливки.
  'bdg',
  // Оверлайн секції Профілю: 11px/600 uppercase, безкласовий <span> у `.over`.
  'over>span',
  // Капшен «оренда + експлуатаційні» під сумою картки: темніший ґрунт
  // (.obj-tot) прибрано за проханням (виглядав як зайва плашка). 4.38:1 —
  // на волосок нижче AA (4.5), сама сума (.obj-tot-v) лишається над порогом.
  'obj-tot-sub',
])

/** Скільки блоків нижче AA дозволено на екран — щоб борг не ріс у своєму класі. */
const FROZEN: Record<string, number> = {
  'db-list': 0,
  // 3 × `.dash-sub` + 2 × `.dash-l` — підписи плиток дашборда; +1 ×
  // `.obj-tot-sub` — капшен суми картки після зняття темного ґрунту.
  'db-objects': 6,
  'property-detail': 0,
  // `.over>span` + 2 × `.fr-seg-b` + `.bdg-info`.
  profile: 4,
}

async function auditScreen(page: Page, label: string) {
  const rows = await measureContrast(page)
  expect(rows.length, `${label}: текстових блоків не знайдено — вибірка застаріла`).toBeGreaterThan(5)
  const bad = belowAA(rows)

  const unexpected = bad
    .filter((b) => !CONTRAST_DEBT.has(b.key))
    .map((b) => `${b.ratio}:1 (треба ${b.need}) ${b.size}px/${b.weight} «${b.text}» .${b.cls} [${b.key}]`)
  expect([...new Set(unexpected)],
    `${label}: НОВИЙ текст нижче WCAG AA — або підніми контраст, або додай у CONTRAST_DEBT із причиною`)
    .toEqual([])

  expect(bad.length,
    `${label}: блоків нижче AA стало ${bad.length}, заморожено ${FROZEN[label]} — борг виріс усередині дозволеного класу`)
    .toBeLessThanOrEqual(FROZEN[label])
}

test('контраст тексту: список баз і об\'єкти бази', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(700)
  await auditScreen(page, 'db-list')

  // Замір робить текст прозорим НЕОБОРОТНО, тож наступний екран — з чистого старту.
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await auditScreen(page, 'db-objects')
})

test('контраст тексту: детальна картка і профіль', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)

  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await auditScreen(page, 'property-detail')

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(700)
  await auditScreen(page, 'profile')
})

/**
 * Заморожений борг зони дотику. `.view-seg-b` — квадратні кнопки-іконки
 * «Картки / Компактно» 38px впритул одна до одної в спільній обгородці:
 * розширення вкрало б тап у сусідню, тож це рішення про геометрію пари, а не
 * про сам контрол. Решта дрібних контролів отримала невидимий `::after` до 44px.
 */
const TAP_DEBT: ReadonlySet<string> = new Set(['view-seg-b'])

test('фактична зона дотику — 44px (Apple HIG)', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  const steps: [string, () => Promise<void>][] = [
    ['db-list', async () => {
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    }],
    ['db-objects', async () => {
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
    }],
    ['property-detail', async () => {
      await page.locator('.obj-card').first().locator('.obj-t').click()
      await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await expect(page.getByText('Сповіщення').first()).toBeVisible({ timeout: 15_000 })
    }],
  ]

  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const small = await smallTargets(page, 44)
    const unexpected = [...new Set(small
      .filter((s) => !TAP_DEBT.has(s.key))
      .map((s) => `.${s.cls} «${s.label}» ${s.w}×${s.h}`))]
    expect(unexpected,
      `${label}: контрол під 44px по ФАКТИЧНІЙ зоні дотику — розшир зону через ::after або додай у TAP_DEBT`)
      .toEqual([])
  }
})

test('розширена зона дотику нікому не краде тапи', async ({ page }) => {
  test.setTimeout(120_000)
  await setup(page)
  // Невидимий `::after` на 44px — компроміс: вигляд рядка лишається, зона росте.
  // Ціна помилки — вкрадений тап у сусідній контрол, тож промацуємо центр і краї
  // розширеної зони і дивимось, у ЩО фактично влучає палець.
  const steps: [string, () => Promise<void>][] = [
    ['db-objects', async () => {
      await page.goto('/')
      await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await expect(page.getByText('Сповіщення').first()).toBeVisible({ timeout: 15_000 })
    }],
  ]
  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const stolen = await page.evaluate(() => {
      const bad: string[] = []
      const bar = document.querySelector('.tabbar') as HTMLElement | null
      const fold = bar ? bar.getBoundingClientRect().top : window.innerHeight
      const targets = [...document.querySelectorAll('.seg-b,.view-seg-b,.fr-seg-b,.notif-tab,.hdr-back')] as HTMLElement[]
      for (const t of targets) {
        const r = t.getBoundingClientRect()
        if (r.width < 4 || r.top < 0 || r.bottom > fold) continue
        for (const dy of [-20, 0, 20]) {
          const x = Math.round(r.left + r.width / 2)
          const y = Math.round(r.top + r.height / 2 + dy)
          if (y < 1 || y > fold - 1) continue
          const hit = document.elementFromPoint(x, y)
          if (!hit) continue
          const ownTarget = hit === t || t.contains(hit) || hit.contains(t)
          const other = (hit as HTMLElement).closest('button,[role="button"],a,.sheet-row,.obj-card,.row,.notif-row')
          if (!ownTarget && other && !t.contains(other)) {
            bad.push(`${(t.className || '').toString().slice(0, 18)} @${dy > 0 ? '+' : ''}${dy} → ${(other.className || other.tagName).toString().slice(0, 24)}`)
          }
        }
      }
      return bad
    })
    expect([...new Set(stolen)], `${label}: розширена зона краде тап у сусідній контрол`).toEqual([])
  }
})

test('дії останньої картки не ховаються під таббаром', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  // Саме в самому низу дії останньої картки зустрічаються з таббаром.
  await page.evaluate(() => {
    const b = document.querySelector('.body') as HTMLElement
    b.scrollTop = b.scrollHeight
  })
  await page.waitForTimeout(600)

  const res = await page.evaluate(() => {
    const bar = document.querySelector('.tabbar') as HTMLElement
    const barTop = bar.getBoundingClientRect().top
    const acts = [...document.querySelectorAll('.obj-act-btn')] as HTMLElement[]
    const last = acts[acts.length - 1]
    const r = last?.getBoundingClientRect()
    const cx = r ? Math.round(r.left + r.width / 2) : 0
    const cy = r ? Math.round(r.top + r.height / 2) : 0
    const hit = r ? document.elementFromPoint(cx, cy) : null
    return {
      found: !!r,
      overlap: r ? Math.round(r.bottom - barTop) : -1,
      hitClass: hit ? (hit.className?.toString().slice(0, 30) || hit.tagName) : 'нічого',
      hitIsAction: !!hit?.closest('.obj-act-btn'),
    }
  })
  expect(res.found, 'дій картки не знайдено — селектор застарів').toBe(true)
  expect(res.overlap, `остання дія залазить під таббар на ${res.overlap}px`).toBeLessThanOrEqual(0)
  expect(res.hitIsAction, `тап у центр останньої дії влучає в ${res.hitClass}, а не в кнопку`).toBe(true)
})
