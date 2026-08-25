import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Modal behaviour + data-entry: rent modal (live preview, validation),
// payment schedule SCREEN (range validation — full-screen route since phase 2
// of the modal rework), close affordances (backdrop, Escape), and the 16px
// anti-zoom guarantee for inputs INSIDE modals.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, rent_type: 'per_m2',
    rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
    parking_type: null, ev_charger: false,
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120 }),
  prop(2, {}), // Офіс 102 — вільний: ціль rent-модалки
  prop(3, {}),
]

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() === 'PATCH') {
      const body = JSON.parse(req.postData() ?? '{}')
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      const base = PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0]
      return json(route, { ...base, ...body })
    }
    if (req.method() === 'GET' && accept.includes('object')) {
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      return json(route, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    if (req.method() === 'GET') return json(route, PROPERTIES)
    return route.fallback()
  })
  await page.route('**/rest/v1/rent_payments**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    if (route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      return json(route, { id: '55550000-0000-0000-0000-000000000001', created_at: NOW, ...body })
    }
    // .maybeSingle() (PaymentScheduleScreen) asks for a single object via Accept.
    return json(route, accept.includes('object') ? null : [])
  })
  await page.route('**/rest/v1/rent_payment_records**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? null : [])
  })
  await page.route('**/rest/v1/property_folders**', (route) => json(route, [{
    id: '40000000-0000-0000-0000-0000000000a1', db_id: DB_ID, owner_id: USER.id,
    name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW,
  }]))
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

/** Меню бази — ActionSheet, що лишився після видалення Modal.tsx. */
async function openSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
}

async function openRentScreen(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  // Клік по заголовку — центр короткої картки влучає в рядок дій
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: 'Здати в оренду' }).first().click()
  // Оренда — ПОВНОЕКРАННИЙ маршрут (фаза 5). Чекаємо на поле, а не на текст:
  // «Здати в оренду» — це ще й підпис CTA самого екрана.
  await expect(page.getByLabel('Орендар')).toBeVisible({ timeout: 15_000 })
}

test('екран оренди: disabled CTA, live monthly preview, currency-aware unit labels', async ({ page }) => {
  await fixtures(page)
  await openRentScreen(page)

  // «Здати» must be disabled until the tenant is named
  const submit = page.getByRole('button', { name: 'Здати в оренду', exact: true })
  await expect(submit).toBeDisabled()

  // Одиниця несе валюту власника (USD → $), але живе тепер КОЛО ЗНАЧЕННЯ, а не в
  // підписі: у половинному полі «Експлуатаційні, $/м²» не вміщалось і ellipsis
  // зʼїдав саму одиницю — користувач не бачив, ставку за м² він вводить чи суму.
  await expect(page.getByText('Оренда', { exact: true })).toBeVisible()
  await expect(page.getByText('Експлуатаційні', { exact: true })).toBeVisible()
  expect(await page.locator('.fld-u').allInnerTexts()).toEqual(['$/м²', '$/м²'])

  // Live preview on the default basis (розрахункова/total area 52):
  // 52 м² × 20 + 52 м² × 5 = 1 300 — recomputes as you type
  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  await expect(submit).toBeEnabled()
  const rateInput = page.locator('.fld input[inputmode="decimal"]').first()
  const utilInput = page.locator('.fld input[inputmode="decimal"]').nth(1)
  await rateInput.fill('20')
  await expect(page.getByText('Разом на місяць')).toBeVisible()
  await expect(page.getByText(/\$1\s?040/)).toBeVisible()
  await utilInput.fill('5')
  await expect(page.getByText(/\$1\s?300/)).toBeVisible()

  // Усі поля екрана тримають поріг 16px проти автозуму iOS
  const sizes = await page.locator('.body input').evaluateAll(els =>
    els.map(el => parseFloat(getComputedStyle(el).fontSize)))
  for (const s of sizes) expect(s).toBeGreaterThanOrEqual(16)
})

test('екран оренди: lease that ends before it starts is rejected; valid save PATCHes', async ({ page }) => {
  await fixtures(page)
  const patches: Record<string, unknown>[] = []
  await page.route('**/rest/v1/properties?id=eq.*', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    const body = JSON.parse(route.request().postData() ?? '{}')
    patches.push(body)
    return json(route, { ...PROPERTIES[1], ...body })
  })
  await openRentScreen(page)

  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  const dates = page.locator('input[type="date"]')
  await dates.first().fill('2026-05-10')
  await dates.nth(1).fill('2026-05-01') // раніше початку

  await page.getByRole('button', { name: 'Здати в оренду', exact: true }).click()
  await expect(page.getByText('Дата закінчення оренди раніше початку')).toBeVisible()
  // Екран лишається відкритим, нічого не збережено
  await expect(page.getByLabel('Орендар')).toBeVisible()
  expect(patches).toHaveLength(0)

  await dates.nth(1).fill('2026-12-01')
  await page.getByRole('button', { name: 'Здати в оренду', exact: true }).click()
  await expect.poll(() => patches.length).toBe(1)
  expect(patches[0].status).toBe('occupied')
  expect(patches[0].tenant_name).toBe('ФОП Петренко')
  expect(patches[0].lease_end_date).toBe('2026-12-01')
})

test('modal closes on Escape and on backdrop tap, not on inner tap', async ({ page }) => {
  await fixtures(page)
  await openSheet(page)

  // Тап всередині модалки не закриває
  await page.locator('.modal-head').click()
  await expect(page.locator('.modal')).toBeVisible()

  // Escape закриває (десктопний Telegram / браузер)
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // Бекдроп закриває
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.locator('.modal-overlay').click({ position: { x: 10, y: 10 } })
  await expect(page.locator('.modal')).toHaveCount(0)
})

test('modal: swipe down on the header dismisses', async ({ page }) => {
  await fixtures(page)
  await openSheet(page)

  // Simulate a downward drag on the grabber/header past the dismiss threshold.
  await page.locator('.modal-head').evaluate((el) => {
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2
    const y = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, {
        touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true,
      }))
    }
    fire('touchstart', y)
    fire('touchmove', y + 70)
    fire('touchmove', y + 150)
    fire('touchend', y + 150, true)
  })

  await expect(page.locator('.modal')).toHaveCount(0)
})


test('nested modal fills the viewport, not the parent sheet', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Потрібен шит, ВСЕРЕДИНІ якого відкривається підтвердження. Після фази 4
  // таким лишився шит поширення: «Відкликати» кличе confirmAction, не
  // розмонтовуючи себе (меню бази, навпаки, демонтується — див. фазу 1).
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення', { exact: true }).click()
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByRole('button', { name: /Відкликати/ }).first().click()
  // Саме ЗАГОЛОВОК підтвердження (`.modal-h`), а не будь-який текст: підпис
  // рядка шита під ним збігається з тим самим регексом — strict mode violation.
  await expect(page.locator('.modal-h').filter({ hasText: /Відкликати/ }))
    .toBeVisible({ timeout: 10_000 })
  // Чекаємо, доки slide-up ЗАВЕРШИТЬСЯ, а не фіксовану паузу: під паралельним
  // навантаженням 500мс іноді не вистачало і замір ловив кадр анімації.
  await page.waitForFunction(() => {
    const ovs = document.querySelectorAll('.modal-overlay')
    const m = ovs[ovs.length - 1]?.querySelector('.modal') as HTMLElement | undefined
    if (!m) return false
    return m.getAnimations().every(a => a.playState !== 'running')
  }, undefined, { timeout: 5000 })

  // .modal має backdrop-filter → containing block для position:fixed нащадків.
  // Без порталу вкладений оверлей затискався в батьківський шит (плавав по
  // центру з чорною діркою знизу). Портал у <body> це лікує.
  const geo = await page.evaluate(() => {
    const ovs = [...document.querySelectorAll('.modal-overlay')]
    const last = ovs[ovs.length - 1] as HTMLElement
    const r = last.getBoundingClientRect()
    const modal = last.querySelector('.modal') as HTMLElement
    return {
      count: ovs.length, top: Math.round(r.top), height: Math.round(r.height),
      vh: window.innerHeight, modalBottom: Math.round(modal.getBoundingClientRect().bottom),
    }
  })
  expect(geo.count).toBe(2)
  expect(geo.top).toBe(0)
  expect(geo.height).toBe(geo.vh)
  expect(geo.modalBottom).toBe(geo.vh) // шит притиснутий до низу екрана
})

test('payment schedule screen: day outside 1–28 shows the range error; valid day saves', async ({ page }) => {
  // Фаза 2 переробки модалок: розклад платежів — повноекранний маршрут, не
  // шит. День і далі валідується тостом при сабміті, НЕ переведено на
  // disabled — свідомо не змінена поведінка в цій фазі.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  // «Платежі» переїхали з рядка картки в шит за кнопкою «⋯».
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-more').click()
  await page.waitForTimeout(420)
  await page.locator('.sheet-row').filter({ hasText: 'Платежі' }).click()
  // Заголовок залежить від входу: per-property — «Платежі — <назва>»
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })

  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()

  const dayInput = page.getByLabel('День місяця')
  await dayInput.fill('45')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await expect(page.getByText('День платежу має бути від 1 до 28')).toBeVisible()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible() // екран не закрився

  await dayInput.fill('10')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 10_000 })
})





// «поле у фокусі не ховається під кнопками дій навіть у затиснутій модалці» —
// видалено у фазі 2 переробки модалок: розклад платежів більше не шит, а
// повноекранний маршрут, і Modal-специфічна геометрія (`.modal-actions`)
// тут уже не застосовна. Еквівалентне покриття (поле не ховається під
// `.mbtn-flow`) — генерично в field-obstruction.spec.ts/keyboard-viewport.spec.ts.

test('кнопки дій шита — напівпрозоре скло', async ({ page }) => {
  // Дії були єдиними суцільними заливками в інтерфейсі, збудованому на склі.
  //
  // Носій змінився: раніше це був шит оренди з ПЕРВИННОЮ кнопкою «Здати», але
  // після фази 5 оренда — екран, а меню бази має лише «Скасувати». Єдиний
  // шит, що лишився з первинною дією, — підтвердження (`ConfirmHost`).
  //
  // Друга половина колишнього тесту («неактивна не через opacity») сюди не
  // переїхала СВІДОМО: тепер це стан екранної CTA, і його вже міряє
  // `design-system-runtime` на всіх 25 екранах — дублювати означало б мати
  // два джерела правди про одне правило.
  await fixtures(page)
  await openSheet(page)
  await page.getByText('Видалити базу', { exact: true }).click()
  await expect(page.locator('.modal-h').filter({ hasText: /Видалити/ }))
    .toBeVisible({ timeout: 10_000 })
  await page.waitForTimeout(420)

  const on = await page.evaluate(() => {
    const btn = [...document.querySelectorAll('.modal-btn')]
      .find((b) => (b.textContent ?? '').includes('Видалити')) as HTMLElement
    const cs = getComputedStyle(btn)
    return { cls: btn.className, bgImage: cs.backgroundImage, bf: cs.backdropFilter, opacity: cs.opacity }
  })
  expect(on.cls, 'дія шита — скляна').toContain('btn-glass')
  const alphas = [...on.bgImage.matchAll(/rgba\([^)]*?,\s*([\d.]+)\)/g)].map((m) => Number(m[1]))
  expect(alphas.length, 'фон — тонований градієнт').toBeGreaterThan(0)
  expect(Math.max(...alphas), 'жоден стоп не суцільний').toBeLessThan(0.8)
  expect(on.bf, 'liquid glass = блюр підкладки').toContain('blur')
  expect(parseFloat(on.opacity), 'кнопка не привид').toBe(1)
})


// ─── ПІДЙОМ НА ФОКУС: старт одночасно з клавіатурою ───────────────────────────
//
// Заміряно на записі з iPhone: клавіатура рушала на 3543 мс, шит — на 3691 мс.
// Лаг 148 мс — це не тривалість переходу, а ДЖЕРЕЛО: `visualViewport.resize` на
// WebKit приходить один раз, наприкінці анімації клавіатури. Слідкувати за нею
// покадрово неможливо (WebKit не перебудовує лейаут щокадру; потік дає лише
// `geometrychange` VirtualKeyboard API, і той є тільки в Chromium). Тому ми
// СТАРТУЄМО одночасно з нею, узявши висоту з кешу попереднього відкриття.

/**
 * Кеш висоти клавіатури для цього вʼюпорта, як його пише застосунок.
 *
 * Сідається ПІСЛЯ `goto`, а не в `addInitScript`, і це не стиль: `innerWidth/
 * innerHeight`, прочитані в init-скрипті, віддають вікно браузера ДО емуляції
 * (та сама пастка, що вже описана для `devices.spec.ts`) — ключ виходив чужий,
 * і кеш не знаходився. Застосунок читає його лише на `focusin`, тож сідати
 * після завантаження цілком вчасно.
 */
async function seedKbCache(page: Page, px: number) {
  await page.evaluate((h) => {
    localStorage.setItem('kb_h_v1', JSON.stringify({ [`${window.innerWidth}x${window.innerHeight}`]: h }))
  }, px)
}

const kbVar = (page: Page) => page.evaluate(() =>
  parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--keyboard-h')) || 0)

// Фаза 2 переробки модалок: розклад платежів — повноекранний маршрут
// (`payment-schedule`), не шит. `--keyboard-h` — глобальна змінна, яку
// пише `page.tsx` на будь-якому фокусі в будь-якому полі застосунку, тож
// цей набір лишається чинним 1:1 — репойнт на екран, не переписування.
async function openScheduleScreen(page: Page, kbCachePx = 0) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  if (kbCachePx > 0) await seedKbCache(page, kbCachePx)
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  // «Платежі» переїхали з рядка картки в шит за кнопкою «⋯».
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-more').click()
  await page.waitForTimeout(420)
  await page.locator('.sheet-row').filter({ hasText: 'Платежі' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()
}

test('шит підіймається ВІДРАЗУ на фокус, не чекаючи на resize', async ({ page }) => {
  await fixtures(page)
  await openScheduleScreen(page, 280)

  expect(await kbVar(page), 'до фокуса підйому бути не може').toBe(0)

  await page.getByLabel('День місяця').focus()
  // Один кадр — саме те вікно, якого бракувало: значення мусить зʼявитись без
  // жодного `resize`, бо його ніхто не надсилав.
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))))
  expect(await kbVar(page), 'підйом не стартував на фокус — лаг лишився').toBe(280)
})

test('без кешу поведінка лишається сьогоднішньою — жодних здогадів', async ({ page }) => {
  // Антивакуумність до попереднього: підйом мусить залежати САМЕ від кешу, а не
  // спрацьовувати завжди. Перший фокус на новому пристрої не має чим ризикувати.
  await fixtures(page)
  await openScheduleScreen(page)
  await page.getByLabel('День місяця').focus()
  await page.waitForTimeout(120)
  expect(await kbVar(page), 'підйом на порожньому кеші — це здогад, а не замір').toBe(0)
})

test('справжня висота ПЕРЕТИРАЄ передбачену, а не додається до неї', async ({ page }) => {
  await fixtures(page)
  await openScheduleScreen(page, 280)
  await page.getByLabel('День місяця').focus()
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))))
  expect(await kbVar(page)).toBe(280)

  // Підміна РЕАЛІСТИЧНА: прямий запис у --keyboard-h стер би `applyKeyboardFromVV`,
  // який рахує висоту з незміненого вʼюпорта (пастка вже в CLAUDE.md).
  await page.evaluate(() => {
    const vv = window.visualViewport!
    Object.defineProperty(vv, 'height', { get: () => window.innerHeight - 310, configurable: true })
    vv.dispatchEvent(new Event('resize'))
  })
  await page.waitForTimeout(80)
  expect(await kbVar(page), '280 + 310 = подвійний ліфт; має бути рівно 310').toBe(310)
})

test('непідтверджений підйом знімає сам себе', async ({ page }) => {
  // Апаратна клавіатура на планшеті: фокус є, OSK немає, resize не прийде.
  // Без само-скасування шит завис би піднятим на порожнє місце.
  await fixtures(page)
  await openScheduleScreen(page, 280)
  await page.getByLabel('День місяця').focus()
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))))
  expect(await kbVar(page)).toBe(280)

  await page.waitForTimeout(900)
  expect(await kbVar(page), 'підйом без підтвердження мусить зникнути').toBe(0)
})

test('на клієнті, що СТИСКАЄ лейаут, підйому на фокус немає', async ({ page }) => {
  // Найдорожчий інваріант цього раунду: подвійний ліфт уже коштував окремого
  // раунду. Кеш наповнюється лише з `innerHeight − vv.height > 0`, тобто лише
  // там, де клавіатура НАКРИВАЄ. Тут же прямо перевіряємо гілку стискання.
  await fixtures(page)
  await openScheduleScreen(page)

  const size = page.viewportSize()!
  await page.setViewportSize({ width: size.width, height: size.height - 300 })
  // Кеш сідається ПІСЛЯ ресайзу, і це не дрібниця: ключ залежить від геометрії,
  // тож посіяний до ресайзу він просто не знаходився б — і гард проходив би
  // ВАКУУМНО, тобто зеленим навіть із прибраною умовою стискання. Наступано.
  await seedKbCache(page, 280)
  await page.evaluate(() => {
    const w = window as unknown as { __tgViewportStable?: (h: number) => void; __tgKeyboard?: (h: number) => void }
    w.__tgViewportStable?.(667)
    w.__tgKeyboard?.(300)
  })
  await page.waitForTimeout(120)

  await page.getByLabel('День місяця').focus()
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r(null))))
  expect(await kbVar(page), 'лейаут уже без клавіатури — наш ліфт відняв би її вдруге').toBe(0)
})

// ─── ВИДАЛЕНО РАЗОМ ІЗ `Modal.tsx` (фаза 5) ──────────────────────────────────
//
// Шість тестів перевіряли КЛАВІАТУРНУ ЕВРИСТИКУ `Modal.tsx`: пробу висоти з
// підтвердженням, фолбек `KB_FALLBACK_PX` із самоскасуванням, подвійний сигнал
// стискання лейауту, зняття блюру під клавіатурний рух, анімацію `max-height`.
// Кожен із них колись знайшов справжній production-баг, і кожен ловив свій.
//
// Файла більше немає: усі шити з полями стали повноекранними маршрутами, де
// клавіатуру тримає ОДНА глобальна `--keyboard-h` з `page.tsx`, а власної
// евристики немає ні в кого. Тобто інваріанти цих гардів не можуть настати —
// а гард, який не здатен упасти, лише додає зелені (те саме правило, за яким
// раніше прибрано тест про `.batchbar`).
//
// Що лишилось замість них: сюїта «ПІДЙОМ НА ФОКУС» нижче — вона міряє саме
// глобальну змінну й агностична до того, шит це чи екран.
