import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Modal behaviour + data-entry: rent modal (live preview, validation),
// schedule modal (range validation), close affordances (backdrop, Escape),
// and the 16px anti-zoom guarantee for inputs INSIDE modals.

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
    if (route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      return json(route, { id: '55550000-0000-0000-0000-000000000001', created_at: NOW, ...body })
    }
    return json(route, [])
  })
  await page.route('**/rest/v1/rent_payment_records**', (route) => json(route, []))
  await page.route('**/rest/v1/property_folders**', (route) => json(route, [{
    id: '40000000-0000-0000-0000-0000000000a1', db_id: DB_ID, owner_id: USER.id,
    name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW,
  }]))
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openRentModal(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  // Клік по заголовку — центр короткої картки влучає в рядок дій
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  // Чекати на ТЕКСТ тут не можна: «Здати в оренду» — це ще й підпис самої
  // плаваючої кнопки, яка лишається в DOM під шитом, тож `.first()` матчив її
  // і повертав керування ДО монтування модалки (`document.querySelector('.modal')`
  // → null → getComputedStyle кидав). Чекаємо на сам шит.
  await expect(page.locator('.modal')).toBeVisible()
  await expect(page.locator('.modal').getByText('Здати в оренду', { exact: true })).toBeVisible()
}

test('rent modal: disabled CTA, live monthly preview, currency-aware unit labels', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)

  // «Здати» must be disabled until the tenant is named
  const submit = page.getByRole('button', { name: 'Здати', exact: true })
  await expect(submit).toBeDisabled()

  // Одиниця несе валюту власника (USD → $), але живе тепер КОЛО ЗНАЧЕННЯ, а не в
  // підписі: у половинному полі «Експлуатаційні, $/м²» не вміщалось і ellipsis
  // зʼїдав саму одиницю — користувач не бачив, ставку за м² він вводить чи суму.
  await expect(page.locator('.modal').getByText('Оренда', { exact: true })).toBeVisible()
  await expect(page.locator('.modal').getByText('Експлуатаційні', { exact: true })).toBeVisible()
  expect(await page.locator('.modal .fld-u').allInnerTexts()).toEqual(['$/м²', '$/м²'])

  // Live preview on the default basis (розрахункова/total area 52):
  // 52 м² × 20 + 52 м² × 5 = 1 300 — recomputes as you type
  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  await expect(submit).toBeEnabled()
  const rateInput = page.locator('.modal .fld input[inputmode="decimal"]').first()
  const utilInput = page.locator('.modal .fld input[inputmode="decimal"]').nth(1)
  await rateInput.fill('20')
  await expect(page.getByText('Разом на місяць')).toBeVisible()
  await expect(page.locator('.modal').getByText(/\$1\s?040/)).toBeVisible()
  await utilInput.fill('5')
  await expect(page.locator('.modal').getByText(/\$1\s?300/)).toBeVisible()

  // All modal inputs obey the 16px anti-zoom floor
  const sizes = await page.locator('.modal input').evaluateAll(els =>
    els.map(el => parseFloat(getComputedStyle(el).fontSize)))
  for (const s of sizes) expect(s).toBeGreaterThanOrEqual(16)
})

test('rent modal: lease that ends before it starts is rejected; valid save PATCHes', async ({ page }) => {
  await fixtures(page)
  const patches: Record<string, unknown>[] = []
  await page.route('**/rest/v1/properties?id=eq.*', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    const body = JSON.parse(route.request().postData() ?? '{}')
    patches.push(body)
    return json(route, { ...PROPERTIES[1], ...body })
  })
  await openRentModal(page)

  await page.getByPlaceholder('ТОВ «Назва» або ФОП').fill('ФОП Петренко')
  const dates = page.locator('.modal input[type="date"]')
  await dates.first().fill('2026-05-10')
  await dates.nth(1).fill('2026-05-01') // раніше початку

  await page.getByRole('button', { name: 'Здати', exact: true }).click()
  await expect(page.getByText('Дата закінчення оренди раніше початку')).toBeVisible()
  // Модалка лишається відкритою, нічого не збережено
  await expect(page.locator('.modal')).toBeVisible()
  expect(patches).toHaveLength(0)

  await dates.nth(1).fill('2026-12-01')
  await page.getByRole('button', { name: 'Здати', exact: true }).click()
  await expect.poll(() => patches.length).toBe(1)
  expect(patches[0].status).toBe('occupied')
  expect(patches[0].tenant_name).toBe('ФОП Петренко')
  expect(patches[0].lease_end_date).toBe('2026-12-01')
})

test('modal closes on Escape and on backdrop tap, not on inner tap', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)

  // Тап всередині модалки не закриває
  await page.locator('.modal-head').click()
  await expect(page.locator('.modal')).toBeVisible()

  // Escape закриває (десктопний Telegram / браузер)
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // Бекдроп закриває
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.locator('.modal-overlay').click({ position: { x: 10, y: 10 } })
  await expect(page.locator('.modal')).toHaveCount(0)
})

test('modal: swipe down on the header dismisses', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)

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

test('modal не схлопується при некоректній висоті клавіатури', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)
  await page.waitForTimeout(400)
  const before = await page.locator('.modal').boundingBox()
  expect(before!.height).toBeGreaterThan(100)

  // Платформа може повідомити абсурдну висоту клавіатури (iOS + зум/скрол у
  // Telegram). Без нижньої межі max-height ставав ≈0 і модалка ЗНИКАЛА,
  // лишаючи тільки затемнення — саме це користувач бачив як «не відкривається».
  for (const kb of [600, 900, 2000]) {
    await page.evaluate((k) => document.documentElement.style.setProperty('--keyboard-h', `${k}px`), kb)
    await page.waitForTimeout(250)
    const box = await page.locator('.modal').boundingBox()
    expect(box, `модалка існує при --keyboard-h:${kb}px`).not.toBeNull()
    expect(box!.height, `модалка не схлопнулась при --keyboard-h:${kb}px`).toBeGreaterThan(100)
    // Заголовок лишається читабельним
    await expect(page.getByText('Здати в оренду', { exact: true }).first()).toBeVisible()
  }
})

test('nested modal fills the viewport, not the parent sheet', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  // Меню бази → Папки → підтвердження видалення = модалка ВСЕРЕДИНІ модалки.
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText('Групуйте').first()).toBeVisible()
  await page.getByLabel('Видалити').first().click()
  await expect(page.getByText(/Видалити папку/)).toBeVisible()
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

test('schedule modal: day outside 1–28 shows the range error; valid day saves', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  // Заголовок залежить від входу: per-property — «Платежі — <назва>»
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })

  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  await dayInput.fill('45')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  await expect(page.getByText('День платежу має бути від 1 до 28')).toBeVisible()
  await expect(page.locator('.modal')).toBeVisible() // не закрилась

  await dayInput.fill('10')
  await page.getByRole('button', { name: /Зберегти|Створити/ }).click()
  await expect(page.locator('.modal')).toHaveCount(0, { timeout: 10_000 })
})

test('поле в модалці не залишається під клавіатурою, коли платформа її не рапортує', async ({ page }) => {
  // Реальний кейс: iOS у Telegram не ресайзить webview — і viewportChanged, і
  // visualViewport дають 0. Шит прив'язаний до низу, тож поля «День місяця» в
  // календарі платежів опинялись ПІД клавіатурою. Fallback-ліфт має підняти шит.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  const rest = (await dayInput.boundingBox())!
  const restBottom = rest.y + rest.height
  const vh = page.viewportSize()!.height
  expect(restBottom, 'у спокої поле стоїть низько — саме тут його з\'їдала клавіатура')
    .toBeGreaterThan(vh - 320)

  await dayInput.focus()
  // Ліфт застосовується після проби (350мс) + підтвердження (200мс) + перехід
  // padding-bottom (250мс).
  await page.waitForFunction(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement | null
    return !!ov && parseFloat(getComputedStyle(ov).paddingBottom) > 200
  }, undefined, { timeout: 5000 })
  await page.waitForTimeout(320)

  const lifted = (await dayInput.boundingBox())!
  const liftedBottom = lifted.y + lifted.height
  expect(liftedBottom, 'поле піднялось над зоною клавіатури').toBeLessThan(vh - 300)
  // Шит лишається цілим і читабельним
  const modal = (await page.locator('.modal').boundingBox())!
  expect(modal.height).toBeGreaterThan(100)
  expect(modal.y).toBeGreaterThanOrEqual(0)
  await expect(page.locator('.modal-h')).toBeVisible()

  // Знято фокус — шит опускається назад
  await dayInput.blur()
  await page.waitForFunction(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement | null
    return !!ov && parseFloat(getComputedStyle(ov).paddingBottom) < 20
  }, undefined, { timeout: 5000 })
})

test('ліфт вимикається, якщо справжня висота клавіатури приходить ПІЗНІШЕ за пробу', async ({ page }) => {
  // Реальний кейс із відео користувача: на iOS-оверлеї visualViewport.resize
  // іноді приходить пізніше за 350мс-пробу. Одноразовий замір рівно на цій межі
  // бачив «клавіатури ще нема», вмикав фейковий ліфт 320px ПОВЕРХ реальної
  // клавіатури, що вже відкривалась, — поле «Орендар» сіпалось і модалка
  // перекомпоновувалась на секунду-дві, поки нічого не приводило її до тями.
  await fixtures(page)
  await openRentModal(page)

  await page.locator('.modal input').first().focus()
  // Нічого не звітуємо ДО проби — фолбек мусить спрацювати (як і раніше).
  await page.waitForTimeout(600) // 350 проба + 200 підтвердження + запас
  const guessed = await page.evaluate(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return { inline: ov.style.getPropertyValue('--keyboard-h'), computed: parseFloat(getComputedStyle(ov).paddingBottom) }
  })
  expect(guessed.inline, 'фолбек застосувався фейковими 320px').toBe('320px')

  // Тепер, ПІЗНО, приходить справжня висота — так, як реальна клавіатура
  // відрапортувала б із запізненням. Headless Chromium не показує нативну
  // клавіатуру, тож підміняємо `visualViewport.height` напряму (getter на
  // прототипі, own-property на інстансі його затінює) — це той самий сигнал,
  // який на реальному iOS обробляє `applyKeyboardFromVV` у page.tsx й записує
  // в ГЛОБАЛЬНИЙ `--keyboard-h`. Проста подія `resize` без зміни `height`
  // нічого не симулює: `applyKeyboardFromVV` перерахував би 0 і сам стер би
  // будь-яке ручне значення `--keyboard-h`, яке виставив би тест.
  await page.evaluate(() => {
    const vv = window.visualViewport!
    Object.defineProperty(vv, 'height', { configurable: true, get: () => window.innerHeight - 260 })
    vv.dispatchEvent(new Event('resize'))
  })
  await page.waitForFunction(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return ov.style.getPropertyValue('--keyboard-h') === ''
  }, undefined, { timeout: 2000 })
  await page.waitForTimeout(300) // .25s padding-bottom transition — читаємо ПІСЛЯ

  const reconciled = await page.evaluate(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return {
      inline: ov.style.getPropertyValue('--keyboard-h'),
      computed: Math.round(parseFloat(getComputedStyle(ov).paddingBottom)),
    }
  })
  expect(reconciled.inline, 'локальний фейковий ліфт знято').toBe('')
  expect(reconciled.computed, 'падинг тепер зі справжньої висоти, не з вигаданої').toBe(260)
})

test('ліфт НЕ дублюється, коли платформа рапортує висоту клавіатури', async ({ page }) => {
  await fixtures(page)
  await openRentModal(page)
  // Android/веб: webview ресайзиться, --keyboard-h реальний. Тоді власного
  // ліфту бути не повинно — інакше шит підскочив би двічі.
  await page.evaluate(() => document.documentElement.style.setProperty('--keyboard-h', '300px'))
  await page.locator('.modal input').first().focus()
  await page.waitForTimeout(700)
  const pad = await page.evaluate(() => {
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return { inline: ov.style.getPropertyValue('--keyboard-h'), computed: parseFloat(getComputedStyle(ov).paddingBottom) }
  })
  expect(pad.inline, 'локальний fallback не застосовано').toBe('')
  expect(Math.round(pad.computed), 'працює лише реальна висота').toBe(300)
})

test('шит не СНЕПАЄ між висотами — max-height анімується так само, як padding-bottom', async ({ page }) => {
  // Реальний пристрій шле висоту клавіатури кількома тіками, поки вона сама
  // анімується (нормальна поведінка ОС, не баг сигналу). `.modal-overlay`'s
  // padding-bottom вже їде transition-ом (.25s), а .modal's max-height
  // перераховувався МИТТЄВО — шит візуально «стрибав»/«стискався» на кожен тік,
  // хоч кожне окреме значення було коректним. Відео користувача: «стискається
  // так, що з нею неможливо працювати».
  await fixtures(page)
  await openRentModal(page)
  const hasTransition = await page.evaluate(() => {
    const m = document.querySelector('.modal') as HTMLElement
    const cs = getComputedStyle(m)
    const idx = cs.transitionProperty.split(',').findIndex(p => p.trim() === 'max-height')
    if (idx === -1) return null
    return parseFloat(cs.transitionDuration.split(',')[idx] ?? cs.transitionDuration)
  })
  expect(hasTransition, 'max-height мусить мати ненульову transition-duration').not.toBeNull()
  expect(hasTransition).toBeGreaterThan(0)
})

test('поле у фокусі не ховається під кнопками дій навіть у затиснутій модалці', async ({ page }) => {
  // Реальний скрін від користувача: клавіатура стиснула шит, тіло стало
  // прокручуваним — і sticky-кнопки «Скасувати/Зберегти» накрили поле «День
  // місяця», у яке він саме друкував.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Платежі' }).click()
  await expect(page.getByText(/Платежі — Офіс 101|Календар платежів/)).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  // Затискаємо шит так само, як це робить клавіатура на пристрої
  await page.evaluate(() => document.documentElement.style.setProperty('--keyboard-h', '430px'))
  await page.waitForTimeout(400)

  const dayInput = page.locator('.modal input[inputmode="numeric"]').first()
  await dayInput.focus()
  await page.waitForTimeout(900)

  const geo = await page.evaluate(() => {
    const el = document.querySelector('.modal input[inputmode="numeric"]') as HTMLElement
    const act = document.querySelector('.modal-actions') as HTMLElement
    const f = el.getBoundingClientRect()
    const a = act.getBoundingClientRect()
    return { fieldBottom: Math.round(f.bottom), fieldTop: Math.round(f.top), actionsTop: Math.round(a.top) }
  })
  expect(geo.fieldBottom, 'нижній край поля вище за кнопки').toBeLessThanOrEqual(geo.actionsTop)
  expect(geo.fieldTop, 'поле не виїхало за верх екрана').toBeGreaterThan(0)
  await expect(dayInput).toBeVisible()
})

test('кнопки дій — напівпрозоре скло, неактивна лишається видимою', async ({ page }) => {
  // Дії були єдиними суцільними заливками в інтерфейсі, збудованому на склі.
  await fixtures(page)
  await openRentModal(page)
  await page.waitForTimeout(450)

  const cta = await page.evaluate(() => {
    const btn = [...document.querySelectorAll('.modal-btn')]
      .find((b) => (b.textContent ?? '').includes('Здати')) as HTMLElement
    const cs = getComputedStyle(btn)
    return { cls: btn.className, bgImage: cs.backgroundImage, bf: cs.backdropFilter, disabled: (btn as HTMLButtonElement).disabled }
  })
  expect(cta.cls, 'первинна дія — скляна').toContain('btn-glass')
  expect(cta.disabled, 'без орендаря кнопка неактивна').toBe(true)

  // Неактивна: нейтральне скло, а не привид (opacity .45 над темним шитом
  // робив кнопку майже невидимою)
  const offAlpha = await page.evaluate(() => parseFloat(getComputedStyle(
    [...document.querySelectorAll('.modal-btn')].find((b) => (b.textContent ?? '').includes('Здати'))!,
  ).opacity))
  expect(offAlpha).toBe(1)

  // Активуємо — тон стає кольоровим і НАПІВПРОЗОРИМ
  await page.locator('.modal input').first().fill('ТОВ «Ромашка»')
  await page.waitForTimeout(250)
  const on = await page.evaluate(() => {
    const btn = [...document.querySelectorAll('.modal-btn')]
      .find((b) => (b.textContent ?? '').includes('Здати')) as HTMLElement
    const cs = getComputedStyle(btn)
    return { bgImage: cs.backgroundImage, bf: cs.backdropFilter }
  })
  const alphas = [...on.bgImage.matchAll(/rgba\([^)]*?,\s*([\d.]+)\)/g)].map((m) => Number(m[1]))
  expect(alphas.length, 'фон — тонований градієнт').toBeGreaterThan(0)
  expect(Math.max(...alphas), 'жоден стоп не суцільний').toBeLessThan(0.8)
  expect(on.bf, 'liquid glass = блюр підкладки').toContain('blur')
})

test('шит НЕ підстрибує вгору, коли webview стиснувся, а Telegram про це не звітує', async ({ page }) => {
  // Реальний скріншот користувача (модалка «Папки»): шит відлетів у верх екрана,
  // під ним діра, унизу клавіатура. Це ПОДВІЙНИЙ ліфт — лейаут уже стиснувся під
  // клавіатуру, і шит підняв себе ще на KB_FALLBACK_PX поверх цього.
  //
  // Гард від подвійного ліфту існував, але питав про стискання САМЕ Telegram
  // (viewportHeight vs viewportStableHeight). Клієнт користувача webview стискав,
  // а цих значень не оновлював — тож гард казав «не стиснувся». Тут відтворюємо
  // рівно це: висоту вікна ріжемо, а __tgViewportStable/__tgKeyboard НЕ чіпаємо.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText('Групуйте').first()).toBeVisible()

  const size = page.viewportSize()!
  const modal = page.locator('.modal').last()
  await expect(modal).toBeVisible()

  // Телеграм мовчить: жодного __tgKeyboard / __tgViewportStable — лише реальне
  // стискання вікна, як робить сам клієнт.
  await page.setViewportSize({ width: size.width, height: size.height - 300 })
  await page.locator('.modal input').first().focus()
  // Довше за KB_PROBE_MS + KB_CONFIRM_MS + transition, щоб фолбек устиг би
  // увімкнутись, якби гард не спрацював.
  await page.waitForTimeout(1200)

  const gap = await page.evaluate(() => {
    const ov = document.querySelectorAll('.modal-overlay')
    const m = ov[ov.length - 1]?.querySelector('.modal') as HTMLElement
    return Math.round(window.innerHeight - m.getBoundingClientRect().bottom)
  })
  // Шит мусить лишатись ПРИКЛЕЄНИМ до низу вже стиснутого вікна. Клавіатуру
  // лейаут відняв сам; будь-який власний ліфт тут — це другий відлік.
  expect(gap, `шит відірвався від низу на ${gap}px — знову подвійний ліфт`).toBeLessThan(24)
})
