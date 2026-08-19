import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * Сітка безпеки під рефакторинг модалок.
 *
 * `Modal.tsx` УЖЕ має повний набір діалогової механіки — фокус переходить у шит,
 * повертається на опенер (APG), Tab і Shift+Tab заперті всередині, прокрутка фону
 * блокується, свайп нижче порога вертає шит на місце. І на все це немає ЖОДНОГО
 * тесту: у `tests/` ніхто не натискає Tab і не читає `activeElement` для перевірки
 * фокуса. Тобто будь-який рефакторинг ламає цю механіку МОВЧКИ — вона не видна ні
 * на скріншоті, ні в жодному з наявних 202 тестів.
 *
 * Ці гарди мусять зʼявитись ПЕРЕД змінами, а не після.
 */

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

function prop(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over,
  }
}
// Достатньо обʼєктів, щоб список під шитом був ДОВШИМ за екран — інакше перевірка
// блокування прокрутки фону нічого не означає.
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120 }),
  ...Array.from({ length: 8 }, (_, i) => prop(i + 2)),
]

const json = (route: Route, body: unknown) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
                   'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * Відкриває шит «Здати в оренду». Опенер — СПРАВЖНЯ кнопка (`.fbtn`), тож на ній
 * можна перевірити повернення фокуса.
 */
async function openRentSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  const opener = page.getByRole('button', { name: 'Здати в оренду' })
  await expect(opener).toBeVisible({ timeout: 15_000 })
  await opener.click()
  // Чекати на текст не можна: «Здати в оренду» — ще й підпис плаваючої кнопки під
  // шитом. Чекаємо на сам шит (див. CLAUDE.md про `.modal`, що перерішується).
  await expect(page.locator('.modal')).toBeVisible()
  await expect(page.locator('.modal').getByText('Здати в оренду', { exact: true })).toBeVisible()
}

/** Клас/тег елемента у фокусі — читабельніше за сирий HTML у повідомленні падіння. */
const activeDesc = (page: Page) => page.evaluate(() => {
  const a = document.activeElement as HTMLElement | null
  if (!a) return 'null'
  return `${a.tagName.toLowerCase()}.${(a.className || '').toString().trim().split(/\s+/)[0] || '-'}`
})

test('фокус іде в шит при відкритті і вертається на кнопку, що його відкрила', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // Фокус мусить бути ВСЕРЕДИНІ діалогу — інакше читалка лишається на екрані
  // під шитом і озвучує контент, якого користувач не бачить.
  const inside = await page.evaluate(() =>
    document.querySelector('.modal')?.contains(document.activeElement) ?? false)
  expect(inside, `фокус поза шитом: ${await activeDesc(page)}`).toBe(true)

  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // …і повернутись саме на опенер, а не на <body>: інакше після закриття Tab
  // починає обхід з початку екрана.
  const restored = await page.evaluate(() => {
    const a = document.activeElement as HTMLElement | null
    return !!a && a.classList.contains('fbtn')
  })
  expect(restored, `фокус не повернувся на опенер, зараз: ${await activeDesc(page)}`).toBe(true)
})

test('Tab і Shift+Tab не виводять фокус за межі шита', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  const focusableCount = await page.locator('.modal').evaluate((el) =>
    el.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])').length)
  // Гард від вакуумності: у шиті без фокусованих елементів пастка тримала б
  // фокус на контейнері, і тест проходив би, нічого не перевіряючи.
  expect(focusableCount, 'у шиті нема чого обходити — тест став би порожнім').toBeGreaterThan(2)

  // Обходимо ПОВНЕ коло плюс запас: якщо пастка не замикається, фокус вийде
  // на контент під шитом ще до кінця циклу.
  for (let i = 0; i < focusableCount + 3; i++) {
    await page.keyboard.press('Tab')
    const inside = await page.evaluate(() =>
      document.querySelector('.modal')?.contains(document.activeElement) ?? false)
    expect(inside, `Tab #${i + 1} вивів фокус за шит: ${await activeDesc(page)}`).toBe(true)
  }

  for (let i = 0; i < 4; i++) {
    await page.keyboard.press('Shift+Tab')
    const inside = await page.evaluate(() =>
      document.querySelector('.modal')?.contains(document.activeElement) ?? false)
    expect(inside, `Shift+Tab #${i + 1} вивів фокус за шит: ${await activeDesc(page)}`).toBe(true)
  }
})

test('прокрутка фону заблокована, поки шит відкритий, і відновлюється після', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })

  const before = await page.evaluate(() => document.body.style.overflow)

  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.locator('.modal')).toBeVisible()

  expect(await page.evaluate(() => document.body.style.overflow),
    'фон не заблокований, поки шит відкритий').toBe('hidden')

  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // Відновлення важливіше за саме блокування: протікле `overflow:hidden` лишає
  // застосунок незгортним назавжди, і жоден екран цього не покаже.
  expect(await page.evaluate(() => document.body.style.overflow),
    'блокування протекло після закриття шита').toBe(before)
})

/**
 * Синтезує вертикальний drag; `end` — чи відпускаємо палець.
 *
 * Кадри РОЗНЕСЕНІ в часі, і це принципово: `Modal` рахує швидкість жесту, тож
 * touchmove-и впритул один до одного описують не «повільний рух», а миттєвий
 * стрибок — тобто саме флік. Ця пастка вже спрацювала: гард «повільний рух не
 * закриває» падав, поки хелпер стріляв обома кадрами в один тік.
 */
async function drag(page: Page, selector: string, dy: number, end = true, stepMs = 120) {
  await page.locator(selector).evaluate(async (el, { dy, end, stepMs }) => {
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2
    const y0 = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, {
        touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true,
      }))
    }
    fire('touchstart', y0)
    await new Promise(res => setTimeout(res, stepMs))
    fire('touchmove', y0 + dy / 2)
    await new Promise(res => setTimeout(res, stepMs))
    fire('touchmove', y0 + dy)
    if (end) fire('touchend', y0 + dy, true)
  }, { dy, end, stepMs })
}

test('свайп НИЖЧЕ порога вертає шит і не лишає інлайнових стилів', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // 60px — свідомо менше за поріг 96px у Modal.tsx.
  await drag(page, '.modal-head', 60)
  await expect(page.locator('.modal'), 'свайп нижче порога закрив шит').toBeVisible()

  // Snap-back їде .24s; читаємо ПІСЛЯ переходу, інакше зловимо кадр анімації.
  await page.waitForTimeout(450)
  const left = await page.evaluate(() => {
    const m = document.querySelector('.modal') as HTMLElement
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return { transform: m.style.transform, opacity: ov.style.opacity }
  })
  // Інлайнові залишки — не косметика: вони переживають шит і перебивають CSS
  // при наступних анімаціях (transform лишався назавжди при тапі без руху).
  expect(left.transform, 'на шиті лишився інлайновий transform').toBe('')
  expect(left.opacity, 'на оверлеї лишилась інлайнова opacity').toBe('')
})

test('свайп, початий у ТІЛІ шита, не закриває його', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // Прокрутка вмісту не має конкурувати з жестом закриття: інакше кожна спроба
  // догорнути форму викидала б користувача з шита.
  await drag(page, '.modal-body', 160)
  await expect(page.locator('.modal'), 'свайп у тілі шита закрив його').toBeVisible()
})

// «Тап по бекдропу під час запиту НЕ лишає шит мертвим і незакривним» —
// видалено (фаза 3 переробки модалок, atomic-riding-clock.md). Приклад
// використовував «Запросити гостя», тепер повноекранний CreateInviteScreen:
// без бекдропу й без `requestClose` цей клас гарда не застосовний. Еквівалент
// («подвійний сабміт під час запиту не породжує другий insert») — робота на
// майбутнє: перевірка `disabled`-стану кнопки під час `saving`, той самий
// принцип, що вже застосований у PaymentScheduleScreen/PaymentConfirmScreen.

test('рядки шита досяжні з клавіатури і активуються Enter', async ({ page }) => {
  // Рядки меню бази були клікабельними `<div>`, тобто для фокус-пастки їх не
  // існувало: Tab у меню циклився між «Скасувати» і нічим, а сама навігація по
  // базі була недосяжна ні з клавіатури, ні для читалки.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()

  const rows = page.locator('.modal .sheet-row')
  const rowCount = await rows.count()
  expect(rowCount, 'у меню нема рядків — тест став би порожнім').toBeGreaterThan(3)
  // Кожен рядок мусить бути справжнім фокусованим контролом, а не div-ом.
  expect(await rows.evaluateAll((els) => els.map((e) => e.tagName.toLowerCase())))
    .toEqual(Array(rowCount).fill('button'))

  // Tab має дійти до рядків, а не застрягти на єдиній кнопці дій.
  let reached = ''
  for (let i = 0; i < rowCount + 2 && !reached; i++) {
    await page.keyboard.press('Tab')
    reached = await page.evaluate(() => {
      const a = document.activeElement as HTMLElement | null
      return a?.classList.contains('sheet-row') ? (a.textContent ?? '').trim() : ''
    })
  }
  expect(reached, 'Tab не дійшов ні до одного рядка меню').not.toBe('')

  // …і активація з клавіатури мусить справді працювати: доводимо переходом на
  // екран календаря платежів, до якого рядок веде.
  await page.keyboard.press('Tab')
  const focused = await page.evaluate(() => (document.activeElement?.textContent ?? '').trim())
  if (focused === 'Календар платежів') {
    await page.keyboard.press('Enter')
    await expect(page.getByText(/Календар платежів|Платежі —/)).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('.modal')).toHaveCount(0)
  }
})

test('фокус із клавіатури ВИДНО — і на рядках шита, і на хромі екрана', async ({ page }) => {
  // Друга половина фікса вище. Рядки стали `<button>` і Tab до них доходить —
  // але кільце фокуса в CSS існувало лише для `input`/`textarea`, тож дійшовши,
  // фокус був НЕВИДИМИЙ: навігація з клавіатури працювала всліпу, а тест вище
  // цього не бачив, бо читає `activeElement`, а не піксель.
  //
  // Міряємо `outlineWidth` на РЕАЛЬНО сфокусованому вузлі. `:focus-visible`
  // спрацьовує саме від клавіатури, тож ставити фокус через `.focus()` не можна
  // — Chromium тоді кільця не малює, і гард став би хибно червоним.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  const ringOfFocused = () => page.evaluate(() => {
    const a = document.activeElement as HTMLElement | null
    if (!a || a === document.body) return null
    const cs = getComputedStyle(a)
    return {
      tag: a.tagName.toLowerCase(),
      cls: (a.className || '').toString().slice(0, 40),
      width: parseFloat(cs.outlineWidth) || 0,
      style: cs.outlineStyle,
    }
  })

  // 1) Хром екрана: перший фокусований НЕ-поле контрол на db-list.
  //
  // Поля пропускаємо СВІДОМО, і це не послаблення гарда. `:focus-visible` не
  // означає «лише з клавіатури»: за специфікацією елемент, що очікує введення
  // тексту, матчить його ЗАВЖДИ — тобто на тачі кожен ТАП по полю малював синю
  // рамку (скріншот власника). Тому кільце на полях тепер під
  // `@media (pointer: fine)`, а цей проєкт — `coarse`. Протилежний бік того
  // самого контракту стереже `inputs.spec.ts` («тап по полю НЕ малює кільце»).
  // Перший фокусований вузол на db-list — саме поле пошуку, тож без цього
  // фільтра гард міряв би те, чого тут за задумом немає.
  let chrome: Awaited<ReturnType<typeof ringOfFocused>> = null
  for (let i = 0; i < 8 && !chrome; i++) {
    await page.keyboard.press('Tab')
    const cur = await ringOfFocused()
    if (cur && cur.tag !== 'input' && cur.tag !== 'textarea') chrome = cur
  }
  expect(chrome, 'Tab не знайшов жодного НЕ-поля контрола — гард став би порожнім').not.toBeNull()
  expect(chrome!.style, `${chrome!.tag}.${chrome!.cls}: кільце фокуса вимкнене`).not.toBe('none')
  // Саме ≥2px, а не «більше нуля»: без нашого правила Chromium сам малює
  // волосинку `outline:auto 1px`, і поріг «>0» проходив би на ній. Над темним
  // склом застосунку той UA-піксель практично не видно, тож він не рахується
  // за видимий фокус — і гард на ньому був би вакуумним (перевірено заміром:
  // 1px/auto без правила проти 2px/solid із ним).
  expect(chrome!.width, `${chrome!.tag}.${chrome!.cls}: кільце тонше за 2px — фокус практично невидимий`)
    .toBeGreaterThanOrEqual(2)

  // 2) Рядок шита — той самий контрол, який `modal-a11y` зробив досяжним.
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)

  let row: Awaited<ReturnType<typeof ringOfFocused>> = null
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab')
    const cur = await ringOfFocused()
    if (cur?.cls.includes('sheet-row')) { row = cur; break }
  }
  expect(row, 'Tab не дійшов до рядка шита — тест став би порожнім').not.toBeNull()
  expect(row!.width, 'рядок шита у фокусі лишився на UA-волосинці замість нашого кільця').toBeGreaterThanOrEqual(2)
  // Контроли, що клiпають самі себе (`overflow:hidden` під ellipsis), мусять
  // мати ВНУТРІШНЄ кільце — зовнішнє там просто обрізалось би, як колись `::after`.
  const clipped = await page.evaluate(() => {
    const out: { cls: string; offset: string; clips: boolean }[] = []
    for (const sel of ['.seg-b', '.fr-seg-b', '.notif-tab', '.view-seg-b']) {
      const el = document.querySelector(sel)
      if (!el) continue
      const cs = getComputedStyle(el)
      out.push({ cls: sel, offset: cs.outlineOffset, clips: cs.overflow !== 'visible' })
    }
    return out
  })
  for (const c of clipped.filter((x) => x.clips)) {
    expect(parseFloat(c.offset), `${c.cls} клiпає себе, тож кільце мусить бути всередині`)
      .toBeLessThanOrEqual(0)
  }
})

test('керування шарингом під час запиту — справді disabled, а не мертвий тап', async ({ page }) => {
  // `onClick={busy ? undefined : …}` знімало обробник, але лишало cursor:pointer
  // і :active — рядок підсвічувався під пальцем і не робив НІЧОГО. Тепер це
  // `disabled`, тож і вигляд, і читалка кажуть правду.
  await fixtures(page)
  let calls = 0
  await page.route('**/rest/v1/rpc/manage_share**', async (r) => {
    calls++
    await new Promise(res => setTimeout(res, 900))
    return json(r, [{ share_token: 'cc'.repeat(12), share_expires_at: null, error: null }])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()

  const preset = page.locator('.modal .fr-seg-b', { hasText: '7 днів' })
  const revoke = page.locator('.modal .sheet-row', { hasText: 'Відкликати доступ' })
  await expect(preset).toBeEnabled()

  await preset.click()
  // Поки летить запит — і пресети, і небезпечний рядок мусять бути неактивні.
  await expect(preset).toBeDisabled()
  await expect(revoke).toBeDisabled()
  // Тап по неактивному рядку не має породити другий запит.
  await revoke.click({ force: true })
  await expect(preset).toBeEnabled({ timeout: 15_000 })
  expect(calls, 'неактивний рядок усе одно вистрілив запитом').toBe(1)
})

test('Escape під час перейменування папки скасовує ЛИШЕ рядок, не весь шит', async ({ page }) => {
  // Modal слухає Escape на window і закриває верхній шит стеку. Локальний обробник
  // на інпуті перейменування без `stopPropagation` конкурував із ним: користувач
  // тиснув Escape, щоб відмовитись від правки назви, і втрачав усю модалку папок
  // разом із нею.
  await fixtures(page)
  const FOLDER = {
    id: '30000000-0000-0000-0000-000000000001',
    db_id: DB_ID, owner_id: USER.id, name: 'Перший поверх', sort_order: 100,
    created_at: NOW, updated_at: NOW,
  }
  await page.route('**/rest/v1/property_folders**', (r) => json(r, [FOLDER]))

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.locator('.modal').getByText('Папки', { exact: true })).toBeVisible()

  await page.getByLabel('Перейменувати').first().click()
  const input = page.locator('.fold-mng-row .fold-mng-input')
  await expect(input).toHaveValue('Перший поверх')
  await input.fill('Інша назва')

  await input.press('Escape')

  // Правка скасована…
  await expect(input, 'Escape не вийшов з режиму перейменування').toHaveCount(0)
  await expect(page.locator('.modal').getByText('Перший поверх')).toBeVisible()

  // …а шит на місці. Пауза ОБОВʼЯЗКОВА і не є довільною: закриття двофазне, шит
  // живе в DOM ще ~320мс із класом `closing` (плюс safety-net таймер такої ж
  // довжини). Без цієї паузи `toHaveCount(1)` збігався на першому ж полінгу
  // ПОСЕРЕД виходу — гард проходив і зі зламаним `stopPropagation`, тобто не
  // перевіряв нічого. Перевірено falsification-ом.
  await page.waitForTimeout(600)
  await expect(page.locator('.modal.closing'), 'шит почав закриватись від Escape у полі').toHaveCount(0)
  await expect(page.locator('.modal'), 'Escape у полі зніс усю модалку папок').toHaveCount(1)
  await expect(page.locator('.modal').getByText('Папки', { exact: true })).toBeVisible()

  // Другий Escape — уже поза полем — закриває шит, як і має.
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)
})

/** Швидкий флік — той самий жест, але кадри по ~16мс, тобто висока швидкість. */
const fling = (page: Page, selector: string, dy: number) => drag(page, selector, dy, true, 16)

test('швидкий флік закриває шит, не доходячи до порога відстані', async ({ page }) => {
  // Порогом була ЛИШЕ відстань (96px), тобто на короткому шиті рішучий рух пальцем
  // майже на всю його висоту не закривав нічого — жест читався як «не працює».
  await fixtures(page)
  await openRentSheet(page)

  await fling(page, '.modal-head', 50) // < 96px, але швидко
  await expect(page.locator('.modal'), 'швидкий флік не закрив шит').toHaveCount(0, { timeout: 6_000 })
})

test('повільний рух на ту саму відстань шит НЕ закриває', async ({ page }) => {
  // Парний до попереднього: швидкість не має перетворювати поріг у «закривається
  // від будь-якого дотику».
  await fixtures(page)
  await openRentSheet(page)

  await drag(page, '.modal-head', 50)
  await page.waitForTimeout(450)
  await expect(page.locator('.modal'), 'повільний рух на 50px закрив шит').toHaveCount(1)
})

test('тап по хедеру без руху не лишає мертвого transition, що ламає закриття', async ({ page }) => {
  // `transitionend` після snap-back не приходить, якщо transform і не змінювався
  // (тап без руху) — інлайновий `transition: transform .24s` лишався на шиті
  // назавжди і перебивав анімацію закриття.
  await fixtures(page)
  await openRentSheet(page)

  // Саме ТАП: touchstart + touchend без жодного touchmove. Через `drag(…, 0)` це
  // не відтворюється — там є move-події, і шлях виходить інший (перевірено:
  // зі зламаним фіксом той варіант гарда усе одно проходив).
  await page.locator('.modal-head').evaluate((head) => {
    const r = head.getBoundingClientRect()
    const t = new Touch({ identifier: 1, target: head as Element, clientX: r.x + r.width / 2, clientY: r.y + 8 })
    head.dispatchEvent(new TouchEvent('touchstart', { touches: [t], changedTouches: [t], bubbles: true, cancelable: true }))
    head.dispatchEvent(new TouchEvent('touchend', { touches: [], changedTouches: [t], bubbles: true, cancelable: true }))
  })
  await page.waitForTimeout(450)
  expect(await page.locator('.modal').evaluate((el) => (el as HTMLElement).style.transition),
    'на шиті лишився інлайновий transition після тапу без руху').toBe('')

  // …і закриття після цього мусить працювати штатно.
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)
})

test('вкладене підтвердження не затемнює екран удвічі', async ({ page }) => {
  // Обидва оверлеї мали rgba(0,0,0,.6) + blur(4px): разом ≈0.84 і подвійний блюр,
  // причому розмивався й сам шит під підтвердженням.
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await expect(page.locator('.modal')).toHaveCount(1)

  // «Відкликати доступ» просить підтвердження — фолбек-шит поверх ShareSheet.
  await page.locator('.modal .sheet-row', { hasText: 'Відкликати доступ' }).click()
  await expect(page.locator('.modal')).toHaveCount(2)
  // Чекаємо КІНЦЯ виїзду, і це не косметика: поки шит їде, блюр із нього
  // свідомо знятий (клас `moving` — див. `modal-sweep`, гард про кадри,
  // загублені на старті анімації). Замір одразу після появи читав би саме той
  // проміжний стан, а контракт нижче — про стан СПОКОЮ.
  await expect(page.locator('.modal-overlay.moving')).toHaveCount(0, { timeout: 8_000 })

  const overlays = await page.locator('.modal-overlay').evaluateAll((els) => els.map((e) => {
    const s = getComputedStyle(e)
    return { bg: s.backgroundColor, blur: s.backdropFilter }
  }))
  expect(overlays).toHaveLength(2)
  const alpha = (c: string) => Number(/rgba?\([^)]*?([\d.]+)\)$/.exec(c)?.[1] ?? 1)
  expect(overlays[0].bg, 'нижній оверлей втратив затемнення').not.toBe('rgba(0, 0, 0, 0)')
  // Спершу тут стояло «верхній оверлей НЕ затемнює зовсім» — і це виявилось
  // помилкою, знайденою аудитом вигляду: саме цей шар відділяє підтвердження від
  // шита під ним, і без нього «Відкликати доступ?» лягало на живі, нерозмиті
  // рядки ShareSheet. Правильний контракт — затемнює СЛАБШЕ за базовий, але
  // затемнює, і розмиття лишається.
  expect(alpha(overlays[1].bg), 'вкладений оверлей перестав відділяти підтвердження від шита')
    .toBeGreaterThan(0.1)
  expect(alpha(overlays[1].bg), 'вкладений оверлей затемнює як повноцінний — разом майже чорне')
    .toBeLessThan(alpha(overlays[0].bg))
  expect(overlays[1].blur, 'вкладений оверлей утратив розмиття нижнього шита').not.toBe('none')
})
