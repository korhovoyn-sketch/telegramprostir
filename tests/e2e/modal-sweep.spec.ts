import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * Спільний контракт УСІХ 16 інстансів `<Modal>` (12 файлів).
 *
 * `modals.spec.ts` покриває три з них глибоко — оренда, розклад платежів,
 * папки: свайп-закриття, клавіатура, валідація дат. Решта тринадцяти не
 * перевірялись жодним тестом навіть на те, що вони взагалі відкриваються.
 * А спільного в них рівно стільки, скільки й спільного коду: заголовок, тіло,
 * що прокручується, sticky-екшени, бекдроп-тап, Escape лише для верхньої.
 *
 * Тому тут не глибина, а ПОВНОТА: кожна модалка відкривається, проходить один
 * і той самий чекліст і закривається бекдроп-тапом. Регресія в `Modal.tsx`
 * впаде на всіх шістнадцяти одразу, а не проявиться на одній, до якої ніхто
 * не дійшов.
 */

const NOW = '2025-09-01T09:00:00.000Z'
const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Ірина' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB2_ID = '10000000-0000-0000-0000-000000000002'
const FOLDER_ID = '50000000-0000-0000-0000-000000000001'
const COL_ID = '70000000-0000-0000-0000-000000000001'

const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const db = (id: string, name: string) => ({
  id, owner_id: OWNER.id, name, address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: `aabbccddeeff0011223344${id.slice(-2)}`,
  share_expires_at: null, created_at: NOW, updated_at: NOW,
})
const DBS = [db(DB_ID, 'БЦ Рубін'), db(DB2_ID, 'БЦ Сапфір')]

function prop(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, area_basis: 'total', rent_type: 'per_m2', rent_rate: 20, utilities_rate: 2,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: 'Світлий офіс.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01', folder_id: FOLDER_ID }),
  prop(2, { status: 'free' }),
]
/** Розклад платежів на «Офіс 101» — без нього календар не має ні карток, ні модалок. */
const SCHEDULE = [{
  id: '80000000-0000-0000-0000-000000000001', property_id: PROPERTIES[0].id,
  owner_id: OWNER.id, due_day: 5, notify_days_before: 3, is_active: true,
  created_at: NOW, updated_at: NOW,
}]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const url = r.request().url()
    if ((r.request().headers()['accept'] ?? '').includes('object')) {
      const m = url.match(/id=eq\.([0-9a-f-]+)/)
      return json(r, DBS.find((d) => d.id === m?.[1]) ?? DBS[0])
    }
    return json(r, DBS)
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find((p) => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/property_folders**', (r) => json(r, [
    { id: FOLDER_ID, db_id: DB_ID, owner_id: OWNER.id, name: 'Орендарі', sort_order: 1, created_at: NOW, updated_at: NOW },
  ]))
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, SCHEDULE))
  // INSERT іде через `.single()`, тож відповідь мусить бути ОБ'ЄКТОМ: на масиві
  // токен вийшов би undefined і шит «посилання створено» показав би сміття.
  await page.route('**/rest/v1/guest_links**', (r) => {
    if (r.request().method() === 'POST') return json(r, { invite_token: 'ee00112233445566778899bb' })
    return json(r, [{
      id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
      db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
      guest_user_id: null, status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/db_members**', (r) => {
    if (r.request().method() === 'POST') return json(r, { invite_token: 'ff00112233445566778899cc' })
    if (r.request().url().includes('user_id=eq.')) return json(r, [])
    return json(r, [{
      id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID, user_id: '00000000-0000-0000-0000-000000000077',
      role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер',
      member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/rpc/manage_share', (r) =>
    json(r, [{ share_token: DBS[0].share_token, share_expires_at: null, error: null }]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? OWNER : [OWNER]))
  for (const t of ['rent_payment_records', 'property_views', 'property_files', 'property_photos', 'notifications', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * Спільний чекліст. Повертає заголовок — щоб виклик читався як опис того, що
 * саме відкрилось, і випадкове відкриття ІНШОЇ модалки було видно в звіті.
 */
async function checkModal(page: Page, where: string, expectTitle?: string): Promise<string> {
  // Попередній шит під час виходу ЩЕ в DOM (клас `closing`, ~320мс). Поки він там,
  // `.last()` перерішується між викликами: очікування анімації діставалось йому
  // (уже спокійний → повертало миттєво), а замір — новому, який саме виїжджав.
  // Звідси й брались «вилазить на 134px», щоразу з іншим числом.
  await expect(page.locator('.modal.closing'), `${where}: попередній шит не закрився`)
    .toHaveCount(0, { timeout: 6_000 })
  // Коли один шит ЗАМІНЮЄТЬСЯ іншим (інвайт → готове посилання), між кліком і
  // підміною є вікно, де старий шит ще не почав виходити: `.modal.closing` порожній,
  // а `.last()` — це все ще ПОПЕРЕДНІЙ шит. Гард тоді міряв кнопку «Створення...»
  // висотою 0. Тому чекаємо на конкретний заголовок, а не просто на «якийсь шит».
  if (expectTitle) {
    await expect(page.locator('.modal .modal-h').last(), `${where}: очікувався шит «${expectTitle}»`)
      .toHaveText(expectTitle, { timeout: 10_000 })
  }
  const modal = page.locator('.modal').last()
  await expect(modal, `${where}: модалка не відкрилась`).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Щось пішло не так'), `${where}: ErrorBoundary`).toHaveCount(0)
  // Один і той самий вузол для очікування і заміру — локатор більше не перерішується.
  const el = await modal.elementHandle()
  if (!el) throw new Error(`${where}: шит зник між очікуванням і заміром`)
  // `modalSlideUp` виїжджає з-під низу екрана (.38s), тож без очікування геометрія
  // читається на півдорозі: перший прогін показав кнопку «на 219px за низом шита»
  // — і це був не дефект верстки, а замір під час анімації. `animations:'disabled'`
  // з конфіга глушить рух лише для скріншотів, не для evaluate.
  //
  // Чекаємо саме СТАБІЛЬНОСТІ рамки, а не `getAnimations().finished`: коли один
  // шит змінюється іншим (інвайт → готове посилання), новий елемент уже в DOM,
  // але його анімація стартує лише наступним кадром — на цей момент список
  // анімацій порожній, і очікування пропускалось. Fill-mode `both` тримає
  // початкову позицію з моменту вставки, тож три однакові кадри = шит на місці.
  await el.evaluate(async (el) => {
    const deadline = performance.now() + 2500
    let last = Number.NaN
    let stable = 0
    while (performance.now() < deadline) {
      // Спершу дочекатись анімацій, які ВЖЕ біжать, потім кадр, потім замір.
      // Самих лише «трьох однакових кадрів» не досить: коли один шит змінюється
      // іншим, новий елемент уже в DOM, а його анімація стартує наступним кадром
      // — три кадри на стартовій позиції fill-mode `both` виглядали як спокій.
      await Promise.all(el.getAnimations().map((a) => a.finished.catch(() => undefined)))
      await new Promise((r) => requestAnimationFrame(() => r(null)))
      const y = Math.round(el.getBoundingClientRect().top)
      if (y === last) { if (++stable >= 3) return } else { stable = 0; last = y }
    }
  })

  const res = await el.evaluate((el) => {
    const q = <T extends Element>(s: string) => el.querySelector(s) as T | null
    const head = q<HTMLElement>('.modal-h')
    const body = q<HTMLElement>('.modal-body')
    const overlay = el.closest('.modal-overlay') as HTMLElement
    const frame = overlay.getBoundingClientRect()
    const named = (b: HTMLElement) =>
      !!(b.getAttribute('aria-label') || (b.textContent ?? '').trim() ||
         b.getAttribute('aria-labelledby') || (b as HTMLInputElement).labels?.length)
    return {
      title: (head?.textContent ?? '').trim(),
      role: el.getAttribute('role'),
      modal: el.getAttribute('aria-modal'),
      labelledby: el.getAttribute('aria-labelledby'),
      headId: head?.id ?? null,
      // Горизонтальне переповнення: шит на всю ширину, тож зайвий піксель означає
      // контент, який вилазить за екран (довга назва, нерозривний токен).
      overflowX: [el, body].filter(Boolean)
        .map((n) => (n as HTMLElement).scrollWidth - (n as HTMLElement).clientWidth)
        .filter((d) => d > 1),
      actions: [...el.querySelectorAll<HTMLButtonElement>('.modal-actions .modal-btn')].map((b) => {
        const r = b.getBoundingClientRect()
        return {
          label: (b.textContent ?? '').trim(),
          h: Math.round(r.height),
          // Sticky-екшени мусять лежати в межах шита, а не під згином.
          below: Math.round(r.bottom - frame.bottom),
          disabled: b.disabled,
          opacity: Number(getComputedStyle(b).opacity),
        }
      }),
      fields: [...el.querySelectorAll<HTMLElement>('input,textarea,select')]
        .filter((f) => (f as HTMLInputElement).type !== 'hidden')
        .filter((f) => !named(f))
        .map((f) => `${f.tagName.toLowerCase()}[${(f as HTMLInputElement).type ?? ''}] .${f.className.slice(0, 20)}`),
      // Обрізаний підпис. Для `ellipsis+nowrap+hidden` єдиний надійний критерій —
      // scrollWidth > clientWidth на самому носії тексту; leaf-фільтри його гублять,
      // бо підпис поля — це іконка + текстовий вузол. Так знайшлось
      // «Експлуатаційні, $/м²», де ellipsis зʼїдав саму ОДИНИЦЮ, тобто користувач
      // не бачив, що вводить: ставку за м² чи фіксовану суму.
      truncated: [...el.querySelectorAll<HTMLElement>('*')]
        .filter((n) => {
          const st = getComputedStyle(n)
          return st.overflowX !== 'visible' && st.textOverflow === 'ellipsis' && n.scrollWidth - n.clientWidth > 0
        })
        .map((n) => `«${(n.textContent ?? '').trim().slice(0, 34)}» обрізано на ${n.scrollWidth - n.clientWidth}px`),
      // Кнопки дій НЕ мають ellipsis, тож перевірка вище їх не бачить: довгий
      // підпис у них не обрізається, а вилазить за край кнопки. При 375px половинна
      // кнопка — ~167px, і на цьому спалились шість підписів (гірший, «Поділитись
      // в Telegram», на 31px).
      tight: [...el.querySelectorAll<HTMLButtonElement>('.modal-actions .modal-btn')]
        .map((b) => {
          const cs = getComputedStyle(b)
          const inner = b.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)
          const rng = document.createRange()
          rng.selectNodeContents(b)
          return { label: (b.textContent ?? '').trim(), by: Math.round(rng.getBoundingClientRect().width - inner) }
        })
        .filter((r) => r.by > 0)
        .map((r) => `«${r.label}» шириться за кнопку на ${r.by}px`),
    }
  })

  expect(res.title, `${where}: порожній заголовок шита`).not.toBe('')
  expect(res.role, `${where}: не role=dialog`).toBe('dialog')
  expect(res.modal, `${where}: не aria-modal`).toBe('true')
  expect(res.labelledby, `${where}: aria-labelledby не вказує на заголовок`).toBe(res.headId)
  expect(res.overflowX, `${where} «${res.title}»: горизонтальне переповнення`).toEqual([])
  expect(res.fields, `${where} «${res.title}»: поля без доступної назви`).toEqual([])
  expect(res.truncated, `${where} «${res.title}»: обрізаний текст`).toEqual([])
  expect(res.tight, `${where} «${res.title}»: підпис кнопки не вміщується`).toEqual([])
  for (const a of res.actions) {
    expect(a.h, `${where} «${res.title}» → «${a.label}»: висота ${a.h}px < 44 (Apple HIG)`)
      .toBeGreaterThanOrEqual(44)
    expect(a.below, `${where} «${res.title}» → «${a.label}» вилазить на ${a.below}px за низ шита`)
      .toBeLessThanOrEqual(0)
    if (a.disabled) {
      // Правило проєкту: неактивна дія — нейтральне скло, а не привид. Над темним
      // шитом opacity:.45 з'їдала кнопку до невидимості.
      expect(a.opacity, `${where} «${res.title}» → «${a.label}»: неактивна через прозорість`)
        .toBeGreaterThanOrEqual(0.9)
    }
  }
  return res.title
}

/** Закриття бекдроп-тапом — єдиний шлях виходу, спільний для всіх шитів. */
async function closeByBackdrop(page: Page, where: string) {
  const before = await page.locator('.modal').count()
  await page.locator('.modal-overlay').last().click({ position: { x: 10, y: 10 } })
  await expect(page.locator('.modal'), `${where}: бекдроп-тап не закрив шит`)
    .toHaveCount(before - 1, { timeout: 6_000 })
}

async function sweep(page: Page, where: string, expectTitle?: string) {
  const title = await checkModal(page, where, expectTitle)
  await closeByBackdrop(page, where)
  return title
}

async function toObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
}

async function menu(page: Page, item: string) {
  await page.getByLabel('Меню бази').click()
  await page.getByText(item, { exact: true }).click()
}

test('шити бази: меню, папки, вибір папки, перенос у базу, поширення', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // 1. Меню бази (DatabaseObjectsScreen) — заголовок = назва бази.
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  expect(await sweep(page, 'db-menu')).toBe('БЦ Рубін')

  // 2. FolderManageModal
  await menu(page, 'Папки')
  expect(await sweep(page, 'folders')).toBe('Папки')

  // 3+4. Режим вибору → «У папку» і «Перенести» (FolderPicker + DbPicker).
  await menu(page, 'Виділити об\'єкти')
  await page.locator('.obj-card').first().click()
  await expect(page.locator('.batchbar')).toBeVisible()
  await page.locator('.batch-pill', { hasText: 'У папку' }).click()
  await sweep(page, 'folder-picker')
  await page.locator('.batch-pill').filter({ hasText: /базу|Перенести/ }).first().click()
  expect(await sweep(page, 'db-picker')).toBe('Перенести в базу')

  // 5. ShareSheet з екрана аналітики.
  await toObjects(page)
  await menu(page, 'Аналітика і поширення')
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await sweep(page, 'share-sheet')
})

test('шити об\'єкта і платежів: оренда, розклад, підтвердження платежу', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // 6. «Здати в оренду» (PropertyDetailScreen) — на вільному об'єкті.
  await toObjects(page)
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Здати в оренду/ })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Здати в оренду/ }).click()
  expect(await sweep(page, 'rent')).toBe('Здати в оренду')

  // 7. Налаштування розкладу — на об'єкті БЕЗ розкладу.
  await toObjects(page)
  await menu(page, 'Календар платежів')
  await expect(page.getByText(/Календар платежів|Платежі/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  expect(await sweep(page, 'schedule')).toBe('Налаштувати розклад')

  // 8. Підтвердження отримання — на об'єкті З розкладом.
  await page.getByRole('button', { name: /Отримано/ }).first().click()
  expect(await sweep(page, 'pay-confirm')).toBe('Підтвердити отримання')

  // …і сума на грошовому шляху мусить валідуватись ДО підтвердження. Раніше вона
  // парсилась усередині дії, тож нуль чи самотня крапка тихо йшли як `undefined`
  // і платіж підтверджувався без жодного сигналу. Шит доводиться відкривати
  // заново — `sweep` закриває його бекдроп-тапом.
  await page.getByRole('button', { name: /Отримано/ }).first().click()
  await expect(page.locator('.modal')).toBeVisible()
  const payBtn = page.locator('.modal-actions .modal-btn', { hasText: 'Підтвердити' })
  const amount = page.getByLabel('Сума отриманого платежу')
  await expect(payBtn, 'порожнє поле легальне — береться очікувана сума').toBeEnabled()
  await amount.fill('0')
  await expect(payBtn, 'нульова сума приймається як платіж').toBeDisabled()
  await amount.fill('.')
  await expect(payBtn, 'самотня крапка приймається як сума').toBeDisabled()
  await amount.fill('1500')
  await expect(payBtn, 'коректна сума не проходить').toBeEnabled()
})

test('шити доступів: гості, команда, і створене посилання', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  await toObjects(page)
  await menu(page, 'Управління гостями')
  await expect(page.getByText(/Гості|Запросити/).first()).toBeVisible({ timeout: 15_000 })

  // 9. «Запросити гостя»
  await page.getByRole('button', { name: /Запросити/ }).first().click()
  expect(await checkModal(page, 'guest-invite')).toBe('Запросити гостя')

  // 10. Шит із готовим посиланням — окремий інстанс `<Modal>`, який видно лише
  // після успішного INSERT, тож дійти до нього можна тільки створивши інвайт.
  await page.getByLabel('Підпис гостьового лінка').fill('Орендар, кв. 5')
  await page.locator('.modal-btn', { hasText: 'Створити' }).click()
  expect(await sweep(page, 'guest-created', 'Посилання створено!')).toBe('Посилання створено!')

  // 11+12. Команда: те саме — інвайт і шит зі створеним посиланням.
  await toObjects(page)
  await menu(page, 'Команда')
  await expect(page.getByText(/Команда|Запросити/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Запросити/ }).first().click()
  expect(await checkModal(page, 'team-invite')).toBe('Запросити в команду')
  await page.locator('.modal input').first().fill('Менеджер Оля')
  await page.locator('.modal-btn', { hasText: /Створити/ }).click()
  expect(await sweep(page, 'team-created', 'Запрошення створено!')).toBe('Запрошення створено!')
})

test('шити профілю: вихід і видалення акаунта', async ({ page }) => {
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })

  // 12. Вихід
  await page.getByText('Вийти з акаунту', { exact: true }).click()
  expect(await sweep(page, 'logout')).toBe('Вийти з акаунту?')

  // 13. Видалення акаунта — свідомо на власній модалці, бо потребує ВВЕДЕННЯ
  // слова підтвердження, чого нативний попап Telegram не вміє.
  await page.getByText('Видалити акаунт', { exact: true }).click()
  const title = await checkModal(page, 'delete-account')
  expect(title).toBe('Видалити акаунт?')
  const confirm = page.locator('.modal-btn').filter({ hasText: /Видалити/ }).last()
  await expect(confirm, 'кнопка активна ще до введення слова підтвердження').toBeDisabled()
  await closeByBackdrop(page, 'delete-account')
})

test('шити рієлтора: підбірка і додавання об\'єкта', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: REALTOR })
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [
    { id: '60000000-0000-0000-0000-000000000001', realtor_id: REALTOR.id, db_id: DB_ID, created_at: NOW, database: DBS[0] },
  ]))
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DBS[0] : [DBS[0]]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPERTIES[0] : PROPERTIES))
  await page.route('**/rest/v1/collections**', (r) => json(r, [{
    id: COL_ID, realtor_id: REALTOR.id, name: 'Для клієнта А', is_draft: false,
    share_token: 'ff00112233445566778899aa', share_expires_at: null,
    created_at: NOW, updated_at: NOW, properties: [],
  }]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? REALTOR : [REALTOR]))
  for (const t of ['collection_properties', 'property_photos', 'property_views', 'notifications', 'property_files', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await expect(page.getByText('Для клієнта А').first()).toBeVisible({ timeout: 15_000 })

  // 14. ShareSheet зі списку підбірок.
  await page.locator('.collection-c').filter({ hasText: 'Для клієнта А' }).first().click()
  await expect(page.getByLabel('Додати об\'єкт')).toBeVisible({ timeout: 15_000 })

  // 15. «Додати об'єкт» у деталях підбірки.
  await page.getByLabel('Додати об\'єкт').click()
  expect(await sweep(page, 'collection-add')).toBe('Додати об\'єкт')
})

test('Escape закриває ЛИШЕ верхню модалку стеку', async ({ page }) => {
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // Вкладений випадок: підтвердження всередині шита поширення. Ротація токена —
  // незворотна дія, тож без нативних попапів вона малює ConfirmHost ПОВЕРХ шита.
  await toObjects(page)
  await menu(page, 'Аналітика і поширення')
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await checkModal(page, 'share-sheet/base')

  await page.locator('.modal').last().getByText(/Оновити посилання|Ротація|Новий токен/).first().click()
  await expect(page.locator('.modal'), 'підтвердження не стало другим шитом').toHaveCount(2, { timeout: 8_000 })
  await checkModal(page, 'nested-confirm')

  await page.keyboard.press('Escape')
  await expect(page.locator('.modal'), 'Escape зніс і батьківський шит').toHaveCount(1, { timeout: 8_000 })
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0, { timeout: 8_000 })
})

test('шит НЕ блюрить фон, поки їде — і повертає блюр, коли став', async ({ page }) => {
  // Причина цього гарда заміряна на РЕАЛЬНОМУ пристрої, а не виведена з теорії.
  // Покадровий розбір запису з iPhone (43.6 к/с) показав, що перші ~60% шляху
  // шит долав за ОДИН кадр — 1 994 102 змінених пікселі з 2 962 440 екрана, —
  // а наступний кадр був майже без руху (61 594). Тобто кадри на старті
  // губились: відкриття створює ДВА нові backdrop-шари (`.modal` blur 48px і
  // `.modal-overlay` blur 4px) поверх екрана, де вже 24+ карток `.glass-s` зі
  // своїм blur(28px).
  //
  // Прийом не новий — акордеон папок робить рівно це (`.fold-anim`), і в
  // `Collapsible.tsx` прямо написано, що переблюрювання карток щокадру «is what
  // made it stutter».
  //
  // ЧОГО ЦЕЙ ГАРД НЕ ДОВОДИТЬ: що на iOS стало плавно. Chromium тут блюр
  // майже не коштує (`_blur-cost`: p50 16.7мс і з ним, і без), тож локальний
  // прогін не побачить ані дефекту, ані фікса. Він стереже саме МЕХАНІЗМ —
  // клас `moving` є під час руху і зникає після нього.
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)
  await toObjects(page)

  await page.getByLabel('Меню бази').click()

  // Поки анімація йде — блюру нема на ОБОХ шарах.
  const during = await page.locator('.modal').first().evaluate((el) => {
    const overlay = el.closest('.modal-overlay') as HTMLElement
    return {
      modalMoving: el.classList.contains('moving'),
      modal: getComputedStyle(el).backdropFilter,
      overlay: getComputedStyle(overlay).backdropFilter,
    }
  })
  expect(during.modalMoving, 'клас руху не виставився на старті — блюр глушити нічим').toBe(true)
  expect(during.modal, 'шит блюрить фон під час руху').toBe('none')
  expect(during.overlay, 'затемнення блюрить фон під час руху').toBe('none')

  // …а коли став — повертається, інакше зникло б саме скло.
  await expect(page.locator('.modal.moving')).toHaveCount(0, { timeout: 8_000 })
  const after = await page.locator('.modal').first()
    .evaluate((el) => getComputedStyle(el).backdropFilter)
  expect(after, 'блюр не повернувся — шит перестав бути склом').toContain('blur')
})
