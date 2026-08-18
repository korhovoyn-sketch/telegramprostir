import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * Оповіщення НАСКРІЗЬ: бейдж непрочитаних у таббарі, автопозначення при вході,
 * «Прочитано», видалення, фільтри вкладок, порожній стан.
 *
 * Раніше екран лише ВІДКРИВАЛИ (скріншот-тур і обхід нативного клієнта), а
 * жодна функція `useNotifications` — markRead / markAllAsRead / deleteNotification
 * і сам лічильник — не перевірялась.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date()
const iso = (daysAgo: number) => new Date(NOW.getTime() - daysAgo * 86400000).toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: iso(30), updated_at: iso(1),
}

function notif(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `90000000-0000-0000-0000-00000000000${n}`, user_id: USER.id,
    type: 'view', title: `Перегляд об'єкта ${n}`, body: 'Гість відкрив картку',
    is_read: false, data: {}, created_at: iso(n), ...over,
  }
}

interface Wire { patches: string[]; deletes: string[] }

/** Розклад платежів для `useUpcomingPayments` (обʼєкт приходить вкладеним). */
function schedule(dueDay: number, over: Record<string, unknown> = {}) {
  return {
    property_id: '20000000-0000-0000-0000-000000000001',
    due_day: dueDay,
    property: {
      id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, name: 'Офіс 101',
      tenant_name: 'Фоп Плотко', status: 'occupied',
      rent_type: 'per_m2', rent_rate: 18, area_useful: 100,
    },
    ...over,
  }
}

/**
 * Час ЗАМОРОЖУЄТЬСЯ для платіжних гардів, і без цього вони недетерміновані:
 * хук бере день місяця з розкладу, тож «через 3 дні» на 29-те число означало б
 * уже НАСТУПНИЙ місяць, а перша неоплачена дата лишалась би в цьому — тобто
 * той самий тест читав би «прострочено на 28 днів» раз на місяць.
 */
const FROZEN = new Date('2025-09-10T10:00:00.000Z')

async function setup(page: Page, notifications: unknown[], opts: { schedules?: unknown[]; records?: unknown[] } = {}): Promise<Wire> {
  const wire: Wire = { patches: [], deletes: [] }
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => json(r, []))
  await page.route('**/rest/v1/notifications**', (r) => {
    const m = r.request().method()
    if (m === 'PATCH') { wire.patches.push(r.request().url()); return json(r, []) }
    if (m === 'DELETE') { wire.deletes.push(r.request().url()); return json(r, []) }
    return json(r, notifications)
  })
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, opts.schedules ?? []))
  await page.route('**/rest/v1/rent_payment_records**', (r) => json(r, opts.records ?? []))
  for (const t of ['property_folders', 'property_files', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  return wire
}

async function openApp(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
}

const badge = (page: Page) => page.locator('.tabbar .tab-badge')

test('бейдж непрочитаних показує кількість і зникає після прочитання', async ({ page }) => {
  const wire = await setup(page, [notif(1), notif(2), notif(3, { is_read: true })])
  await openApp(page)

  // Дві непрочитані з трьох.
  await expect(badge(page)).toHaveText('2', { timeout: 15_000 })

  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Сповіщення').first()).toBeVisible()

  // Вхід на екран сам позначає все прочитаним — PATCH пішов, бейдж зник.
  await expect.poll(() => wire.patches.length, { timeout: 10_000 }).toBeGreaterThan(0)
  await expect(badge(page)).toHaveCount(0)
})

test('«Прочитано» в хедері доступне лише поки є непрочитані', async ({ page }) => {
  await setup(page, [notif(1), notif(2)])
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()

  // Автопозначення на вході вже спрацювало, тож кнопки не має бути:
  // показувати дію, яка нічого не змінить, — обман.
  await expect(page.getByRole('button', { name: 'Прочитано' })).toHaveCount(0)
  await expect(page.getByText('нових')).toHaveCount(0)
})

test('видалення сповіщення прибирає рядок і не відкриває картку', async ({ page }) => {
  const wire = await setup(page, [notif(1), notif(2)])
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toBeVisible({ timeout: 15_000 })

  await page.locator('.notif-del').first().click()

  await expect.poll(() => wire.deletes.length, { timeout: 10_000 }).toBe(1)
  await expect(page.getByText('Перегляд об\'єкта 1')).toHaveCount(0)
  // stopPropagation: тап по хрестику не мусить навігувати на об'єкт.
  await expect(page.getByText('Сповіщення').first()).toBeVisible()
})

// Вкладки описують ЛИШЕ те, що застосунок реально створює. Єдиний виробник
// рядків — edge-функція `send-reminders`, і лише з `type='rent_reminder'`.
// Вкладки «Перегляди»/«Повідомлення»/«Система» прибрані: у проді вони були
// назавжди порожні, а старий тест цього не бачив, бо сам підсовував `type:'view'`.
test('вкладка «Платежі» лишає лише нагадування про оплату', async ({ page }) => {
  await setup(page, [
    notif(1, { type: 'rent_reminder', title: 'Платіж за Офіс 101' }),
    notif(2, { type: 'view', title: 'Перегляд об\'єкта 2' }),
  ])
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Платіж за Офіс 101')).toBeVisible({ timeout: 15_000 })

  await page.locator('.notif-tab', { hasText: 'Платежі' }).click()
  await expect(page.getByText('Платіж за Офіс 101')).toBeVisible()
  await expect(page.getByText('Перегляд об\'єкта 2'), 'чужий тип у «Платежах» не місце').toHaveCount(0)
})

test('вкладка «Договори» НЕ показує звичайні сповіщення', async ({ page }) => {
  // Гард на реальний баг: гілки для `lease` у фільтрі не було взагалі, тож він
  // падав у фінальний `return true` — і вкладка показувала ВСІ сповіщення
  // поспіль, тобто не фільтрувала нічого.
  await setup(page, [
    notif(1, { type: 'rent_reminder', title: 'Платіж за Офіс 101' }),
    notif(2, { type: 'view', title: 'Перегляд об\'єкта 2' }),
  ])
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Платіж за Офіс 101')).toBeVisible({ timeout: 15_000 })

  await page.locator('.notif-tab', { hasText: 'Договори' }).click()
  await expect(page.getByText('Платіж за Офіс 101')).toHaveCount(0)
  await expect(page.getByText('Перегляд об\'єкта 2')).toHaveCount(0)
})

test('порожній стан замість пустого екрана', async ({ page }) => {
  await setup(page, [])
  await openApp(page)
  await expect(badge(page), 'без непрочитаних бейджа нема').toHaveCount(0)

  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText(/З'являться|з'являться/)).toBeVisible()
})

test('падіння запиту сповіщень не валить екран', async ({ page }) => {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/notifications**', (r) =>
    r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'boom' }) }))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Сповіщення').first()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Щось пішло не так'), 'екран мусить вижити').toHaveCount(0)
})

test('повільний GET не оживляє бейдж після позначення прочитаним', async ({ page }) => {
  // Детермінований відтворювач гонки: GET сповіщень відповідає ПОВІЛЬНО, тож
  // якщо екран не дочікується завантаження перед markAllAsRead, серверні рядки
  // (де is_read ще false) перетруть локально прочитаний стан — бейдж повернеться,
  // а рядки намалюються непрочитаними. Саме це й ловив флейк у паралельному
  // прогоні, коли лічильник перевели на requestIdleCallback.
  const wire: Wire = { patches: [], deletes: [] }
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) => json(r, [DB]))
  await page.route('**/rest/v1/properties**', (r) => json(r, []))
  await page.route('**/rest/v1/notifications**', async (r) => {
    const m = r.request().method()
    if (m === 'PATCH') { wire.patches.push(r.request().url()); return json(r, []) }
    if (m === 'DELETE') { wire.deletes.push(r.request().url()); return json(r, []) }
    await new Promise((res) => setTimeout(res, 500))
    return json(r, [notif(1), notif(2)])
  })
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toBeVisible({ timeout: 15_000 })
  await expect.poll(() => wire.patches.length, { timeout: 10_000 }).toBeGreaterThan(0)

  // Даємо будь-якій запізнілій відповіді час перетерти стан.
  await page.waitForTimeout(900)
  await expect(badge(page), 'бейдж не мусить оживати').toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Прочитано' }), 'кнопки «Прочитано» теж бути не має').toHaveCount(0)
})

// ── Найближчі платежі: закріплений блок, похідний від РОЗКЛАДУ ───────────────
//
// Скарга власника: «в оповіщенні не відображаються нагадування про платежі».
// Причина була архітектурна, а не в фільтрі: рядки `rent_reminder` пише лише
// edge-функція `send-reminders`, і лише в день нагадування — тобто решту
// місяця вкладка «Платежі» була порожня В ПРИНЦИПІ. Тепер найближчий платіж
// рахується з розкладу на клієнті, як і кінець договору.

async function openNotifications(page: Page) {
  await page.clock.setFixedTime(FROZEN)
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Сповіщення').first()).toBeVisible({ timeout: 15_000 })
}

test('найближчий платіж видно у «Всі» і у «Платежах» — без жодного рядка в notifications', async ({ page }) => {
  await setup(page, [], { schedules: [schedule(13)] })
  await openNotifications(page)

  await expect(page.getByText('Найближчі платежі')).toBeVisible({ timeout: 15_000 })
  const row = page.locator('.notif-i', { hasText: 'Офіс 101' })
  await expect(row).toBeVisible()
  await expect(row).toContainText('Через 3 дні')
  // Орендар — частина рядка: без нього незрозуміло, з кого питати оплату.
  await expect(row).toContainText('Фоп Плотко')

  await page.locator('.notif-tab', { hasText: 'Платежі' }).click()
  await expect(page.locator('.notif-i', { hasText: 'Офіс 101' })).toBeVisible()
})

test('сума — МІСЯЧНА, а не сира ставка за метр', async ({ page }) => {
  // Той самий клас помилки, що вже ловили в календарі: `rent_rate` для per_m2 —
  // це $/м², і показати його як суму до сплати означає показати $18 замість
  // $1 800. Нормалізує `monthlyRent` (100 м² × 18).
  await setup(page, [], { schedules: [schedule(13)] })
  await openNotifications(page)
  const row = page.locator('.notif-i', { hasText: 'Офіс 101' })
  await expect(row).toContainText('1 800')
  await expect(row, 'сира ставка за метр замість місячної суми').not.toContainText(/\$18(?!\d)/)
})

test('прострочений платіж лишається на екрані і позначений рівнем «overdue»', async ({ page }) => {
  await setup(page, [], { schedules: [schedule(5)] })
  await openNotifications(page)
  const row = page.locator('.notif-i', { hasText: 'Офіс 101' })
  await expect(row).toContainText('Прострочено на 5 днів')
  await expect(row).toHaveClass(/lvl-overdue/)
})

test('підтверджений платіж ЗНИКАЄ з блоку — це стан, а не подія', async ({ page }) => {
  // Головна перевага похідного блоку над рядком у `notifications`: він не
  // потребує прибирання. Оплачено 13.09 → найближчий стає 13.10, а це вже поза
  // вікном PAYMENT_ALERT_DAYS.
  await setup(page, [], {
    schedules: [schedule(13)],
    records: [{ property_id: '20000000-0000-0000-0000-000000000001', due_date: '2025-09-13', status: 'paid' }],
  })
  await openNotifications(page)
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Найближчі платежі')).toHaveCount(0)
})

test('рядок платежу — СПРАВЖНЯ кнопка, досяжна з клавіатури', async ({ page }) => {
  // Клікабельний <div> не оголошується читалкою і недосяжний Tab-ом — те саме
  // правило, через яке рядки шитів свого часу перевели на <button>.
  await setup(page, [], { schedules: [schedule(13)] })
  await openNotifications(page)
  const row = page.locator('.notif-i', { hasText: 'Офіс 101' })
  await expect(row).toBeVisible({ timeout: 15_000 })
  expect(await row.evaluate((el) => el.tagName.toLowerCase()),
    'рядок лишився <div> — з клавіатури до нього не дійти').toBe('button')
})

test('порожній розклад не малює блок і не ламає порожній стан', async ({ page }) => {
  await setup(page, [], { schedules: [] })
  await openNotifications(page)
  await expect(page.getByText('Найближчі платежі')).toHaveCount(0)
  await expect(page.getByText('Немає сповіщень')).toBeVisible()
})

test('ГЛОБАЛЬНИЙ лічильник, випущений РАНІШЕ, не воскрешає бейдж', async ({ page }) => {
  // Детермінований відтворювач гонки, яку знайшов CI. Запитів на `notifications`
  // ДВА і від різних власників:
  //   1) глобальний лічильник бейджа в page.tsx — на requestIdleCallback;
  //   2) сам екран сповіщень — `load().then(markAllAsRead)`.
  // Обидва пишуть у стор УВЕСЬ список, тож виграє той, хто відповів ОСТАННІМ, а
  // не той, чиї дані свіжіші.
  //
  // ПОРЯДОК ТУТ ТРЕБА ГАРАНТУВАТИ, і перша версія цього гарда була вакуумною
  // саме тому, що не гарантувала: вона робила найповільнішим ПЕРШИЙ запит,
  // припускаючи, що перший — глобальний. Якщо idle-колбек не встигав спрацювати
  // до кліку, першим виявлявся запит екрана, він же відповідав останнім — і
  // тест проходив навіть на зламаному коді.
  //
  // Тепер: чекаємо 2.5с (timeout у requestIdleCallback — 2000мс, тобто глобальний
  // запит ГАРАНТОВАНО вже випущений), а сам його тримаємо 6с. Клік по вкладці
  // випускає другий запит, той відповідає за 100мс → markAllAsRead. Стара
  // відповідь приземляється ще через кілька секунд і намагається повернути
  // `is_read:false`.
  const wire: Wire = { patches: [], deletes: [] }
  let gets = 0
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  const json = (r: Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) => json(r, [DB]))
  await page.route('**/rest/v1/properties**', (r) => json(r, []))
  await page.route('**/rest/v1/notifications**', async (r) => {
    const m = r.request().method()
    if (m === 'PATCH') { wire.patches.push(r.request().url()); return json(r, []) }
    if (m === 'DELETE') { wire.deletes.push(r.request().url()); return json(r, []) }
    const n = ++gets
    await new Promise((res) => setTimeout(res, n === 1 ? 6000 : 100))
    return json(r, [notif(1), notif(2)])
  })
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await openApp(page)
  // Глобальний запит уже випущений і висить — інакше порядок не гарантований.
  await page.waitForTimeout(2500)
  expect(gets, 'глобальний лічильник не встиг випустити запит — гард був би вакуумним').toBeGreaterThan(0)

  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toBeVisible({ timeout: 15_000 })
  await expect.poll(() => wire.patches.length, { timeout: 10_000 }).toBeGreaterThan(0)

  // Дочікуємось приземлення ПЕРШОГО, найповільнішого запиту.
  await page.waitForTimeout(4500)
  await expect(badge(page), 'відповідь на запит, випущений РАНІШЕ, повернула бейдж').toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Прочитано' }),
    'разом із бейджем повернулась і кнопка «Прочитано»').toHaveCount(0)
})
