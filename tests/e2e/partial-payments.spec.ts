import { test, expect, type Page, type Route } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, USER, NOW } from './helpers/ownerFixtures'
import { filterRows, queryRows } from './helpers/rowFilter'

/**
 * ЧАСТКОВА ОПЛАТА (071): період складається з надходжень, підсумок рахує
 * сервер. Тут — клієнт: що він ПОКАЗУЄ і що він ШЛЕ. Арифметику тригера й
 * права доводять стенди на живому Postgres (`verify-behaviour.sql`,
 * `verify-rls.sql`); мок лише віддає те, що сервер віддав би.
 *
 * Очікувана сума Офісу 101: 18 $/м² × 120 м² (база «розрахункова») = $2 160.
 * Годинник — 15.09.2026; розклад на 5-те, заведений у липні, тож липень і
 * серпень оплачені (інакше вони стали б «Заборгованістю» й заплутали кейси).
 *
 * Харнес за замовчуванням відповідає, що таблиці надходжень НЕМАЄ (стан
 * проду до 071) — тут вона вмикається явно, і останній кейс перевіряє, що
 * без неї форма лишається старою «лише повна оплата».
 */

const SCHEDULE = {
  id: '61000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id, owner_id: USER.id,
  due_day: 5, notify_days_before: 3, is_active: true,
  created_at: '2026-07-10T09:00:00.000Z', updated_at: NOW,
}

const SEPT = '2026-09-05'
const REC_SEPT = '71000000-0000-0000-0000-000000000009'

const REC = (due: string, over: Record<string, unknown> = {}) => ({
  id: `71000000-0000-0000-0000-0000000000${due.slice(5, 7)}`,
  property_id: OCCUPIED.id, owner_id: USER.id, due_date: due, paid_at: `${due}T10:00:00.000Z`,
  amount: 2160, amount_due: 2160, status: 'paid', notes: null, created_at: NOW, updated_at: NOW, ...over,
})

const PAID_BEFORE = [REC('2026-07-05'), REC('2026-08-05')]
const PARTIAL = REC(SEPT, { amount: 1000, amount_due: 2160, status: 'partial', paid_at: '2026-09-06T10:00:00.000Z' })

const PART = (id: string, amount: number, day: string, notes: string | null = null) => ({
  id: `72000000-0000-0000-0000-00000000000${id}`, record_id: REC_SEPT,
  amount, paid_at: `${day}T10:00:00.000Z`, notes, created_at: NOW,
})

const wantsObject = (r: Route) => (r.request().headers()['accept'] ?? '').includes('object')

interface Wire {
  rpc: Record<string, unknown>[]
  recordWrites: Record<string, unknown>[]
  partPatches: { url: string; body: Record<string, unknown> }[]
  partDeletes: string[]
}

async function backend(page: Page, o: {
  records?: Record<string, unknown>[]
  parts?: Record<string, unknown>[] | 'missing'
  rpcReply?: Record<string, unknown>
  patchAffects?: boolean
  wire: Wire
}) {
  await page.route('**/rest/v1/rent_payments**', (r) => {
    const rows = filterRows(r.request().url(), [SCHEDULE])
    return jsonRoute(r, wantsObject(r) ? (rows[0] ?? null) : rows)
  })
  await page.route('**/rest/v1/rent_payment_records**', (r) => {
    const rq = r.request()
    if (rq.method() !== 'GET') {
      const body = rq.postData() ? JSON.parse(rq.postData()!) : {}
      o.wire.recordWrites.push(Array.isArray(body) ? body[0] : body)
      const row = REC(SEPT, Array.isArray(body) ? body[0] : body)
      return jsonRoute(r, wantsObject(r) ? row : [row])
    }
    const q = queryRows(rq.url(), o.records ?? PAID_BEFORE)
    return wantsObject(r) ? jsonRoute(r, q.rows[0] ?? null) : jsonRoute(r, q.rows, 200, q)
  })
  await page.route('**/rest/v1/rent_payment_parts**', (r) => {
    const rq = r.request()
    if (o.parts === 'missing') {
      return r.fulfill({ status: 404, contentType: 'application/json',
        body: JSON.stringify({ code: 'PGRST205', message: "Could not find the table 'public.rent_payment_parts' in the schema cache" }) })
    }
    if (rq.method() === 'PATCH') {
      o.wire.partPatches.push({ url: decodeURIComponent(rq.url()), body: JSON.parse(rq.postData() ?? '{}') })
      // Порожній набір без помилки — так PostgREST під RLS повідомляє про ВІДМОВУ.
      return jsonRoute(r, o.patchAffects === false ? [] : [{ id: 'x' }])
    }
    if (rq.method() === 'DELETE') {
      o.wire.partDeletes.push(decodeURIComponent(rq.url()))
      return jsonRoute(r, [{ id: 'x' }])
    }
    return jsonRoute(r, filterRows(rq.url(), o.parts ?? []))
  })
  await page.route('**/rest/v1/rpc/record_rent_payment**', (r) => {
    o.wire.rpc.push(JSON.parse(r.request().postData() ?? '{}'))
    return jsonRoute(r, o.rpcReply ?? { record_id: REC_SEPT, part_id: 'p', status: 'paid', amount: 2160, amount_due: 2160, error: null })
  })
}

const freshWire = (): Wire => ({ rpc: [], recordWrites: [], partPatches: [], partDeletes: [] })

async function openCalendar(page: Page) {
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.locator('.stat', { hasText: 'Прострочено' })).toBeVisible({ timeout: 15_000 })
}

const septCard = (page: Page) => page.locator('.pay-card', { hasText: '5 вересня' })
const digits = (s: string | null) => (s ?? '').replace(/\D/g, '')

test('календар: частково оплачений період показує ЗАЛИШОК і лишається боргом', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { records: [...PAID_BEFORE, PARTIAL], wire }))
  await openCalendar(page)
  const card = septCard(page)
  await expect(card).toContainText(/Отримано \$1[,\s]?000 з \$2[,\s]?160/, { timeout: 10_000 })
  // Сума до сплати — залишок, а не повні $2 160 поруч з уже отриманою тисячею.
  await expect(card).toContainText(/\$1[,\s]?160/)
  await expect(card.getByRole('button', { name: /Доплата/ })).toBeVisible()
  // Неповна оплата — це НЕ «закрито»: період рахується простроченим…
  await expect(page.locator('.stat', { hasText: 'Прострочено' }).locator('.stat-n')).toHaveText('1')
  // …а гроші, що вже прийшли, — у плитці «Отримано».
  expect(digits(await page.locator('.stat', { hasText: 'Отримано' }).locator('.stat-n').textContent())).toBe('1000')
})

test('доплата: підсумок, залишок у полі, підказка — і ОДИН атомарний виклик', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    records: [...PAID_BEFORE, PARTIAL], parts: [PART('1', 1000, '2026-09-06', 'Готівка')],
    rpcReply: { record_id: REC_SEPT, part_id: 'p2', status: 'partial', amount: 1500, amount_due: 2160, error: null },
    wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Доплата/ }).click()

  await expect(page.locator('.hdr')).toContainText('Доплата', { timeout: 10_000 })
  const sum = page.getByLabel('Підсумок платежу')
  await expect(sum).toContainText(/Очікується\s*\$2[,\s]?160/)
  await expect(sum).toContainText(/Отримано\s*\$1[,\s]?000/)
  await expect(sum).toContainText(/Залишок\s*\$1[,\s]?160/)
  // Надходження видно з датою й приміткою — «коли він заплатив?» без архіву.
  await expect(page.locator('.part-row', { hasText: '6 вересня' })).toContainText('Готівка')

  const amount = page.getByLabel('Сума отриманого платежу')
  await expect(amount).toHaveValue('1160')
  await amount.fill('500')
  await expect(page.locator('.pay-hint')).toHaveText(/залишиться \$660/)

  await page.getByRole('button', { name: 'Додати оплату' }).click()
  await expect.poll(() => wire.rpc.length).toBe(1)
  expect(wire.rpc[0]).toMatchObject({ p_property_id: OCCUPIED.id, p_due_date: SEPT, p_amount: 500, p_amount_due: 2160 })
  // Жодного прямого запису в періоди: підсумок рахує сервер, а не клієнт.
  expect(wire.recordWrites).toEqual([])
  await expect(page.getByText('Часткову оплату записано')).toBeVisible()
  await expect(page.locator('.stat', { hasText: 'Прострочено' })).toBeVisible()
})

test('перша оплата меншою сумою: підказка ДО натискання, запис через RPC', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    parts: [],
    rpcReply: { record_id: REC_SEPT, part_id: 'p', status: 'partial', amount: 1000, amount_due: 2160, error: null },
    wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Отримано/ }).click()
  await expect(page.locator('.hdr')).toContainText('Підтвердити платіж', { timeout: 10_000 })
  // Нового періоду ще немає — підсумку теж.
  await expect(page.getByLabel('Підсумок платежу')).toHaveCount(0)
  await page.getByLabel('Сума отриманого платежу').fill('1000')
  await expect(page.locator('.pay-hint')).toHaveText(/Часткова оплата — залишиться \$1[,\s]?160/)
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expect.poll(() => wire.rpc.length).toBe(1)
  expect(wire.rpc[0]).toMatchObject({ p_amount: 1000, p_amount_due: 2160 })
  await expect(page.getByText('Часткову оплату записано')).toBeVisible()
})

test('оплачений період відкривається на останньому надходженні; виправлення — PATCH саме його', async ({ page }) => {
  const wire = freshWire()
  const parts = [PART('1', 1000, '2026-09-06'), PART('2', 1160, '2026-09-10', 'Переказ')]
  await setup(page, null, (p) => backend(p, {
    records: [...PAID_BEFORE, REC(SEPT, { id: REC_SEPT, paid_at: '2026-09-10T10:00:00.000Z' })], parts, wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Сплачено/ }).click()
  await expect(page.locator('.hdr')).toContainText('Редагувати платіж', { timeout: 10_000 })
  await expect(page.locator('.part-main[aria-pressed="true"]')).toContainText('10 вересня')
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('1160')
  await expect(page.getByLabel('Нотатка до платежу')).toHaveValue('Переказ')

  await page.getByLabel('Сума отриманого платежу').fill('1200')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expect.poll(() => wire.partPatches.length).toBe(1)
  expect(wire.partPatches[0].url).toContain(`id=eq.${parts[1].id}`)
  expect(wire.partPatches[0].body).toMatchObject({ amount: 1200, notes: 'Переказ' })
  await expect(page.getByText('Платіж оновлено')).toBeVisible()
})

test('виправлення, яке RLS мовчки відхилила, НЕ рапортує «оновлено»', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    records: [...PAID_BEFORE, REC(SEPT, { id: REC_SEPT })], parts: [PART('1', 2160, '2026-09-06')],
    patchAffects: false, wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Сплачено/ }).click()
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('2160', { timeout: 10_000 })
  await page.getByLabel('Сума отриманого платежу').fill('2000')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expect(page.getByText('Платіж не зберігся')).toBeVisible()
  await expect(page.getByText('Платіж оновлено')).toHaveCount(0)
  // Лишились на формі — правку не втрачено.
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('2000')
})

test('інше надходження вибирається тапом, «Нове надходження» повертає форму додавання', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    records: [...PAID_BEFORE, REC(SEPT, { id: REC_SEPT })],
    parts: [PART('1', 1000, '2026-09-06', 'Готівка'), PART('2', 1160, '2026-09-10')], wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Сплачено/ }).click()
  await page.locator('.part-main', { hasText: '6 вересня' }).click({ timeout: 10_000 })
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('1000')
  await expect(page.getByLabel('Нотатка до платежу')).toHaveValue('Готівка')
  await page.getByRole('button', { name: 'Нове надходження' }).click()
  await expect(page.locator('.hdr')).toContainText('Доплата')
  await expect(page.getByRole('button', { name: 'Додати оплату' })).toBeVisible()
  await expect(page.locator('.part-main[aria-pressed="true"]')).toHaveCount(0)
})

test('видалення надходження — після підтвердження, з доказом запису, екран лишається', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    records: [...PAID_BEFORE, PARTIAL], parts: [PART('1', 1000, '2026-09-06')], wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Доплата/ }).click()
  await page.getByRole('button', { name: /Видалити надходження/ }).click({ timeout: 10_000 })
  // Фолбек-підтвердження (нативного попапа в харнесі немає).
  await page.locator('.modal').getByRole('button', { name: 'Видалити' }).click()
  await expect.poll(() => wire.partDeletes.length).toBe(1)
  expect(wire.partDeletes[0]).toContain(`id=eq.${PART('1', 0, '').id}`)
  await expect(page.getByText('Надходження видалено')).toBeVisible()
  await expect(page.locator('.hdr')).toContainText('Доплата')
})

test('відмова сервера з кодом пояснюється людською мовою і не закриває форму', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, {
    parts: [], rpcReply: { error: 'invalid_date' }, wire,
  }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Отримано/ }).click()
  await page.getByRole('button', { name: 'Підтвердити' }).click({ timeout: 10_000 })
  await expect(page.getByText('Дата отримання не може бути в майбутньому')).toBeVisible()
  await expect(page.locator('.hdr')).toContainText('Підтвердити платіж')
})

test('архів: часткова оплата входить у «Всього отримано» і підписана залишком', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { records: [...PAID_BEFORE, PARTIAL], wire }))
  await openCalendar(page)
  await page.locator('.seg-b', { hasText: 'Архів' }).click()
  await expect(page.getByText('Всього отримано за весь час').locator('..')).toContainText(/5[,\s]?320/, { timeout: 10_000 })
  await expect(septCard(page)).toContainText(/Частково · залишок \$1[,\s]?160/)
})

test('сповіщення: найближчий платіж — це ЗАЛИШОК, з позначкою «частково»', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { records: [...PAID_BEFORE, PARTIAL], wire }))
  await page.route('**/rest/v1/rent_payments**', (r) => jsonRoute(r, [{
    property_id: OCCUPIED.id, due_day: 5, created_at: SCHEDULE.created_at,
    property: { id: OCCUPIED.id, db_id: OCCUPIED.db_id, name: OCCUPIED.name, tenant_name: OCCUPIED.tenant_name,
      lease_start_date: OCCUPIED.lease_start_date, status: 'occupied', rent_type: 'per_m2', rent_rate: 18,
      area_useful: 100, area_total: 120, area_basis: 'total' },
  }]))
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  const row = page.locator('.notif-i', { hasText: 'Офіс 101' })
  await expect(row).toContainText('частково', { timeout: 10_000 })
  await expect(row).toContainText(/\$1[,\s]?160/)
})

test('БЕЗ 071 форма лишається «лише повна оплата»: ні підказки, ні RPC, запис як доти', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { parts: 'missing', wire }))
  await openCalendar(page)
  await septCard(page).getByRole('button', { name: /Отримано/ }).click()
  await page.getByLabel('Сума отриманого платежу').fill('1000', { timeout: 10_000 })
  // Підказка про залишок збрехала б: записати частину тут нема як.
  await expect(page.locator('.pay-hint')).toHaveCount(0)
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expect.poll(() => wire.recordWrites.length).toBe(1)
  expect(wire.recordWrites[0]).toMatchObject({ status: 'paid', amount: 1000, due_date: SEPT })
  expect(wire.rpc).toEqual([])
})
