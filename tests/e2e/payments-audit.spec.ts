import { test, expect, type Page, type Route } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, FREE, USER, NOW, DB_ID } from './helpers/ownerFixtures'
import { filterRows, queryRows } from './helpers/rowFilter'

/**
 * АУДИТ РОЗДІЛУ ПЛАТЕЖІВ — архів, підтвердження, межі боргу, повнота вибірки.
 *
 * Кожен кейс тут — про те, ЩО ПОТРАПИЛО У ВИБІРКУ, тож моки фільтрують рядки
 * за запитом (`filterRows`), а не віддають фікстуру цілком: інакше код, що
 * питав не про ті обʼєкти, отримував би «правильну» відповідь і проходив.
 *
 * Годинник — 15.09.2026 (`ownerFixtures.setup`).
 */

const SCHEDULE = (over: Record<string, unknown> = {}) => ({
  id: '60000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id, owner_id: USER.id,
  due_day: 5, notify_days_before: 3, is_active: true,
  created_at: '2026-07-10T09:00:00.000Z', updated_at: NOW, ...over,
})

let seq = 0
const RECORD = (propertyId: string, due: string, amount: number, over: Record<string, unknown> = {}) => ({
  id: `70000000-0000-0000-0000-${String(++seq).padStart(12, '0')}`,
  property_id: propertyId, owner_id: USER.id, due_date: due, paid_at: `${due}T10:00:00.000Z`,
  amount, status: 'paid', notes: null, created_at: NOW, updated_at: NOW, ...over,
})

const TENANCY = (over: Record<string, unknown>) => ({
  id: `80000000-0000-0000-0000-${String(++seq).padStart(12, '0')}`, owner_id: USER.id, db_id: DB_ID,
  property_id: OCCUPIED.id, property_name: OCCUPIED.name, tenant_name: 'ТОВ «Ромашка»', landlord_name: null,
  rent_rate: 18, rent_type: 'per_m2', utilities_rate: 2.5, area_basis: 'total', area_useful: 100, area_total: 120,
  currency: 'USD', lease_start_date: null, lease_end_date: null,
  started_at: '2026-01-01T00:00:00.000Z', ended_at: null, created_at: NOW, updated_at: NOW, ...over,
})

const wantsObject = (r: Route) => (r.request().headers()['accept'] ?? '').includes('object')

/** Бекенд платежів, що ЧЕСНО фільтрує вибірку. */
async function payments(page: Page, o: {
  properties?: Record<string, unknown>[]
  schedules?: Record<string, unknown>[]
  records?: Record<string, unknown>[]
  tenancies?: Record<string, unknown>[] | 'missing'
  maxRows?: number
  posts?: Record<string, unknown>[]
}) {
  const props = o.properties ?? [OCCUPIED, FREE]
  await page.route('**/rest/v1/properties**', (r) => {
    const rows = filterRows(r.request().url(), props)
    return jsonRoute(r, wantsObject(r) ? (rows[0] ?? null) : rows)
  })
  await page.route('**/rest/v1/rent_payments**', (r) => {
    const rows = filterRows(r.request().url(), o.schedules ?? [])
    return jsonRoute(r, wantsObject(r) ? (rows[0] ?? null) : rows)
  })
  await page.route('**/rest/v1/rent_payment_records**', (r) => {
    const rq = r.request()
    if (rq.method() !== 'GET') {
      const body = rq.postData() ? JSON.parse(rq.postData()!) : {}
      o.posts?.push(Array.isArray(body) ? body[0] : body)
      const row = RECORD(OCCUPIED.id, '2026-09-05', 0, Array.isArray(body) ? body[0] : body)
      return jsonRoute(r, wantsObject(r) ? row : [row])
    }
    const q = queryRows(rq.url(), o.records ?? [], { maxRows: o.maxRows })
    return wantsObject(r) ? jsonRoute(r, q.rows[0] ?? null) : jsonRoute(r, q.rows, 200, q)
  })
  await page.route('**/rest/v1/tenancies**', (r) => {
    if (o.tenancies === 'missing') {
      return r.fulfill({ status: 404, contentType: 'application/json',
        body: JSON.stringify({ code: '42P01', message: 'relation "public.tenancies" does not exist' }) })
    }
    return jsonRoute(r, filterRows(r.request().url(), o.tenancies ?? []))
  })
}

async function openCalendar(page: Page) {
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.locator('.stat', { hasText: 'Прострочено' })).toBeVisible({ timeout: 15_000 })
}

async function openArchive(page: Page) {
  await openCalendar(page)
  await page.locator('.seg-b', { hasText: 'Архів' }).click()
}

const overdueStat = (page: Page) => page.locator('.stat', { hasText: 'Прострочено' }).locator('.stat-n')
const digits = (s: string | null) => (s ?? '').replace(/\D/g, '')

test('архів показує платежі ЗВІЛЬНЕНОГО обʼєкта і рахує їх у загальну суму', async ({ page }) => {
  await setup(page, null, (p) => payments(p, {
    schedules: [SCHEDULE()],
    records: [RECORD(OCCUPIED.id, '2026-09-05', 2160), RECORD(FREE.id, '2026-03-05', 1500)],
  }))
  await openArchive(page)
  // Антивакуум: платіж зайнятого обʼєкта на місці.
  await expect(page.getByText('Офіс 101')).toBeVisible({ timeout: 10_000 })
  // Звільнений обʼєкт — це історія, а не сміття: його гроші отримано.
  await expect(page.getByText('Офіс 102')).toBeVisible()
  await expect(page.getByText('Всього отримано за весь час').locator('..')).toContainText(/3\s?660/)
  // Плюрал, а не «2 платежів».
  await expect(page.getByText(/2 платежі · 2 міс\./)).toBeVisible()
})

test('без жодного зайнятого обʼєкта історія платежів лишається досяжною', async ({ page }) => {
  await setup(page, null, (p) => payments(p, {
    properties: [FREE],
    records: [RECORD(FREE.id, '2026-03-05', 1500)],
  }))
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.locator('.seg-b', { hasText: 'Архів' }).click()
  await expect(page.getByText('Офіс 102')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Всього отримано за весь час').locator('..')).toContainText(/1\s?500/)
})

test('архів не приписує старий платіж ПОТОЧНОМУ орендарю', async ({ page }) => {
  await setup(page, null, (p) => payments(p, {
    schedules: [SCHEDULE()],
    records: [RECORD(OCCUPIED.id, '2025-11-05', 1900), RECORD(OCCUPIED.id, '2026-09-05', 2160)],
    tenancies: [
      TENANCY({ tenant_name: 'ФОП Іванов', started_at: '2025-06-01T00:00:00.000Z', ended_at: '2025-12-20T12:00:00.000Z' }),
      TENANCY({ started_at: '2026-01-01T00:00:00.000Z' }),
    ],
  }))
  await openArchive(page)
  const nov = page.locator('.pay-card', { hasText: '5 листопада' })
  const sep = page.locator('.pay-card', { hasText: '5 вересня' })
  await expect(nov).toContainText('ФОП Іванов', { timeout: 10_000 })
  await expect(nov).not.toContainText('Ромашка')
  // Антивакуум: свіжий платіж — справді поточного орендаря.
  await expect(sep).toContainText('Ромашка')
})

test('повторно зданий обʼєкт без дати договору не отримує боргів за час простою', async ({ page }) => {
  // Розклад лишився від ПОПЕРЕДНЬОЇ оренди (звільнення його не прибирає), а
  // нову оренду відкрито 10.09 без дати договору.
  const reRented = { ...OCCUPIED, lease_start_date: null }
  await setup(page, null, (p) => payments(p, {
    properties: [reRented, FREE],
    schedules: [SCHEDULE({ created_at: '2026-03-01T09:00:00.000Z' })],
    tenancies: [TENANCY({ started_at: '2026-09-10T09:00:00.000Z' })],
  }))
  await openCalendar(page)
  await expect(page.getByText('5 жовтня')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('.over', { hasText: 'Заборгованість' })).toHaveCount(0)
  await expect(overdueStat(page)).toHaveText('0')
})

test('без архіву оренд (067) межа боргу лишається попередньою — нічого не ховається наосліп', async ({ page }) => {
  const reRented = { ...OCCUPIED, lease_start_date: null }
  await setup(page, null, (p) => payments(p, {
    properties: [reRented, FREE],
    schedules: [SCHEDULE({ created_at: '2026-08-01T09:00:00.000Z' })],
    tenancies: 'missing',
  }))
  await openCalendar(page)
  // Без джерела про початок оренди серпневий платіж лишається боргом: сховати
  // його означало б вигадати межу, якої ми не знаємо.
  await expect(page.locator('.over', { hasText: 'Заборгованість' })).toBeVisible({ timeout: 10_000 })
})

test('редагування підтвердженого платежу НЕ переписує дату отримання', async ({ page }) => {
  const posts: Record<string, unknown>[] = []
  await setup(page, null, (p) => payments(p, {
    schedules: [SCHEDULE()],
    records: [RECORD(OCCUPIED.id, '2026-03-05', 2160, { paid_at: '2026-03-07T10:00:00.000Z' })],
    posts,
  }))
  await openArchive(page)
  await page.locator('.pay-card', { hasText: '5 березня' }).getByRole('button', { name: /Редагувати/ }).click()
  await expect(page.getByText('Редагувати платіж')).toBeVisible({ timeout: 10_000 })
  const amount = page.getByLabel('Сума отриманого платежу')
  await amount.fill('2200')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expect.poll(() => posts.length).toBe(1)
  expect(String(posts[0].paid_at)).toMatch(/^2026-03-07/)
  expect(posts[0].amount).toBe(2200)
})

test('дату отримання можна вказати — підтверджують часто пізніше, ніж отримали', async ({ page }) => {
  const posts: Record<string, unknown>[] = []
  await setup(page, null, (p) => payments(p, { schedules: [SCHEDULE()], posts }))
  await openCalendar(page)
  await page.locator('.list').getByRole('button', { name: /Отримано/ }).first().click()
  await expect(page.getByText('Підтвердити платіж')).toBeVisible({ timeout: 10_000 })
  await page.getByLabel('Дата отримання').fill('2026-09-08')
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expect.poll(() => posts.length).toBe(1)
  // Локальний день отримання, а не мить натискання.
  const paid = new Date(String(posts[0].paid_at))
  expect([paid.getFullYear(), paid.getMonth() + 1, paid.getDate()]).toEqual([2026, 9, 8])
})

test('порожня сума платіж НЕ підтверджує', async ({ page }) => {
  await setup(page, null, (p) => payments(p, { schedules: [SCHEDULE()] }))
  await openCalendar(page)
  await page.locator('.list').getByRole('button', { name: /Отримано/ }).first().click()
  await expect(page.getByText('Підтвердити платіж')).toBeVisible({ timeout: 10_000 })
  const amount = page.getByLabel('Сума отриманого платежу')
  // Антивакуум: поле префілене очікуваною сумою, тобто кнопка БУЛА активна.
  await expect(page.getByRole('button', { name: 'Підтвердити' })).toBeEnabled()
  await amount.fill('')
  await expect(page.getByRole('button', { name: 'Підтвердити' })).toBeDisabled()
})

test('архів понад 1000 платежів рахує ВСІ — серверна межа не обрізає суму мовчки', async ({ page }) => {
  const many = Array.from({ length: 1200 }, (_, i) => {
    const y = 2020 + Math.floor(i / 12 / 28)
    const m = (Math.floor(i / 28) % 12) + 1
    const d = (i % 28) + 1
    return RECORD(i % 2 ? OCCUPIED.id : FREE.id,
      `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`, 10)
  })
  await setup(page, null, (p) => payments(p, { schedules: [SCHEDULE()], records: many, maxRows: 1000 }))
  await openArchive(page)
  const total = page.getByText('Всього отримано за весь час').locator('..')
  await expect(total).toBeVisible({ timeout: 15_000 })
  expect(digits(await total.locator('div').nth(1).textContent())).toBe('12000')
})
