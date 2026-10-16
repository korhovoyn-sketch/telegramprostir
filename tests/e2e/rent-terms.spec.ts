import { test, expect, type Page, type Route } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, USER, NOW } from './helpers/ownerFixtures'
import { filterRows, queryRows } from './helpers/rowFilter'

/**
 * УМОВИ ОРЕНДИ В ЧАСІ (072): борг за минулий місяць рахується за ставкою, що
 * діяла ТОДІ, а не за поточною. Плюс «Сума за період» — вихід для неповного
 * місяця, знижки й виправленої описки.
 *
 * Офіс 101 зараз: 18 $/м² × 120 м² = $2 160. Ставку підняли 20 серпня з 16
 * (16 × 120 = $1 920). Годинник — 15.09.2026, розклад на 5-те з липня, липень
 * оплачено: отже серпень — заборгованість, і вона мусить бути $1 920, а не
 * $2 160. Вересень — уже за новою ставкою.
 *
 * Що саме доводить історія, і чого НЕ доводить: арифметику тригера й права
 * перевіряють стенди на живому Postgres; тут — що клієнт ПИТАЄ історію і
 * рахує нею КОЖЕН період, а не лише поточний.
 */

const SCHEDULE = {
  id: '61000000-0000-0000-0000-000000000072', property_id: OCCUPIED.id, owner_id: USER.id,
  due_day: 5, notify_days_before: 3, is_active: true,
  created_at: '2026-07-10T09:00:00.000Z', updated_at: NOW,
}
const AUG = '2026-08-05'
const JULY_PAID = {
  id: '71000000-0000-0000-0000-000000000707', property_id: OCCUPIED.id, owner_id: USER.id,
  due_date: '2026-07-05', paid_at: '2026-07-05T10:00:00.000Z', amount: 1920, amount_due: 1920,
  status: 'paid', notes: null, created_at: NOW, updated_at: NOW,
}
const RAISE = {
  id: '73000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id,
  rent_rate: 16, rent_type: 'per_m2', area_basis: 'total', area_useful: 100, area_total: 120,
  valid_until: '2026-08-20T09:00:00.000Z',
}

const wantsObject = (r: Route) => (r.request().headers()['accept'] ?? '').includes('object')

interface Wire { rpc: Record<string, unknown>[]; due: Record<string, unknown>[]; termsAsked: string[] }

async function backend(page: Page, o: {
  records?: Record<string, unknown>[]
  terms?: Record<string, unknown>[] | 'missing'
  wire: Wire
}) {
  await page.route('**/rest/v1/rent_payments**', (r) => {
    const rows = filterRows(r.request().url(), [SCHEDULE])
    return jsonRoute(r, wantsObject(r) ? (rows[0] ?? null) : rows)
  })
  await page.route('**/rest/v1/rent_payment_records**', (r) => {
    const q = queryRows(r.request().url(), o.records ?? [JULY_PAID])
    return wantsObject(r) ? jsonRoute(r, q.rows[0] ?? null) : jsonRoute(r, q.rows, 200, q)
  })
  await page.route('**/rest/v1/rent_payment_parts**', (r) => jsonRoute(r, []))
  if (o.terms !== 'missing') {
    const terms = o.terms ?? [RAISE]
    await page.route('**/rest/v1/property_rent_terms**', (r) => {
      o.wire.termsAsked.push(decodeURIComponent(r.request().url()))
      return jsonRoute(r, filterRows(r.request().url(), terms))
    })
  }
  await page.route('**/rest/v1/rpc/record_rent_payment**', (r) => {
    o.wire.rpc.push(JSON.parse(r.request().postData() ?? '{}'))
    return jsonRoute(r, { record_id: '71000000-0000-0000-0000-000000000808', part_id: 'p', status: 'paid', amount: 1920, amount_due: 1920, error: null })
  })
  await page.route('**/rest/v1/rpc/set_rent_amount_due**', (r) => {
    o.wire.due.push(JSON.parse(r.request().postData() ?? '{}'))
    return jsonRoute(r, { record_id: '71000000-0000-0000-0000-000000000808', status: 'pending', amount_due: 960, error: null })
  })
}

const freshWire = (): Wire => ({ rpc: [], due: [], termsAsked: [] })

async function openCalendar(page: Page) {
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.locator('.stat', { hasText: 'Прострочено' })).toBeVisible({ timeout: 15_000 })
}

const card = (page: Page, day: string) => page.locator('.pay-card', { hasText: day })
const money = (n: string) => new RegExp(`\\$${n.slice(0, 1)}[,\\s\\u00a0]?${n.slice(1)}`)

test('борг ДО підняття ставки — за старою ставкою, поточний місяць — за новою', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { wire }))
  await openCalendar(page)

  await expect(card(page, '5 серпня')).toContainText(money('1920'), { timeout: 10_000 })
  // Антивакуум: нова ставка на екрані Є — інакше «$1 920» могло б братись
  // нізвідки (наприклад, якби історію застосовували до всіх періодів).
  await expect(card(page, '5 вересня')).toContainText(money('2160'))
  await expect(card(page, '5 серпня')).not.toContainText(money('2160'))
  // Історію питали саме про обʼєкти екрана, а не всю таблицю.
  expect(wire.termsAsked.some((u) => u.includes(`property_id=in.(${OCCUPIED.id})`))).toBe(true)
})

test('підтвердження серпня: дефолт і ЗАМОРОЖЕНА сума — за серпневою ставкою', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { wire }))
  await openCalendar(page)
  await card(page, '5 серпня').getByRole('button', { name: /Отримано/ }).click()

  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('1920', { timeout: 10_000 })
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expect.poll(() => wire.rpc.length).toBe(1)
  // Саме ця сума заморожується в періоді: $2 160 тут зробили б оплату в
  // $1 920 «частковою» назавжди.
  expect(wire.rpc[0]).toMatchObject({ p_due_date: AUG, p_amount: 1920, p_amount_due: 1920 })
})

test('«Сума за період»: змінюється лише цей період, через один виклик, з поверненням назад', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { wire }))
  await openCalendar(page)
  await card(page, '5 серпня').getByRole('button', { name: /Отримано/ }).click()

  await page.getByRole('button', { name: /Змінити суму за період/ }).click({ timeout: 10_000 })
  await expect(page.locator('.hdr')).toContainText('Сума за період', { timeout: 10_000 })
  const field = page.getByLabel('Сума до сплати за період')
  await expect(field).toHaveValue('1920')
  // Незмінена сума — нічого зберігати.
  await expect(page.getByRole('button', { name: 'Зберегти' })).toBeDisabled()

  await field.fill('960')
  await expect(page.getByText(/За ставкою: \$1[,\s ]?920/)).toBeVisible()
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await expect.poll(() => wire.due.length).toBe(1)
  expect(wire.due[0]).toEqual({ p_property_id: OCCUPIED.id, p_due_date: AUG, p_amount_due: 960 })
  await expect(page.getByText('Суму за період змінено')).toBeVisible()
  // Назад — на форму платежу того ж періоду, а не кудись іще.
  await expect(page.getByLabel('Сума отриманого платежу')).toBeVisible({ timeout: 10_000 })
})

test('сума періоду, задана руками, — це те, що чекає календар і форма', async ({ page }) => {
  const wire = freshWire()
  const AUG_960 = { ...JULY_PAID, id: '71000000-0000-0000-0000-000000000808', due_date: AUG,
    paid_at: null, amount: null, amount_due: 960, status: 'pending' }
  await setup(page, null, (p) => backend(p, { records: [JULY_PAID, AUG_960], wire }))
  await openCalendar(page)

  await expect(card(page, '5 серпня')).toContainText(money('960'), { timeout: 10_000 })
  await expect(card(page, '5 серпня')).not.toContainText(money('1920'))
  await card(page, '5 серпня').getByRole('button', { name: /Отримано/ }).click()
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('960', { timeout: 10_000 })
})

test('частково оплачений період: наслідок нової суми видно ДО збереження', async ({ page }) => {
  const wire = freshWire()
  const AUG_PART = { ...JULY_PAID, id: '71000000-0000-0000-0000-000000000808', due_date: AUG,
    paid_at: '2026-08-06T10:00:00.000Z', amount: 1000, amount_due: 1920, status: 'partial' }
  await setup(page, null, (p) => backend(p, { records: [JULY_PAID, AUG_PART], wire }))
  await openCalendar(page)
  await card(page, '5 серпня').getByRole('button', { name: /Доплата/ }).click()
  await page.getByRole('button', { name: /Змінити суму за період/ }).click({ timeout: 10_000 })

  const field = page.getByLabel('Сума до сплати за період')
  await field.fill('1000')
  await expect(page.getByRole('status')).toContainText('Період стане оплаченим')
  await field.fill('1500')
  await expect(page.getByRole('status')).toContainText(/Залишиться \$500/)
})

test('без 072: поточна ставка для всіх періодів і жодного входу в «Суму за період»', async ({ page }) => {
  const wire = freshWire()
  await setup(page, null, (p) => backend(p, { terms: 'missing', wire }))
  await openCalendar(page)
  // Стан до міграції: історії немає — серпень за поточною ставкою, як і доти.
  await expect(card(page, '5 серпня')).toContainText(money('2160'), { timeout: 10_000 })

  await card(page, '5 серпня').getByRole('button', { name: /Отримано/ }).click()
  await expect(page.getByLabel('Сума отриманого платежу')).toHaveValue('2160', { timeout: 10_000 })
  // Кнопка вела б у відмову сервера (RPC теж із 072).
  await expect(page.getByRole('button', { name: /Змінити суму за період/ })).toHaveCount(0)
  await expect(page.getByLabel('Підсумок платежу')).toHaveCount(0)
})
