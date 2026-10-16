import { test, expect, type Page } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, USER, DB_ID } from './helpers/ownerFixtures'
import { queryRows } from './helpers/rowFilter'

/**
 * ЖУРНАЛ ЗМІН (073) і АВТОР НАДХОДЖЕННЯ.
 *
 * Події пишуть тригери на сервері — їхню повноту й права доводять стенди на
 * живому Postgres. Тут — що екран ПИТАЄ свою базу, показує «хто» правильно
 * (ти — «Ви», інший — на імʼя) і не видає збій за «змін не було».
 *
 * Годинник ownerFixtures — 15.09.2026 10:00 UTC (13:00 за Києвом).
 */

const EDITOR = '00000000-0000-0000-0000-0000000000e1'

const ev = (i: number, kind: string, details: Record<string, unknown>, at: string, actor: string | null, name: string | null) => ({
  id: `75000000-0000-0000-0000-${String(i).padStart(12, '0')}`, db_id: DB_ID, property_id: OCCUPIED.id,
  property_name: 'Офіс 101', actor_id: actor, actor_name: name, kind, details, created_at: at,
})

const EVENTS = [
  ev(1, 'payment_received', { due_date: '2026-08-05', amount: 1000 }, '2026-09-15T08:10:00.000Z', EDITOR, 'Оля Редакторка'),
  ev(2, 'terms_changed', { from: { rent_rate: 16, rent_type: 'per_m2' }, to: { rent_rate: 18, rent_type: 'per_m2' } }, '2026-09-15T07:00:00.000Z', USER.id, 'Микола'),
  ev(3, 'property_vacated', { tenant: 'ТОВ «Ромашка»', to: 'free' }, '2026-09-14T12:00:00.000Z', EDITOR, 'Оля Редакторка'),
]

interface Wire { asked: string[] }

async function journal(page: Page, rows: Record<string, unknown>[] | 'missing' | 'fail', wire: Wire) {
  await page.route('**/rest/v1/db_activity**', (r) => {
    wire.asked.push(decodeURIComponent(r.request().url()))
    if (rows === 'missing') {
      return r.fulfill({ status: 404, contentType: 'application/json',
        body: JSON.stringify({ code: 'PGRST205', message: "Could not find the table 'public.db_activity' in the schema cache" }) })
    }
    if (rows === 'fail') {
      return r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'XX000', message: 'internal failure' }) })
    }
    const q = queryRows(r.request().url(), rows)
    return jsonRoute(r, q.rows, 200, q)
  })
}

async function openJournal(page: Page) {
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Журнал змін', { exact: true }).click()
  await expect(page.locator('.hdr')).toContainText('Журнал змін', { timeout: 15_000 })
}

test('журнал своєї бази: що сталось, з чим і хто — «Ви» для себе, імʼя для інших', async ({ page }) => {
  const wire: Wire = { asked: [] }
  await setup(page, null, (p) => journal(p, EVENTS, wire))
  await openJournal(page)

  const rows = page.locator('.act-row')
  await expect(rows).toHaveCount(3, { timeout: 10_000 })
  await expect(rows.nth(0)).toContainText(/Отримано \$1[,\s ]?000 за серпень 2026/)
  await expect(rows.nth(0)).toContainText('Оля Редакторка')
  await expect(rows.nth(1)).toContainText(/Ставка: \$16\/м² → \$18\/м²/)
  // Власна дія — «Ви», а не власне імʼя: інакше в журналі не видно, де ти.
  await expect(rows.nth(1).locator('.act-s')).toContainText('Ви')
  await expect(rows.nth(1).locator('.act-s')).not.toContainText('Микола')
  await expect(rows.nth(2)).toContainText('Звільнено, орендар був: ТОВ «Ромашка»')
  // Групи — календарні дні.
  await expect(page.locator('.over', { hasText: 'Сьогодні' })).toBeVisible()
  await expect(page.locator('.over', { hasText: 'Вчора' })).toBeVisible()
  // Питали саме цю базу, від свіжих до старих.
  expect(wire.asked.some((u) => u.includes(`db_id=eq.${DB_ID}`) && u.includes('order=created_at.desc'))).toBe(true)
})

test('журнал росте без меж — вантажиться порціями, «Показати ще» дочитує наступну', async ({ page }) => {
  const wire: Wire = { asked: [] }
  const many = Array.from({ length: 60 }, (_, i) =>
    ev(100 + i, 'photo_deleted', {}, new Date(Date.parse('2026-09-15T08:00:00.000Z') - i * 60_000).toISOString(), USER.id, 'Микола'))
  await setup(page, null, (p) => journal(p, many, wire))
  await openJournal(page)

  await expect(page.locator('.act-row')).toHaveCount(50, { timeout: 10_000 })
  await page.getByRole('button', { name: 'Показати ще' }).click()
  await expect(page.locator('.act-row')).toHaveCount(60)
  // Остання порція неповна — далі дочитувати нічого.
  await expect(page.getByRole('button', { name: 'Показати ще' })).toHaveCount(0)
  expect(wire.asked.some((u) => u.includes('offset=50'))).toBe(true)
})

test('без 073: пояснення, а не помилка і не «змін не було»', async ({ page }) => {
  const wire: Wire = { asked: [] }
  await setup(page, null, (p) => journal(p, 'missing', wire))
  await openJournal(page)
  await expect(page.getByText('Журнал ще не увімкнено')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Змін ще не було')).toHaveCount(0)
})

test('збій завантаження — повтор, а не впевнене «змін не було»', async ({ page }) => {
  let fail = true
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/db_activity**', (r) => {
      if (fail) {
        return r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'XX000', message: 'internal failure' }) })
      }
      const q = queryRows(r.request().url(), EVENTS)
      return jsonRoute(r, q.rows, 200, q)
    })
  })
  await openJournal(page)
  await expect(page.getByRole('button', { name: /Повторити|Спробувати/ })).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Змін ще не було')).toHaveCount(0)
  fail = false
  await page.getByRole('button', { name: /Повторити|Спробувати/ }).click()
  await expect(page.locator('.act-row')).toHaveCount(3, { timeout: 10_000 })
})

test('надходження, вписане РЕДАКТОРОМ, несе його імʼя; своє — без підпису', async ({ page }) => {
  const SEPT = '2026-09-05'
  const REC = {
    id: '71000000-0000-0000-0000-000000000009', property_id: OCCUPIED.id, owner_id: USER.id, due_date: SEPT,
    paid_at: '2026-09-07T10:00:00.000Z', amount: 1500, amount_due: 2160, status: 'partial', notes: null,
    created_at: '2026-09-01T09:00:00.000Z', updated_at: '2026-09-01T09:00:00.000Z',
  }
  const part = (id: string, amount: number, day: string, by: string | null, name: string | null) => ({
    id: `72000000-0000-0000-0000-00000000000${id}`, record_id: REC.id, amount, paid_at: `${day}T10:00:00.000Z`,
    notes: null, created_at: `${day}T10:00:00.000Z`, created_by: by, created_by_name: name,
  })
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/rent_payments**', (r) => {
      const row = { id: '61000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id, owner_id: USER.id,
        due_day: 5, notify_days_before: 3, is_active: true, created_at: '2026-09-01T09:00:00.000Z', updated_at: '2026-09-01T09:00:00.000Z' }
      return jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? row : [row])
    })
    await p.route('**/rest/v1/rent_payment_records**', (r) => {
      const q = queryRows(r.request().url(), [REC])
      return (r.request().headers()['accept'] ?? '').includes('object') ? jsonRoute(r, q.rows[0] ?? null) : jsonRoute(r, q.rows, 200, q)
    })
    await p.route('**/rest/v1/rent_payment_parts**', (r) => jsonRoute(r, [
      part('1', 1000, '2026-09-06', EDITOR, 'Оля Редакторка'),
      part('2', 500, '2026-09-07', USER.id, 'Микола'),
    ]))
  })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.locator('.pay-card', { hasText: '5 вересня' }).getByRole('button', { name: /Доплата/ }).click({ timeout: 15_000 })

  const rows = page.locator('.part-row')
  await expect(rows).toHaveCount(2, { timeout: 10_000 })
  await expect(rows.nth(0)).toContainText('Оля Редакторка')
  await expect(rows.nth(1).locator('.part-who')).toHaveCount(0)
})
