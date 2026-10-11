import { test, expect, type Page } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, FREE, USER, NOW } from './helpers/ownerFixtures'

/**
 * ЗАБОРГОВАНІСТЬ І ПОЧАТОК ДОГОВОРУ В КАЛЕНДАРІ ПЛАТЕЖІВ.
 *
 * Дві помилки обліку, обидві тихі й обидві про гроші:
 *  1. календар дивився лише від ПОТОЧНОГО місяця вперед, тож неоплачена оренда
 *     за серпень 1 вересня зникала — з екрана й з лічильника «Прострочено»;
 *  2. платіж за дату ДО початку договору рахувався простроченим: здав 10-го з
 *     оплатою 5-го — одразу «Прострочено».
 *
 * Годинник — 15.09.2026 (`ownerFixtures.setup`), тож дні в підписах детерміновані.
 */

const SCHEDULE = (over: Record<string, unknown> = {}) => ({
  id: '60000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id, owner_id: USER.id,
  due_day: 5, notify_days_before: 3, is_active: true,
  created_at: '2026-07-10T09:00:00.000Z', updated_at: NOW, ...over,
})

const RECORD = (due: string) => ({
  id: `70000000-0000-0000-0000-0000000${due.replace(/-/g, '').slice(2)}`,
  property_id: OCCUPIED.id, owner_id: USER.id, due_date: due, paid_at: `${due}T10:00:00.000Z`,
  amount: 2160, status: 'paid', notes: null, created_at: NOW, updated_at: NOW,
})

async function openCalendar(page: Page) {
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.locator('.stat', { hasText: 'Прострочено' })).toBeVisible({ timeout: 15_000 })
}

const overdueStat = (page: Page) => page.locator('.stat', { hasText: 'Прострочено' }).locator('.stat-n')

test('неоплачений платіж минулого місяця лишається боргом — і в секції, і в лічильнику', async ({ page }) => {
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/rent_payments**', (r) => jsonRoute(r, [SCHEDULE()]))
    // Липень оплачено, серпень — ні.
    await p.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, [RECORD('2026-07-05')]))
  })
  await openCalendar(page)

  await expect(page.locator('.over', { hasText: 'Заборгованість' })).toBeVisible()
  // 15.09 − 05.08 = 41 день.
  await expect(page.getByText('Прострочено 41д')).toBeVisible()
  // Антивакуум: оплачений липень боргом НЕ став (15.09 − 05.07 = 72).
  await expect(page.getByText('Прострочено 72д')).toHaveCount(0)
  // Поточний місяць теж прострочений (5.09 < 15.09): лічильник = серпень + вересень.
  await expect(page.getByText('Прострочено 10д')).toBeVisible()
  await expect(overdueStat(page)).toHaveText('2')
})

test('місяці до створення розкладу боргом не вважаються', async ({ page }) => {
  // Розклад заведено цього місяця: за липень і серпень застосунок оплат не
  // відстежував, тож «борг» за них був би вигадкою.
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/rent_payments**', (r) =>
      jsonRoute(r, [SCHEDULE({ created_at: '2026-09-02T09:00:00.000Z' })]))
    await p.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, []))
  })
  await openCalendar(page)
  await expect(page.getByText('Прострочено 10д')).toBeVisible()
  await expect(page.locator('.over', { hasText: 'Заборгованість' })).toHaveCount(0)
  await expect(overdueStat(page)).toHaveText('1')
})

test('платіж до початку договору — не борг', async ({ page }) => {
  // Обʼєкт здано 10.09, оплата 5-го: вересневого платежу ця оренда не має.
  const rentedMidMonth = { ...OCCUPIED, lease_start_date: '2026-09-10' }
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/properties**', (r) => {
      const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? rentedMidMonth : [rentedMidMonth, FREE])
    })
    await p.route('**/rest/v1/rent_payments**', (r) => jsonRoute(r, [SCHEDULE()]))
    await p.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, []))
  })
  await openCalendar(page)
  // Перший платіж цієї оренди — 5 жовтня, і він попереду.
  await expect(page.getByText('5 жовтня')).toBeVisible()
  await expect(page.getByText(/Прострочено \d+д/)).toHaveCount(0)
  await expect(overdueStat(page)).toHaveText('0')
})
