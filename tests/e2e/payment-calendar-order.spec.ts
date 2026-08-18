import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, skipCoachmarks, jsonRoute as json } from './helpers/harness'

/**
 * ПОРЯДОК БЛОКІВ У КАЛЕНДАРІ ПЛАТЕЖІВ.
 *
 * Скарга власника: «спершу треба показати де платежі є, а потім де їх немає, в
 * нас навпаки». І це справді був порядок у коді: блок «Немає розкладу» стояв
 * ПЕРЕД місячними секціями. На пристрої це читалось як «платежів немає
 * взагалі» — список справ відсував сам календар за фолд.
 *
 * Гард міряє ГЕОМЕТРІЮ, а не порядок у DOM: саме вертикальна позиція є тим, що
 * бачить користувач, і вона не залежить від того, як саме блоки згруповані у
 * розмітці.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
}

function prop(n: number, name: string) {
  return {
    id: `2000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name, floor: String(n),
    status: 'occupied', area_useful: 100, area_total: 120, rent_type: 'per_m2',
    rent_rate: 18, utilities_rate: null, has_parking: false, parking_spaces: 0,
    parking_type: null, ev_charger: false, utilities: null, description: null,
    address: null, sale_price: null, tenant_name: 'ТОВ «Ромашка»',
    lease_start_date: '2025-01-01', lease_end_date: '2027-01-01',
    sort_order: n * 100, share_token: `bb0000000000000000000_${n}`,
    share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [],
  }
}

// Двоє обʼєктів — інакше перевіряти нема чого: потрібен і платіж, і «справа».
const WITH_SCHEDULE = prop(1, 'Офіс 101')
const NO_SCHEDULE   = prop(2, 'Офіс 202')

async function openCalendar(page: Page) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object')
      ? WITH_SCHEDULE
      : [WITH_SCHEDULE, NO_SCHEDULE]))
  // Розклад лише в першого: день 1 — завжди в поточному місяці, тож секція
  // місяця гарантовано непорожня незалежно від дати прогону.
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, [{
    id: '60000000-0000-0000-0000-000000000001', property_id: WITH_SCHEDULE.id,
    owner_id: USER.id, due_day: 1, notify_days_before: 3, is_active: true,
    created_at: NOW, updated_at: NOW,
  }]))
  await page.route('**/rest/v1/rent_payment_records**', (r) => json(r, []))
  for (const t of ['property_folders', 'property_files', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expect(page.getByText(/Календар платежів|Платежі — /)).toBeVisible({ timeout: 15_000 })
}

test('спершу платежі, і лише ПОТІМ обʼєкти без розкладу', async ({ page }) => {
  await openCalendar(page)

  const payments = page.locator('.notif-i, .list').filter({ hasText: 'Офіс 101' }).first()
  const chores   = page.getByText('Немає розкладу')
  await expect(payments).toBeVisible({ timeout: 15_000 })
  await expect(chores).toBeVisible()

  const payTop   = (await payments.boundingBox())!.y
  const choreTop = (await chores.boundingBox())!.y

  expect(choreTop,
    `«Немає розкладу» (y=${Math.round(choreTop)}) стоїть ВИЩЕ за платежі (y=${Math.round(payTop)}) — `
    + 'екран відкривається списком справ замість календаря')
    .toBeGreaterThan(payTop)
})

test('обʼєкт без розкладу все ще досяжний — блок не зник, а переїхав', async ({ page }) => {
  // Антивакуумність: гард порядку легко «пройти», прибравши блок узагалі.
  await openCalendar(page)
  await expect(page.getByText('Немає розкладу')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Офіс 202')).toBeVisible()
  await expect(page.getByRole('button', { name: /Налаштувати/ })).toBeVisible()
})
