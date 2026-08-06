import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Попередження про кінець договору. Це СТАН (а не подія в `notifications`), тож
// перевіряємо: правильний запит із межею 30 днів, рівні терміновості, і що
// сповіщення не можна змахнути/видалити, поки термін наближається.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'a', type: 'business_center',
  color: 'pink', share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

/** ISO-дата через `days` днів від сьогодні. */
function inDays(days: number): string {
  return new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)
}

const EXPIRING = [
  { id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, name: 'Офіс 101', tenant_name: 'ТОВ «Ромашка»', lease_end_date: inDays(-3) },  // прострочено
  { id: '20000000-0000-0000-0000-000000000002', db_id: DB_ID, name: 'Офіс 102', tenant_name: 'ФОП Іванов',   lease_end_date: inDays(5) },   // критично
  { id: '20000000-0000-0000-0000-000000000003', db_id: DB_ID, name: 'Офіс 103', tenant_name: null,           lease_end_date: inDays(26) },  // скоро
]

async function setup(page: Page, captured: { url?: string }, rows = EXPIRING) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const url = r.request().url()
    // Саме запит алертів — за наявністю фільтра по lease_end_date
    if (url.includes('lease_end_date')) { captured.url = url; return jsonRoute(r, rows) }
    return jsonRoute(r, [])
  })
  await page.route('**/rest/v1/notifications**', (r) => jsonRoute(r, []))
  for (const t of ['property_folders', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function openNotifications(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Сповіщення').first()).toBeVisible()
}

test('запит алертів фільтрує зайняті обʼєкти з договором у межах 30 днів', async ({ page }) => {
  const captured: { url?: string } = {}
  await setup(page, captured)
  await openNotifications(page)

  await expect.poll(() => captured.url, { timeout: 10_000 }).toBeTruthy()
  const url = decodeURIComponent(captured.url!)
  expect(url, 'лише зайняті').toContain('status=eq.occupied')
  expect(url, 'лише з датою закінчення').toContain('lease_end_date=not.is.null')
  expect(url, 'верхня межа — 30 днів').toMatch(/lease_end_date=lte\./)
  expect(url, 'лише власні обʼєкти').toContain(`owner_id=eq.${USER.id}`)

  // Межа справді +30 днів (у межах доби на випадок переходу дати)
  const m = url.match(/lease_end_date=lte\.(\d{4}-\d{2}-\d{2})/)
  const limit = new Date(m![1] + 'T00:00:00Z').getTime()
  const expected = new Date(inDays(30) + 'T00:00:00Z').getTime()
  expect(Math.abs(limit - expected)).toBeLessThanOrEqual(86400000)
})

test('показує всі три рівні терміновості з правильним текстом', async ({ page }) => {
  await setup(page, {})
  await openNotifications(page)

  await expect(page.getByText('Терміни договорів')).toBeVisible({ timeout: 10_000 })

  // прострочено / критично / скоро
  const overdue = page.locator('.notif-i.lease-overdue', { hasText: 'Офіс 101' })
  await expect(overdue).toBeVisible()
  await expect(overdue).toContainText('Договір закінчився 3 дні тому')
  await expect(overdue).toContainText('ТОВ «Ромашка»')

  const critical = page.locator('.notif-i.lease-critical', { hasText: 'Офіс 102' })
  await expect(critical).toBeVisible()
  await expect(critical).toContainText('Залишилось 5 днів')

  const soon = page.locator('.notif-i.lease-soon', { hasText: 'Офіс 103' })
  await expect(soon).toBeVisible()
  await expect(soon).toContainText('Залишилось 26 днів')

  // Це стан, а не подія — видаляти нічим
  await expect(overdue.locator('.notif-del')).toHaveCount(0)
})

test('тап веде на обʼєкт; вкладка «Договори» фільтрує', async ({ page }) => {
  await setup(page, {})
  await openNotifications(page)
  await expect(page.getByText('Терміни договорів')).toBeVisible({ timeout: 10_000 })

  // Вкладка з лічильником
  await expect(page.locator('.notif-tab', { hasText: 'Договори (3)' })).toBeVisible()
  await page.locator('.notif-tab', { hasText: 'Договори' }).click()
  await expect(page.locator('.notif-i.lease-overdue')).toBeVisible()

  await page.locator('.notif-i', { hasText: 'Офіс 102' }).click()
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible({ timeout: 10_000 })
})

test('порожній стан не суперечить собі, коли алертів немає', async ({ page }) => {
  await setup(page, {}, [])
  await openNotifications(page)
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Терміни договорів')).toHaveCount(0)
})
