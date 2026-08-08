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

async function setup(page: Page, notifications: unknown[]): Promise<Wire> {
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
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
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

test('вкладки фільтрують: «Перегляди» лишає перегляди, «Система» — порожньо', async ({ page }) => {
  await setup(page, [
    notif(1, { type: 'view', title: 'Перегляд об\'єкта 1' }),
    notif(2, { type: 'view', title: 'Перегляд об\'єкта 2' }),
  ])
  await openApp(page)
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toBeVisible({ timeout: 15_000 })

  await page.locator('.notif-tab', { hasText: 'Перегляди' }).click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toBeVisible()

  await page.locator('.notif-tab', { hasText: 'Система' }).click()
  await expect(page.getByText('Перегляд об\'єкта 1')).toHaveCount(0)
  await expect(page.getByText('Немає сповіщень')).toBeVisible()
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
