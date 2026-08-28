import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * БЛОК «ХТО ПЕРЕГЛЯДАВ» — іменовані глядачі, згруповані по людині.
 *
 * Дві половини, і друга не менш важлива за першу: власні перегляди мусять
 * ВИПАДАТИ. Вставку на картці робить будь-який автентифікований, включно з
 * власником, тож без фільтра стрічка складалась би переважно з його власних
 * відкриттів — і гард, який перевіряє лише «чужий глядач видно», пройшов би
 * на такому коді не помітивши нічого.
 */

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const NOW = new Date().toISOString()
const DB_ID = '10000000-0000-0000-0000-000000000001'

const VIEWS = [
  // Рієлтор: дві РІЗНІ картки + одне відкриття бази.
  { property_id: 'p1', db_id: null, viewer_id: 'v-realtor', viewer_name: 'Олена Ріелтор', created_at: NOW },
  { property_id: 'p2', db_id: null, viewer_id: 'v-realtor', viewer_name: 'Олена Ріелтор', created_at: NOW },
  { property_id: null, db_id: DB_ID, viewer_id: 'v-realtor', viewer_name: 'Олена Ріелтор', created_at: NOW },
  // Редактор команди — друга категорія, яку просив власник.
  { property_id: 'p1', db_id: null, viewer_id: 'v-editor', viewer_name: 'Оля Редактор', created_at: NOW },
  // ВЛАСНИК сам: не має зʼявитись у списку жодним рядком.
  { property_id: 'p1', db_id: null, viewer_id: OWNER.id, viewer_name: 'Микола', created_at: NOW },
  // Анонім публічної /v: теж не сюди — його рахує екран аналітики.
  { property_id: 'p2', db_id: null, viewer_id: null, viewer_name: null, created_at: NOW },
]

async function app(page: Page, views: unknown[]) {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/property_views**', (r: Route) => jsonRoute(r, views))
  for (const t of ['databases', 'properties', 'notifications', 'rent_payments',
                   'rent_payment_records', 'collections', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }
}

async function openNotifications(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Хто переглядав')).toBeVisible({ timeout: 15_000 })
}

test('глядачі згруповані по людині, власні перегляди виключені', async ({ page }) => {
  await app(page, VIEWS)
  await openNotifications(page)

  const rows = page.locator('.notif-l .notif-i')
  // Рівно двоє: рієлтор і редактор. Пʼять рядків даних від них — один рядок UI
  // на людину, інакше блок був би стрічкою подій.
  await expect(rows).toHaveCount(2)
  await expect(page.getByText('Олена Ріелтор')).toBeVisible()
  await expect(page.getByText('Оля Редактор')).toBeVisible()

  // АНТИВАКУУМ: власник у списку не зʼявляється, хоч його рядок у даних Є.
  await expect(page.getByText('Микола', { exact: true })).toHaveCount(0)

  // Дві різні картки + одне відкриття бази — не «3 обʼєкти».
  await expect(page.locator('.notif-i', { hasText: 'Олена Ріелтор' }).locator('.notif-s'))
    .toHaveText(/2 обʼєкти · 1 відкриття бази/)
})

test('без іменованих глядачів блок не малюється зовсім', async ({ page }) => {
  // Лишається САМЕ анонім: якби блок рахував і його, тут був би рядок.
  await app(page, [VIEWS[5]])
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Хто переглядав')).toHaveCount(0)
})
