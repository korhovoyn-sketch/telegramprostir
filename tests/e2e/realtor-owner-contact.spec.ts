import { test, expect, type Page } from '@playwright/test'
import { realtorFixtures } from './helpers/screens'
import { jsonRoute } from './helpers/harness'

/**
 * КОНТАКТ ВЛАСНИКА В БАЗІ РІЄЛТОРА.
 *
 * Знайдено проходом на ЖИВІЙ базі: екран читав рядок власника прямо з `users`,
 * а єдина політика цієї таблиці — `users_own`, тобто чужого рядка RLS не
 * віддає НІКОЛИ. На справжньому бекенді картка завжди показувала безіменного
 * «Власник» без кнопки «Написати», а ціни форматувались валютою РІЄЛТОРА.
 *
 * Мок-харнес це ховав: на будь-який запит до `users` він віддавав ПОТОЧНОГО
 * користувача, тож у тестах «власником» бази був сам рієлтор. Тепер харнес
 * відповідає як RLS (чужий id → нуль рядків), а контакт іде тим самим шляхом,
 * що й публічна /v, — превʼю за share-токеном, який у рієлтора вже є.
 */

const preview = (rows: unknown[]) => (page: Page) =>
  page.route('**/rest/v1/rpc/get_public_db_preview**', (r) => jsonRoute(r, rows))

const OWNER_ROW = {
  db_id: '10000000-0000-0000-0000-000000000001', db_name: 'БЦ Рубін', property_id: null,
  owner_first_name: 'Андрій', owner_last_name: 'Власенко', owner_tg_username: 'vlasenko',
  owner_phone: null, owner_currency: 'EUR',
}

async function openDb(page: Page) {
  await page.goto('/')
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/).first()).toBeVisible({ timeout: 20_000 })
}

test('рієлтор бачить імʼя власника і може йому написати', async ({ page }) => {
  await realtorFixtures(page)
  await preview([OWNER_ROW])(page)
  await openDb(page)
  await expect(page.locator('.owner-n')).toHaveText('Андрій Власенко')
  await expect(page.locator('.owner-s')).toContainText('@vlasenko')
  await expect(page.getByLabel('Написати власнику')).toBeVisible()
  // Ціни — валютою ВЛАСНИКА: він веде базу в євро, рієлтор у доларах.
  await expect(page.locator('.obj-tot-v').first()).toContainText('€')
})

test('превʼю недоступне (посилання відкликано) — картка без контакту, екран живий', async ({ page }) => {
  await realtorFixtures(page)
  await preview([])(page)
  await openDb(page)
  await expect(page.locator('.owner-n')).toHaveText('Власник')
  await expect(page.getByLabel('Написати власнику')).toHaveCount(0)
  await expect(page.getByText('Щось пішло не так')).toHaveCount(0)
})
