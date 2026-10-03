import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, objectAction, PHOTO_PNG } from './helpers/harness'
import { USER, NOW, OCCUPIED, setup, openDb, type Fail } from './helpers/ownerFixtures'

/**
 * СЕРВЕР ВІДМОВИВ — ЩО БАЧИТЬ ЛЮДИНА.
 *
 * Наявні спеки перевіряють збій ВИБІРКОВО: 403 на платежі, RLS-відмову на
 * відкликанні, офлайн-гард. Тут — один і той самий контракт для КОЖНОЇ основної
 * дії власника: сервер відповідає 500, і тоді
 *   1. людина бачить ПОМИЛКУ (тост `.toast.err`), а не тишу;
 *   2. немає хибного «успіху» — ані тоста, ані переходу, ніби все збереглось;
 *   3. кнопка не лишається в «завантаженні» назавжди;
 *   4. застосунок не падає в ErrorBoundary.
 *
 * Кожна дія ламає РІВНО ОДИН запит — той, що й є сама дія; решта бекенда
 * жива. Інакше тест міряв би «екран не завантажився», а не «дія не вдалась».
 */

const SUCCESS = /Збережено|видалено|Видалено|створено|Створено|здано в оренду|звільнено|оновлено|Платіж підтверджено|Розклад збережено/

async function expectHandled(page: Page) {
  const toast = page.locator('.toast')
  await expect(toast, 'збій не показав жодного повідомлення').toBeVisible({ timeout: 10_000 })
  await expect(toast, 'повідомлення про збій мусить бути ПОМИЛКОЮ, а не успіхом').toHaveClass(/\berr\b/)
  await expect(toast).not.toContainText(SUCCESS)
  await expect(page.getByText('Щось пішло не так')).toHaveCount(0)
  // Кнопка, що лишилась у «завантаженні», — це вічний спінер без виходу.
  await expect(page.locator('[aria-busy="true"], .is-loading')).toHaveCount(0, { timeout: 5_000 })
}

test('редагування обʼєкта', async ({ page }) => {
  await setup(page, { method: 'PATCH', path: '/rest/v1/properties' })
  await openDb(page)
  await objectAction(page, 'Редагувати')
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expectHandled(page)
  await expect(page.getByText('Редагування'), 'після збою форма мусить лишитись — інакше правки втрачені').toBeVisible()
})

test('створення обʼєкта', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/properties' })
  await openDb(page)
  await page.getByRole('button', { name: /Додати обʼєкт|Новий обʼєкт/ }).first().click()
  await page.getByPlaceholder('Офіс 101').fill('Склад')
  await page.getByRole('button', { name: /^Додати|Створити/ }).last().click()
  await expectHandled(page)
  await expect(page.getByText('Новий обʼєкт')).toBeVisible()
})

test('видалення обʼєкта', async ({ page }) => {
  await setup(page, { method: 'DELETE', path: '/rest/v1/properties' })
  await openDb(page)
  await objectAction(page, 'Редагувати')
  await page.getByRole('button', { name: /^Видалити/ }).first().click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити/ }).click()
  await expectHandled(page)
})

test('«Здати в оренду»', async ({ page }) => {
  await setup(page, { method: 'PATCH', path: '/rest/v1/properties' })
  await openDb(page)
  await page.locator('.obj-t', { hasText: 'Офіс 102' }).click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await page.getByLabel('Орендар').fill('ТОВ «Липа»')
  await page.getByRole('button', { name: 'Здати в оренду' }).last().click()
  await expectHandled(page)
})

test('«Звільнити обʼєкт»', async ({ page }) => {
  await setup(page, { method: 'PATCH', path: '/rest/v1/properties' })
  await openDb(page)
  await page.locator('.obj-t', { hasText: 'Офіс 101' }).click()
  await page.getByRole('button', { name: /Звільнити/ }).click()
  const modal = page.locator('.modal')
  if (await modal.count()) await modal.last().getByRole('button', { name: /Звільнити/ }).click()
  await expectHandled(page)
  await expect(page.locator('.obj-hero'), 'невдале звільнення лишило статус «Вільно»').toContainText('Зайнято')
})

test('створення бази', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/databases' })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /Створити базу|Нова база/ }).first().click()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Нова')
  await page.locator('.type-card').first().click()
  await page.getByRole('button', { name: 'Створити базу' }).last().click()
  await expectHandled(page)
})

test('редагування бази', async ({ page }) => {
  await setup(page, { method: 'PATCH', path: '/rest/v1/databases' })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Редагувати базу').click()
  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Рубін Плаза')
  await page.getByRole('button', { name: /Зберегти/ }).click()
  await expectHandled(page)
})

test('видалення бази', async ({ page }) => {
  await setup(page, { method: 'DELETE', path: '/rest/v1/databases' })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити/ }).click()
  await expectHandled(page)
})

test('видалення бази: шляхи файлів не прочиталися — НЕ видаляти', async ({ page }) => {
  let deleted = false
  await setup(page, { method: 'GET', path: '/rest/v1/property_photos' }, async (p) => {
    await p.route('**/rest/v1/databases**', (r) => {
      if (r.request().method() === 'DELETE') deleted = true
      return r.fallback()
    })
  })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити/ }).click()
  await expectHandled(page)
  expect(deleted, 'база видалена, хоча шляхи фото невідомі — файли лишились би в ПУБЛІЧНОМУ бакеті назавжди').toBe(false)
})

test('видалення обʼєкта: шляхи файлів не прочиталися — НЕ видаляти', async ({ page }) => {
  let deleted = false
  await setup(page, { method: 'GET', path: '/rest/v1/property_files' }, async (p) => {
    await p.route('**/rest/v1/properties**', (r) => {
      if (r.request().method() === 'DELETE') deleted = true
      return r.fallback()
    })
  })
  await openDb(page)
  await objectAction(page, 'Редагувати')
  await page.getByRole('button', { name: /^Видалити/ }).first().click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити/ }).click()
  await expectHandled(page)
  expect(deleted).toBe(false)
})

test('розклад платежів', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/rent_payments' })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await page.getByLabel('День місяця').fill('1')
  await page.getByRole('button', { name: 'Зберегти' }).click()
  await expectHandled(page)
  await expect(page.getByText('Налаштувати розклад')).toBeVisible()
})

test('нова папка', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/property_folders' })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await page.getByPlaceholder(/Назва папки|Нова папка/).first().fill('Перший поверх')
  await page.getByRole('button', { name: /Створити|Додати/ }).last().click()
  await expectHandled(page)
})

test('мова в профілі', async ({ page }) => {
  await setup(page, { method: 'PATCH', path: '/rest/v1/users' })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.getByRole('button', { name: /^Eng/ }).click()
  await expectHandled(page)
})

const SCHEDULE = {
  id: '60000000-0000-0000-0000-000000000001', property_id: OCCUPIED.id, owner_id: USER.id,
  due_day: 1, notify_days_before: 3, is_active: true, created_at: NOW, updated_at: NOW,
}
async function withSchedule(p: Page) {
  await p.route('**/rest/v1/rent_payments**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    // Блок сповіщень питає розклад із вкладеним обʼєктом.
    const row = { ...SCHEDULE, property: OCCUPIED }
    return jsonRoute(r, wantsObject ? row : [row])
  })
}

test('підтвердження платежу', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/rent_payment_records' }, withSchedule)
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.getByRole('button', { name: /Отримано/ }).first().click()
  await page.getByRole('button', { name: 'Підтвердити' }).click()
  await expectHandled(page)
  await expect(page.getByText('Підтвердити платіж'), 'після збою екран підтвердження мусить лишитись').toBeVisible()
})

test('завантаження фото', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/storage/v1/object/photos/' })
  await openDb(page)
  await page.locator('.obj-t', { hasText: 'Офіс 101' }).click()
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles([
    { name: 'a.png', mimeType: 'image/png', buffer: PHOTO_PNG },
  ])
  await expectHandled(page)
  await expect(page.getByText('Завантажено!')).toHaveCount(0)
})

test('завантаження документа', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/functions/v1/validate-upload' })
  await openDb(page)
  await page.locator('.obj-t', { hasText: 'Офіс 101' }).click()
  await page.locator('input[type="file"][accept*=".pdf"]').setInputFiles(
    [{ name: 'dogovir.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n%%EOF') }],
  )
  await expectHandled(page)
})

test('запрошення в команду', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/db_members' })
  await openDb(page)
  await page.getByRole('button', { name: 'Меню бази' }).click()
  await page.getByText('Команда', { exact: true }).click()
  await page.getByRole('button', { name: 'Запросити в команду' }).click()
  await page.getByPlaceholder('напр. Менеджер Оля').fill('Менеджер Оля')
  await page.getByRole('button', { name: 'Створити' }).click()
  await expectHandled(page)
  await expect(page.getByText('Запрошення створено!')).toHaveCount(0)
})

test('оновлення посилання шарингу', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/rpc/manage_share' })
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await page.getByRole('button', { name: 'Поділитися' }).click()
  await page.getByText('Оновити посилання').click()
  await page.getByRole('button', { name: 'Оновити', exact: true }).click()
  await expectHandled(page)
})

test('видалення акаунта', async ({ page }) => {
  await setup(page, { method: 'POST', path: '/rest/v1/rpc/delete_my_account' })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await page.locator('.del-acc').click()
  await page.getByLabel('Підтвердження видалення').fill('ВИДАЛИТИ')
  await page.getByRole('button', { name: 'Видалити акаунт', exact: true }).click()
  await expectHandled(page)
  await expect(page.getByText('Мої бази').or(page.locator('.tabbar')), 'акаунт не видалено — людина не сміє опинитись на вході').toHaveCount(0)
})

/**
 * Похідний блок «Найближчі платежі»: другий запит (записи оплат) падає. Доти
 * порожня множина оплат робила КОЖЕН уже оплачений платіж «прострочено» —
 * тобто збій мережі малював хибну тривогу саме про гроші.
 */
test('найближчі платежі: збій записів оплат не малює хибне «Прострочено»', async ({ page }) => {
  await setup(page, { method: 'GET', path: '/rest/v1/rent_payment_records' }, withSchedule)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await page.waitForTimeout(1500)
  await expect(page.getByText('Найближчі платежі')).toHaveCount(0)
  await expect(page.getByText(/Прострочено/)).toHaveCount(0)
})

test('найближчі платежі: антивакуум — без збою неоплачений платіж ВИДНО', async ({ page }) => {
  await setup(page, { method: 'GET', path: '/__never__' }, withSchedule)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expect(page.getByText('Найближчі платежі')).toBeVisible({ timeout: 10_000 })
})

/**
 * ЗБІЙ ЗАВАНТАЖЕННЯ ≠ «ДАНИХ НЕМАЄ». Порожній стан, намальований поверх
 * збою мережі, читається як ВПЕВНЕНА відповідь про дані, яких екран не бачив:
 * «Баз ще немає», «Платежів немає». Контракт: повтор (`RetryState`) з робочою
 * кнопкою, і жодного порожнього стану.
 */
async function expectRetry(page: Page, emptyText: RegExp) {
  const retry = page.getByRole('button', { name: /Спробувати ще раз|Повторити/ })
  await expect(retry, 'збій завантаження не дав повтору').toBeVisible({ timeout: 10_000 })
  await expect(page.getByText(emptyText), 'збій намалював порожній стан').toHaveCount(0)
  await expect(page.getByText('Щось пішло не так')).toHaveCount(0)
}

test('завантаження: список баз', async ({ page }) => {
  await setup(page, { method: 'GET', path: '/rest/v1/databases' })
  await page.goto('/')
  await expectRetry(page, /Баз ще немає|Створіть першу|Немає баз/)
})

test('завантаження: обʼєкти бази', async ({ page }) => {
  let fail = false
  await setup(page, { method: 'GET', path: '/__never__' }, async (p) => {
    await p.route('**/rest/v1/properties**', (r) => fail && r.request().method() === 'GET'
      ? r.fulfill({ status: 500, contentType: 'application/json', body: '{"message":"x"}' })
      : r.fallback())
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  fail = true
  await page.getByText('БЦ Рубін').first().click()
  await expectRetry(page, /Обʼєктів ще немає|Додайте перший|Немає обʼєктів/)
})

test('завантаження: календар платежів', async ({ page }) => {
  let fail = false
  await setup(page, { method: 'GET', path: '/__never__' }, async (p) => {
    await p.route('**/rest/v1/rent_payments**', (r) => fail
      ? r.fulfill({ status: 500, contentType: 'application/json', body: '{"message":"x"}' })
      : r.fallback())
  })
  await openDb(page)
  fail = true
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await expectRetry(page, /Немає розкладу|Платежів немає|Налаштуйте/)
  // Лічильник, що каже «0 прострочено» про дані, яких екран не бачив, — та сама
  // неправда, що й порожній стан, лише в цифрі.
  await expect(page.locator('.stat-n').first()).toHaveText('—')
})

test('завантаження: сповіщення', async ({ page }) => {
  let fail = false
  await setup(page, { method: 'GET', path: '/__never__' }, async (p) => {
    await p.route('**/rest/v1/notifications**', (r) => fail && r.request().method() === 'GET'
      ? r.fulfill({ status: 500, contentType: 'application/json', body: '{"message":"x"}' })
      : r.fallback())
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  fail = true
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
  await expectRetry(page, /Сповіщень немає|Поки тихо|Немає сповіщень/)
})

// ─── Рієлтор ────────────────────────────────────────────────────────────────

const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }

async function setupRealtor(page: Page, fail: Fail) {
  await setupApp(page, { user: REALTOR })
  for (const t of ['realtor_subscriptions', 'databases', 'db_members', 'property_views',
    'notifications', 'collection_properties', 'collections', 'properties']) {
    await page.route(`**/rest/v1/${t}**`, (r) => {
      const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? null : [])
    })
  }
  await page.route('**/*', (r: Route) => {
    const rq = r.request()
    if (rq.method() === fail.method && decodeURIComponent(rq.url()).includes(fail.path)) {
      return r.fulfill({ status: 500, contentType: 'application/json',
        body: JSON.stringify({ code: 'XX000', message: 'internal failure' }) })
    }
    return r.fallback()
  })
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('рієлтор: підписка на базу за кодом', async ({ page }) => {
  await setupRealtor(page, { method: 'POST', path: '/rest/v1/rpc/subscribe_to_shared_db' })
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 25_000 })
  await page.getByRole('button', { name: /Сканувати|QR/ }).first().click()
  await page.getByLabel('Код запрошення').fill('ab00112233445566778899cc')
  await page.getByLabel('Код запрошення').press('Enter')
  await expectHandled(page)
})

test('рієлтор: нова підбірка', async ({ page }) => {
  await setupRealtor(page, { method: 'POST', path: '/rest/v1/collections' })
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 25_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  // Поки список вантажиться, видима лише плаваюча кнопка; щойно приходить
  // порожній стан, вона ховається під таббар, і клік, розпочатий раніше,
  // чекав би на неї до таймауту. Дія — CTA порожнього стану.
  await expect(page.getByText('Немає підбірок')).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'Створити підбірку' }).click()
  await expectHandled(page)
})

test('рієлтор: збій списку баз дає повтор, а не «немає баз»', async ({ page }) => {
  await setupRealtor(page, { method: 'GET', path: '/rest/v1/realtor_subscriptions' })
  await page.goto('/')
  await expectRetry(page, /Ще немає баз|Підключіть першу|Немає баз/)
})

test('рієлтор: збій списку підбірок дає повтор', async ({ page }) => {
  await setupRealtor(page, { method: 'GET', path: '/rest/v1/collections' })
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 25_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await expectRetry(page, /Підбірок ще немає|Створіть першу/)
})
