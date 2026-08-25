import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Гайдлайни Telegram вимагають підписів для полів і зображень. Наші рядки форм
// кладуть підпис у СУСІДНІЙ span — візуально добре, програмно не звʼязано, тож
// читалка озвучувала поле плейсхолдером: ставка оренди читалась як «18», площа
// як «47». Плейсхолдер НЕ вважаємо іменем — саме тому баг і жив.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '2', status: 'free', area_useful: 100, area_total: 120,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/users**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_views', 'db_members', 'notifications', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  // Повноекранні платіжні форми читають ці таблиці через `.maybeSingle()` —
  // масив там, де чекають обʼєкт, лишає екран у RetryState замість форми.
  for (const t of ['rent_payments', 'rent_payment_records']) {
    await page.route(`**/rest/v1/${t}**`, (r) =>
      jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? null : []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Поля без програмного імені (aria-label / aria-labelledby / <label>). */
const unnamedFields = (page: Page, where: string) => page.evaluate((w) => {
  const bad: string[] = []
  document.querySelectorAll('input,textarea,select').forEach((el) => {
    const e = el as HTMLInputElement
    if (e.type === 'hidden') return
    const named = e.getAttribute('aria-label')
      || e.getAttribute('aria-labelledby')
      || (e.labels && e.labels.length > 0)
    if (!named) bad.push(`${w}: <${e.tagName.toLowerCase()} type=${e.type}> placeholder=${e.getAttribute('placeholder') ?? '—'}`)
  })
  return bad
}, where)

/** Зображення без alt (порожній alt — валідний для декоративних). */
const imagesWithoutAlt = (page: Page, where: string) => page.evaluate((w) => {
  const bad: string[] = []
  document.querySelectorAll('img').forEach((img) => {
    if (!img.hasAttribute('alt')) bad.push(`${w}: <img src=${img.getAttribute('src')?.slice(0, 40)}>`)
  })
  return bad
}, where)

/** Кнопки-іконки без назви — тап є, а озвучити нічого. */
const unnamedButtons = (page: Page, where: string) => page.evaluate((w) => {
  const bad: string[] = []
  document.querySelectorAll('button,[role="button"]').forEach((el) => {
    const e = el as HTMLElement
    const hasText = (e.textContent ?? '').trim().length > 0
    if (!hasText && !e.getAttribute('aria-label') && !e.getAttribute('title')) {
      bad.push(`${w}: <${e.tagName.toLowerCase()} class="${e.className}">`)
    }
  })
  return bad
}, where)

async function auditScreen(page: Page, where: string) {
  const problems = [
    ...await unnamedFields(page, where),
    ...await imagesWithoutAlt(page, where),
    ...await unnamedButtons(page, where),
  ]
  expect(problems, `${where}: усе інтерактивне мусить мати доступну назву`).toEqual([])
}

test('усі поля, кнопки та зображення мають доступні назви', async ({ page }) => {
  await setup(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await auditScreen(page, 'db-list')

  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible()
  await auditScreen(page, 'profile')

  await page.locator('.tabbar [aria-label="Бази"]').click()
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await auditScreen(page, 'db-objects')

  await page.locator('.obj-act-btn', { hasText: 'Редагувати' }).first().click()
  await expect(page.getByText('Редагування')).toBeVisible()
  await auditScreen(page, 'property-form')
})

test('поля модалок теж названі (оренда, папки)', async ({ page }) => {
  await setup(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })

  // Модалка оренди
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Здати/ })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Здати/ }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await auditScreen(page, 'rent-modal')
  // Дати мусять бути розрізненні на слух
  await expect(page.getByLabel('Договір від')).toBeVisible()
  await expect(page.getByLabel('Договір до')).toBeVisible()
  // Ставка озвучується назвою, а не значенням плейсхолдера
  await expect(page.getByLabel(/Орендна ставка/)).toBeVisible()

  // Модалка папок — назва тесту обіцяла її й до цього, але крок був утрачений
  // під час фази 2 переробки модалок (звідки в назві лишився й «розклад
  // платежів», що вже не модалка). Порожній підпис = поле без імені.
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText(/Групуйте об.єкти бази/)).toBeVisible({ timeout: 15_000 })
  await auditScreen(page, 'folder-manage')
})

/**
 * Повноекранні маршрути, що замінили шити у фазах 2-3 переробки модалок. Їхні
 * поля не перевіряв ніхто: обхід вище знає чотири екрани, а модальний тест
 * після переносу дійшов лише до оренди.
 */
test('поля повноекранних форм названі (розклад, платіж, запрошення)', async ({ page }) => {
  await setup(page)

  // Розклад платежів
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Календар платежів', { exact: true }).click()
  await expect(page.getByText(/Календар платежів|Платежі —/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible({ timeout: 15_000 })
  await auditScreen(page, 'payment-schedule')
  await expect(page.getByLabel('День місяця')).toBeVisible()
  await expect(page.getByLabel('Нагадати за, днів')).toBeVisible()

  // Підтвердження платежу — досяжне лише коли розклад уже є.
  await page.route('**/rest/v1/rent_payments**', (r) => {
    const row = {
      id: '60000000-0000-0000-0000-000000000001', property_id: PROP.id,
      owner_id: USER.id, due_day: 5, notify_days_before: 3, is_active: true,
      created_at: NOW, updated_at: NOW,
    }
    return jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? row : [row])
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Календар платежів', { exact: true }).click()
  await expect(page.getByText(/Календар платежів|Платежі —/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Отримано/ }).first().click()
  await expect(page.getByText('Підтвердити платіж')).toBeVisible({ timeout: 15_000 })
  await auditScreen(page, 'payment-confirm')
  await expect(page.getByLabel('Сума отриманого платежу')).toBeVisible()
  await expect(page.getByLabel('Нотатка до платежу')).toBeVisible()

  // Запрошення гостя — підпис поля мусить називати СУТНІСТЬ (гість чи член
  // команди), бо для читалки це різні речі.
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Управління гостями', { exact: true }).click()
  await expect(page.getByText(/Гості|Запросити/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Запросити гостя').click()
  await expect(page.getByText('Запросити гостя')).toBeVisible({ timeout: 15_000 })
  await auditScreen(page, 'create-invite')
  await expect(page.getByLabel('Підпис гостьового лінка')).toBeVisible()
})
