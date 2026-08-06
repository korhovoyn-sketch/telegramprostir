import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Видалення акаунта — незворотна дія. Перевіряємо і що вона працює,
// і що ВИПАДКОВО її не запустити (гард підтвердження).

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const NOW = new Date().toISOString()
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'a', type: 'business_center',
  color: 'pink', share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

async function setup(page: Page, calls: { rpc: number; photoRemove: number; fileRemove: number }) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, [{ id: PROP_ID }]))
  await page.route('**/rest/v1/property_photos**', (r) => jsonRoute(r, [{ storage_path: `${PROP_ID}/1_a.jpg` }]))
  await page.route('**/rest/v1/property_files**', (r) => jsonRoute(r, [{ storage_path: `${PROP_ID}/2_b.pdf` }]))
  for (const t of ['property_folders', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  // storage removals
  await page.route('**/storage/v1/object/photos**', (r) => { calls.photoRemove++; return jsonRoute(r, []) })
  await page.route('**/storage/v1/object/property-files**', (r) => { calls.fileRemove++; return jsonRoute(r, []) })
  // the deletion RPC
  await page.route('**/rest/v1/rpc/delete_my_account', (r) => {
    calls.rpc++
    return jsonRoute(r, [{ deleted: true, error: null }])
  })
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function openDeleteModal(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible()
  await page.locator('.del-acc').click()
  await expect(page.getByText('Видалити акаунт?')).toBeVisible()
}

test('видалення акаунта: кнопка заблокована, доки не вписано підтвердження', async ({ page }) => {
  const calls = { rpc: 0, photoRemove: 0, fileRemove: 0 }
  await setup(page, calls)
  await openDeleteModal(page)

  const confirmBtn = page.getByRole('button', { name: 'Видалити назавжди' })
  await expect(confirmBtn).toBeDisabled()

  // Частково/неправильно вписане слово теж не розблоковує
  await page.getByLabel('Підтвердження видалення').fill('ВИДАЛ')
  await expect(confirmBtn).toBeDisabled()

  await page.getByLabel('Підтвердження видалення').fill('ВИДАЛИТИ')
  await expect(confirmBtn).toBeEnabled()

  // Нічого не викликано, поки не натиснуто
  expect(calls.rpc).toBe(0)
})

test('видалення акаунта: чистить сховище, кличе RPC і викидає на welcome', async ({ page }) => {
  const calls = { rpc: 0, photoRemove: 0, fileRemove: 0 }
  await setup(page, calls)
  await openDeleteModal(page)

  await page.getByLabel('Підтвердження видалення').fill('ВИДАЛИТИ')
  await page.getByRole('button', { name: 'Видалити назавжди' }).click()

  await expect.poll(() => calls.rpc, { timeout: 10_000 }).toBe(1)
  // Файли прибрано ДО видалення рядків (інакше шляхи були б втрачені)
  expect(calls.photoRemove, 'фото видалено зі сховища').toBeGreaterThan(0)
  expect(calls.fileRemove, 'документи видалено зі сховища').toBeGreaterThan(0)

  await expect(page.getByText('Акаунт видалено')).toBeVisible({ timeout: 10_000 })
  // Виходимо на welcome, локальна сесія знята
  await expect(page.getByText(/Увійти|Ласкаво просимо|prostir/).first()).toBeVisible({ timeout: 10_000 })
  const cached = await page.evaluate(() => localStorage.getItem('ps_user'))
  expect(cached, 'кеш профілю очищено').toBeNull()
})

test('видалення акаунта: помилка сервера НЕ виходить із акаунта', async ({ page }) => {
  const calls = { rpc: 0, photoRemove: 0, fileRemove: 0 }
  await setup(page, calls)
  // сервер відмовляє
  await page.route('**/rest/v1/rpc/delete_my_account', (r) => {
    calls.rpc++
    return jsonRoute(r, [{ deleted: false, error: 'not_authenticated' }])
  })
  await openDeleteModal(page)

  await page.getByLabel('Підтвердження видалення').fill('ВИДАЛИТИ')
  await page.getByRole('button', { name: 'Видалити назавжди' }).click()

  await expect(page.getByText('Не вдалося видалити акаунт')).toBeVisible({ timeout: 10_000 })
  // Лишаємось у профілі — не викидає на welcome при збої
  await expect(page.getByText('Налаштування')).toBeVisible()
})
