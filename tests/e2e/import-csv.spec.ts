import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * ІМПОРТ ІЗ CSV — зворотний бік експорту, якого не було.
 *
 * Найважливіше тут не «файл прочитався», а що САМЕ доїхало в INSERT: імпорт
 * створює десятки рядків одним махом, тож помилка зіставлення колонок — це не
 * одне зіпсоване поле, а вся база.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const EXISTING = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 101', floor: '1', status: 'free', area_useful: 45, area_total: 52,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, landlord_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 100, share_token: 'bb00000000000000000001', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

interface Wire { inserts: Record<string, unknown>[][] }

async function openImport(page: Page, wire: Wire) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '[]')
      wire.inserts.push(Array.isArray(body) ? body : [body])
      return jsonRoute(r, Array.isArray(body) ? body : [body])
    }
    return jsonRoute(r, [EXISTING])
  })
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Імпорт із CSV', { exact: true }).click()
  await expect(page.getByText('Обрати файл')).toBeVisible({ timeout: 15_000 })
}

async function upload(page: Page, name: string, content: string) {
  await page.locator('input[type="file"]').setInputFiles({
    name, mimeType: 'text/csv', buffer: Buffer.from(content, 'utf-8'),
  })
}

test('колонки зіставляються самі, і в INSERT їде саме те, що в файлі', async ({ page }) => {
  const wire: Wire = { inserts: [] }
  await openImport(page, wire)

  await upload(page, 'obj.csv',
    'Назва,Поверх,Статус,Орендар,Площа корисна (м²),Ставка оренди\n' +
    'Офіс 201,2,Зайнято,ТОВ «Ромашка»,45.5,18\n' +
    'Офіс 202,3,Вільно,,60,20\n')

  await expect(page.getByText('2 обʼєкти')).toBeVisible({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Імпортувати' }).click()
  await expect.poll(() => wire.inserts.length, { timeout: 15_000 }).toBe(1)

  const rows = wire.inserts[0]
  expect(rows).toHaveLength(2)
  expect(rows[0].name).toBe('Офіс 201')
  expect(rows[0].floor).toBe('2')
  expect(rows[0].status).toBe('occupied')
  expect(rows[0].tenant_name).toBe('ТОВ «Ромашка»')
  expect(rows[0].area_useful).toBe(45.5)
  expect(rows[0].rent_rate).toBe(18)
  expect(rows[1].status).toBe('free')
  // sort_order мусить бути ЗРОСТАЮЧИЙ і не збігатись: інакше порядок у списку
  // визначався б випадково, а ручне «Змінити порядок» не мало б за що взятись.
  expect(Number(rows[1].sort_order)).toBeGreaterThan(Number(rows[0].sort_order))
})

/**
 * Орендар на ВІЛЬНОМУ обʼєкті — суміш, яка вже одного разу їхала в експорт і на
 * публічну /v. Імпорт не має бути другим шляхом її створити.
 */
test('орендар не пишеться вільному обʼєкту', async ({ page }) => {
  const wire: Wire = { inserts: [] }
  await openImport(page, wire)
  await upload(page, 'obj.csv', 'Назва,Статус,Орендар\nОфіс 301,Вільно,ТОВ «Зайве»\n')

  await expect(page.getByText('1 обʼєкт', { exact: false })).toBeVisible({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Імпортувати' }).click()
  await expect.poll(() => wire.inserts.length, { timeout: 15_000 }).toBe(1)
  expect(wire.inserts[0][0].tenant_name).toBeNull()
})

/**
 * Назва, що вже є в базі, ПРОПУСКАЄТЬСЯ. Мовчазне затирання наявного обʼєкта —
 * найдорожча з можливих інтерпретацій «імпортувати», і користувач мусить
 * бачити ПОІМЕННО, що не заїхало.
 */
test('наявні назви пропускаються і названі поіменно', async ({ page }) => {
  const wire: Wire = { inserts: [] }
  await openImport(page, wire)
  await upload(page, 'obj.csv', 'Назва,Поверх\nОфіс 101,9\nОфіс 202,3\n')

  await expect(page.getByText('1 обʼєкт', { exact: false })).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText(/Пропущено.*Офіс 101/)).toBeVisible()

  await page.getByRole('button', { name: 'Імпортувати' }).click()
  await expect.poll(() => wire.inserts.length, { timeout: 15_000 }).toBe(1)
  expect(wire.inserts[0]).toHaveLength(1)
  expect(wire.inserts[0][0].name).toBe('Офіс 202')
})

/** Українська локаль Excel зберігає з `;` — без автовизначення це один стовпець. */
test('крапка з комою читається як роздільник', async ({ page }) => {
  const wire: Wire = { inserts: [] }
  await openImport(page, wire)
  await upload(page, 'excel.csv', 'Назва;Поверх;Площа корисна (м²)\nОфіс 401;5;33\n')

  await expect(page.getByText('1 обʼєкт', { exact: false })).toBeVisible({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Імпортувати' }).click()
  await expect.poll(() => wire.inserts.length, { timeout: 15_000 }).toBe(1)
  expect(wire.inserts[0][0].name).toBe('Офіс 401')
  expect(wire.inserts[0][0].area_useful).toBe(33)
})

/** Без колонки назви імпортувати нічого — кнопка мусить бути мертвою. */
test('без колонки «Назва» імпорт заблокований', async ({ page }) => {
  const wire: Wire = { inserts: [] }
  await openImport(page, wire)
  await upload(page, 'obj.csv', 'Поверх,Площа корисна (м²)\n2,45\n')

  await expect(page.getByText('Вкажіть, яка колонка містить назву')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByRole('button', { name: 'Імпортувати' })).toBeDisabled()
  expect(wire.inserts).toHaveLength(0)
})
