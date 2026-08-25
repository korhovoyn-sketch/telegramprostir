import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks, objectAction } from './helpers/harness'

// Гайдлайни Telegram: незворотні дії підтверджує НАТИВНИЙ попап — він несе
// авторитет платформи. У клієнтів без `showPopup` (браузер, старий клієнт)
// мусить лишатись власна модалка з ТИМ САМИМ текстом, інакше на різних
// платформах користувач читає різні попередження.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'free', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}

async function setup(page: Page): Promise<{ deletes: string[] }> {
  const deletes: string[] = []
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    if (r.request().method() === 'DELETE') {
      deletes.push(r.request().url())
      // Успішний DELETE повертає видалений рядок — клієнт тепер доводить, що
      // видалення справді сталось (порожньо = заблоковано RLS, lib/dbWrite.ts).
      return jsonRoute(r, [{ id: PROP.id }])
    }
    return jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP])
  })
  await page.route('**/rest/v1/users**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  return { deletes }
}

/** Відкриває форму редагування об'єкта. */
async function openEditForm(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()
}

test('видалення об\'єкта підтверджується нативним попапом Telegram', async ({ page }) => {
  const { deletes } = await setup(page)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.addInitScript(() => { (window as any).__tgEnablePopups?.('ok') })
  await openEditForm(page)

  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const popups = await page.evaluate(() => (window as any).__tgPopups)
  expect(popups).toHaveLength(1)
  expect(popups[0].title).toBe('Видалити об\'єкт?')
  expect(popups[0].message).toContain('Офіс 101')
  expect(popups[0].buttons[0]).toMatchObject({ id: 'ok', type: 'destructive', text: 'Видалити' })
  expect(popups[0].buttons[1]).toMatchObject({ id: 'cancel' })

  // Своя модалка НЕ показується — інакше було б два діалоги поверх одного.
  await expect(page.locator('.modal')).toHaveCount(0)
  await expect.poll(() => deletes.length, { timeout: 10_000 }).toBe(1)
  expect(deletes[0]).toContain(PROP_ID)
})

test('видалення об\'єкта: Back після видалення НЕ повертає на мертву форму редагування', async ({ page }) => {
  const { deletes } = await setup(page)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.addInitScript(() => { (window as any).__tgEnablePopups?.('ok') })
  await openEditForm(page)

  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()
  await expect.poll(() => deletes.length, { timeout: 10_000 }).toBe(1)

  // Приземлились на список об'єктів бази (єдиний живий екран після видалення).
  await expect(page.getByText('Всі (1)')).toBeVisible()

  // deleteProperty мусить popати з history і форму, і деталі видаленого
  // об'єкта (backThenReplace), а не лишати їх там (navigate) — інакше ОДИН
  // тап «Назад» повертає на форму редагування об'єкта, якого вже нема.
  await page.locator('.hdr-back').click()
  await expect(page.getByText('Мої бази')).toBeVisible()
  await expect(page.getByText('Редагування')).toHaveCount(0)
})

test('закриття нативного попапу свайпом = відмова, нічого не видаляється', async ({ page }) => {
  const { deletes } = await setup(page)
  // Telegram віддає null, коли попап закрили без вибору кнопки.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.addInitScript(() => { (window as any).__tgEnablePopups?.(null) })
  await openEditForm(page)

  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await expect.poll(() => page.evaluate(() => (window as any).__tgPopups.length)).toBe(1)

  await expect(page.getByText('Редагування')).toBeVisible()
  expect(deletes).toEqual([])
})

test('без showPopup лишається фолбек-модалка з тим самим текстом', async ({ page }) => {
  const { deletes } = await setup(page)
  await openEditForm(page)

  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await expect(page.getByText('Видалити об\'єкт?', { exact: true })).toBeVisible()
  await expect(page.getByText(/Об'єкт "Офіс 101" буде видалено/)).toBeVisible()

  await page.locator('.modal').getByRole('button', { name: 'Скасувати' }).click()
  await expect(page.locator('.modal')).toHaveCount(0)
  expect(deletes).toEqual([])

  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()
  await page.locator('.modal').getByRole('button', { name: 'Видалити' }).click()
  await expect.poll(() => deletes.length, { timeout: 10_000 }).toBe(1)
})

test('редагування: видалення живе в хедері — єдиний шлях, і він працює', async ({ page }) => {
  const { deletes } = await setup(page)
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const w = window as any
    // Нативну смугу вмикаємо СВІДОМО: навіть коли Telegram її пропонує, ми нею
    // більше не користуємось — тулбар прибрано з застосунку.
    w.__tgEnableMainButton?.(true)
    w.__tgEnablePopups?.('ok')
  })
  await openEditForm(page)

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const bar = await page.evaluate(() => ({ main: (window as any).__tgMain, sec: (window as any).__tgSecondary }))
  expect(bar.main.isVisible, 'нативна смуга не вмикається').toBe(false)
  expect(bar.sec.isVisible, 'нативної пари теж немає').toBe(false)

  // Первинна дія — наша власна пігулка…
  await expect(page.locator('button.mbtn')).toHaveText('Зберегти зміни')
  // …а незворотне видалення мусить лишатись досяжним, інакше воно просто
  // зникло б разом із нативною парою.
  await page.getByRole('button', { name: 'Видалити об\'єкт' }).click()
  await expect.poll(() => deletes.length, { timeout: 10_000 }).toBe(1)
})

test('форма СТВОРЕННЯ жива на нативному клієнті і керується власною CTA', async ({ page }) => {
  await setup(page)
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).__tgEnableMainButton?.(true)
  })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })

  await page.locator('.fbtn').click()
  await expect(page.getByText('Новий об\'єкт')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Щось пішло не так')).toHaveCount(0)

  const cta = page.locator('button.mbtn')
  await expect(cta).toHaveText('Додати об\'єкт')
  await expect(cta, 'без назви — неактивна').toBeDisabled()
  await page.getByLabel('Назва обʼєкта').fill('Офіс 202')
  await expect(cta, 'назва введена — активна').toBeEnabled()
})

test('вихід з акаунту — теж нативний попап, а не рукописна копія модалки', async ({ page }) => {
  // Вихід був ЄДИНОЮ незворотною дією поза `confirmAction()`: ProfileScreen тримав
  // власний <Modal> із тим самим змістом. Тобто на нативному клієнті користувач
  // бачив скляну модалку там, де всі інші 13 місць питають попапом Telegram.
  await setup(page)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.addInitScript(() => { (window as any).__tgEnablePopups?.('cancel') })
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })

  await page.getByRole('button', { name: /Вийти з акаунту/ }).click()

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const popups = await page.evaluate(() => (window as any).__tgPopups)
  expect(popups).toHaveLength(1)
  expect(popups[0].title).toBe('Вийти з акаунту?')
  expect(popups[0].buttons[0]).toMatchObject({ id: 'ok', type: 'destructive', text: 'Вийти' })
  // Відповідь 'cancel' — з акаунта не викинуло.
  await expect(page.locator('.modal')).toHaveCount(0)
  await expect(page.getByText('Налаштування')).toBeVisible()
})
