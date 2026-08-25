import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, objectAction } from './helpers/harness'

/**
 * Обхід ВСІХ екранів так, як їх бачить реальний Telegram: з нативною нижньою
 * смугою (MainButton + SecondaryButton) і нативними попапами.
 *
 * НАВІЩО окремий прохід. Решта спеків ганяє слабший клієнт — стаб без цих API,
 * тобто DOM-фолбеки. Прод же працює саме з ними, і одного невалідного параметра
 * смуги досить, щоб екран пішов у ErrorBoundary: так `text: ' '` для схованої
 * другорядної кнопки завалив створення об'єкта, і жоден із 150 тестів цього не
 * бачив. Тут перевіряється, що ЖОДЕН екран не падає на нативному клієнті і що
 * кнопка не «протікає» на наступний екран.
 */

const NOW = new Date().toISOString()
const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.' }
const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Ірина' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const FOLDER_ID = '50000000-0000-0000-0000-000000000001'

const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

function prop(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, area_basis: 'total', rent_type: 'per_m2', rent_rate: 20, utilities_rate: 2,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: 'Світлий офіс.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01', folder_id: FOLDER_ID }),
  prop(2, { status: 'free' }),
]

/** Нативний клієнт: смуга + попапи вмикаються ДО першого скрипта застосунку. */
async function enableNative(page: Page, popupAnswer: string | null = 'cancel') {
  await page.addInitScript((answer) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const w = window as any
    w.__tgEnableMainButton?.(true)
    w.__tgEnablePopups?.(answer)
  }, popupAnswer)
}

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/property_folders**', (r) => json(r, [
    { id: FOLDER_ID, db_id: DB_ID, owner_id: OWNER.id, name: 'Орендарі', sort_order: 1, created_at: NOW, updated_at: NOW },
  ]))
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
    db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
    guest_user_id: null, status: 'active', claimed_at: NOW, created_at: NOW,
  }]))
  await page.route('**/rest/v1/db_members**', (r) => {
    if (r.request().url().includes('user_id=eq.')) return json(r, [])
    return json(r, [{
      id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID, user_id: '00000000-0000-0000-0000-000000000077',
      role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер',
      member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/rpc/manage_share', (r) => json(r, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))
  for (const t of ['property_views', 'property_files', 'property_photos', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  // PaymentScheduleScreen/PaymentConfirmScreen читають ці таблиці через
  // `.maybeSingle()` — Accept вирішує форму відповіді. Масив там, де чекають
  // обʼєкт, дає помилку PostgREST, і екран малює RetryState замість форми.
  for (const t of ['rent_payments', 'rent_payment_records']) {
    await page.route(`**/rest/v1/${t}**`, (r) =>
      json(r, (r.request().headers()['accept'] ?? '').includes('object') ? null : []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Екран живий: ErrorBoundary не спрацював. */
async function alive(page: Page, where: string) {
  await expect(page.getByText('Щось пішло не так'), `${where}: екран у ErrorBoundary`).toHaveCount(0)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bar = (page: Page) => page.evaluate(() => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  main: (window as any).__tgMain as { text: string; isVisible: boolean; isActive?: boolean },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sec: (window as any).__tgSecondary as { text: string; isVisible: boolean },
}))

async function toObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
}

test('нативний клієнт: усі екрани власника живі, смуга не протікає', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await enableNative(page)
  await ownerRoutes(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await alive(page, 'db-list')
  const cta = page.locator('button.mbtn')
  // Нативну нижню смугу Telegram прибрано з усього застосунку (власник не
  // хотів тулбара) — первинна дія тепер наша власна пігулка .mbtn. Смуга
  // мусить лишатись невидимою СКРІЗЬ, інакше ми знову її десь вмикаємо.
  expect((await bar(page)).main.isVisible, 'нативна смуга більше не вживається').toBe(false)
  await expect(cta, 'db-list: первинна дія — FAB, не CTA форми').toHaveCount(0)

  // ── Створення бази
  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible()
  await alive(page, 'create-db')
  await expect(cta).toHaveText('Створити базу')
  await expect(cta, 'без назви кнопка неактивна').toBeDisabled()
  expect((await bar(page)).main.isVisible, 'нативна смуга не вмикається').toBe(false)

  // ── Об'єкти бази
  await toObjects(page)
  await alive(page, 'db-objects')
  await expect(cta, 'CTA форми не протекла на список').toHaveCount(0)

  // ── Створення об'єкта (той самий екран, що падав у проді)
  await page.locator('.fbtn').click()
  await expect(page.getByText('Новий об\'єкт')).toBeVisible({ timeout: 15_000 })
  await alive(page, 'property-form-create')
  await expect(cta).toHaveText('Додати об\'єкт')
  await expect(cta).toBeDisabled()
  await page.getByLabel('Назва обʼєкта').fill('Офіс 202')
  await expect(cta, 'назва введена — кнопка активна').toBeEnabled()
  await alive(page, 'property-form-create+input')

  // ── Редагування об'єкта: збереження + видалення в хедері
  await toObjects(page)
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()
  await alive(page, 'property-form-edit')
  await expect(cta).toHaveText('Зберегти зміни')
  // Пари на нативній смузі більше немає, тож видалення мусить бути досяжним —
  // інакше незворотна дія просто зникла б з екрана.
  await expect(page.getByRole('button', { name: "Видалити об'єкт" })).toBeVisible()

  // Вихід із форми мусить прибрати CTA.
  await toObjects(page)
  await expect(cta, 'CTA прибрано на unmount').toHaveCount(0)
  expect((await bar(page)).main.isVisible, 'нативна смуга лишається вимкненою').toBe(false)

  // ── Детальна картка + нативне підтвердження звільнення
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
  await alive(page, 'property-detail')

  // ── Екрани з меню бази
  const menuScreens: [string, RegExp][] = [
    ['Аналітика і поширення', /Аналітика|Поділитись/],
    ['Календар платежів', /Календар платежів|Прострочено|Платежі/],
    ['Управління гостями', /Гості|Запросити/],
    ['Команда', /Команда|Запросити/],
    ['Експорт', /Формат файлу|Завантажити/],
  ]
  for (const [item, marker] of menuScreens) {
    await toObjects(page)
    await page.getByLabel('Меню бази').click()
    await page.getByText(item, { exact: true }).click()
    await expect(page.getByText(marker).first()).toBeVisible({ timeout: 15_000 })
    await alive(page, `menu:${item}`)
    expect((await bar(page)).main.isVisible, `menu:${item} — чужа кнопка на екрані`).toBe(false)
  }

  // ── Повноекранні маршрути, що замінили шити (фази 2-3 переробки модалок).
  // Кожен несе власну первинну дію, тож правило «новий екран із CTA = новий
  // крок тут» стосується їх напряму: саме такий екран колись і падав, не
  // помічений жодним із 150 тестів.
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів', { exact: true }).click()
  await expect(page.getByText(/Календар платежів|Платежі —/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByText('Налаштувати розклад')).toBeVisible({ timeout: 15_000 })
  await alive(page, 'payment-schedule')
  await expect(cta).toHaveText('Зберегти')
  expect((await bar(page)).main.isVisible, 'payment-schedule — нативна смуга вимкнена').toBe(false)

  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Управління гостями', { exact: true }).click()
  await expect(page.getByText(/Гості|Запросити/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Запросити гостя').click()
  await expect(page.getByText('Запросити гостя')).toBeVisible({ timeout: 15_000 })
  await alive(page, 'create-invite')
  await expect(cta).toHaveText('Створити')
  expect((await bar(page)).main.isVisible, 'create-invite — нативна смуга вимкнена').toBe(false)

  // Вихід мусить прибрати CTA — вона не «протікає» на наступний екран.
  await toObjects(page)
  await expect(cta, 'CTA прибрано після виходу з create-invite').toHaveCount(0)

  // ── Папки, режим вибору, пакетні пікери
  // Керування папками і обидва пікери — ПОВНОЕКРАННІ маршрути (фаза 4), тож
  // у кожного своя первинна дія, і кожна мусить бути перевірена тут: саме
  // цей прохід закриває прогалину, через яку падіння форми створення колись
  // не побачив жоден тест.
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText(/Групуйте об.єкти бази/)).toBeVisible({ timeout: 15_000 })
  await alive(page, 'folder-manage')
  await expect(cta).toHaveText('Додати папку')
  expect((await bar(page)).main.isVisible, 'folder-manage — нативна смуга вимкнена').toBe(false)

  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Виділити об\'єкти', { exact: true }).click()
  await page.locator('.obj-card').first().click()
  await expect(page.locator('.batchbar')).toBeVisible()
  await alive(page, 'select-mode')

  await page.getByRole('button', { name: /У папку/ }).click()
  await expect(page.getByText('Оберіть папку або створіть нову')).toBeVisible({ timeout: 15_000 })
  await alive(page, 'folder-picker')
  await expect(cta).toHaveText('Створити й перемістити')
  expect((await bar(page)).main.isVisible, 'folder-picker — нативна смуга вимкнена').toBe(false)

  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Виділити об\'єкти', { exact: true }).click()
  await page.locator('.obj-card').first().click()
  await page.getByRole('button', { name: /В базу/ }).click()
  await expect(page.getByText(/буде переміщено/)).toBeVisible({ timeout: 15_000 })
  await alive(page, 'db-picker')
  await expect(cta).toHaveText('Створити й перенести')
  expect((await bar(page)).main.isVisible, 'db-picker — нативна смуга вимкнена').toBe(false)

  // ── Режим порядку
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Змінити порядок', { exact: true }).click()
  await expect(page.getByText(/Готово|порядок/i).first()).toBeVisible({ timeout: 15_000 })
  await alive(page, 'reorder-mode')

  // ── Редагування бази: ще один екран із плаваючою CTA
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Редагувати базу', { exact: true }).click()
  await expect(page.locator('.hdr-t', { hasText: 'Редагувати базу' })).toBeVisible({ timeout: 15_000 })
  await alive(page, 'edit-db')
  await expect(cta).toHaveText('Зберегти зміни')
  expect((await bar(page)).main.isVisible, 'нативна смуга не вмикається').toBe(false)

  // ── Таби
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  for (const tab of ['Сповіщення', 'Профіль']) {
    await page.locator(`.tabbar [aria-label="${tab}"]`).click()
    await page.waitForTimeout(400)
    await alive(page, `tab:${tab}`)
    expect((await bar(page)).main.isVisible, `tab:${tab} — чужа кнопка`).toBe(false)
  }
})

test('нативний клієнт: екрани рієлтора і підбірки живі', async ({ page }) => {
  test.setTimeout(120_000)
  await setupApp(page, { user: REALTOR })
  await enableNative(page)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [
    { id: '60000000-0000-0000-0000-000000000001', realtor_id: REALTOR.id, db_id: DB_ID, created_at: NOW, database: DB },
  ]))
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPERTIES[0] : PROPERTIES))
  await page.route('**/rest/v1/collections**', (r) => json(r, [
    { id: '70000000-0000-0000-0000-000000000001', realtor_id: REALTOR.id, name: 'Для клієнта А', is_draft: false, share_token: 'ff00112233445566778899aa', share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [] },
  ]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? REALTOR : [REALTOR]))
  for (const t of ['collection_properties', 'property_photos', 'property_views', 'notifications', 'property_files', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await alive(page, 'realtor-dashboard')

  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
  await alive(page, 'realtor-database')
  expect((await bar(page)).main.isVisible, 'на базі рієлтора нативної кнопки нема').toBe(false)

  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await expect(page.getByText(/Підбірки|Немає підбірок/).first()).toBeVisible({ timeout: 15_000 })
  await alive(page, 'collections')
})
