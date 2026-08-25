import { expect, type Page, type Route } from '@playwright/test'
import { setupApp, seedSession, DEFAULT_USER, type HarnessUser } from './harness'

/**
 * ЄДИНИЙ обхід усіх досяжних екранів — для гардів, які міряють РЕНДЕР.
 *
 * `contrast.spec.ts` і `design-system-runtime.spec.ts` мали власні, майже
 * однакові маршрути з чотирьох екранів: `db-list → db-objects →
 * property-detail → profile`. Тобто **24 екрани з 28** не перевірялись ані на
 * WCAG AA, ані на радіус/шкалу шрифту — і закрити цю прогалину скріншотами
 * НЕМОЖЛИВО принципово: кадр ловить ЗМІНУ проти бейслайна, а дефект, який був
 * там від початку, бейслайн благословляє. Текст, що завжди був нижче AA, і
 * радіус, що завжди був поза шкалою, для нього — норма.
 *
 * Кроки СВІДОМО самодостатні: кожен починається з `page.goto('/')` і сам
 * доходить до свого екрана. Це коштує зайвий перезавантаж, але без цього
 * `contrast` тут узагалі не працює — його замір робить текст прозорим
 * НЕОБОРОТНО, тож наступний екран мусить малюватись із чистого старту.
 * Заодно крок, що впав, не забирає з собою решту черги.
 */

export interface ScreenStep {
  /** Ключ у `FROZEN`/бейслайнах — стабільний, не змінювати без причини. */
  label: string
  go: (page: Page) => Promise<void>
}

const NOW = '2025-09-01T09:00:00.000Z'
const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

export const OWNER: HarnessUser = {
  ...DEFAULT_USER, role: 'owner', first_name: 'Микола', last_name: 'К.',
}
const DB_ID = '10000000-0000-0000-0000-000000000001'
const OTHER_OWNER = '00000000-0000-0000-0000-000000000099'

const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}

function prop(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: OWNER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: ['electricity', 'water'],
    description: 'Світлий офіс у центрі міста.', address: 'вул. Хрещатик, 1',
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}${n}`,
    share_expires_at: null, created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
    ...over,
  }
}

const PROPERTIES = [
  prop(1, {
    status: 'occupied', tenant_name: 'Фоп Плотко', rent_rate: 12.8,
    area_useful: 175.8, area_total: 195.13,
    lease_start_date: '2025-08-15', lease_end_date: '2026-08-31',
  }),
  prop(2),
  prop(3, { status: 'for_sale', sale_price: 250_000 }),
]

const FOLDERS = [{
  id: '40000000-0000-0000-0000-0000000000a1', db_id: DB_ID, owner_id: OWNER.id,
  name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW,
}]

/** Порожні таблиці, які тягне майже кожен екран. */
async function emptyTables(page: Page, names: string[]) {
  for (const t of names) await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
}

// ── Власник ───────────────────────────────────────────────────────────────────

export async function ownerFixtures(page: Page) {
  await setupApp(page, { user: OWNER })
  await seedSession(page, OWNER as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find((p) => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? OWNER : [OWNER]))
  await page.route('**/rest/v1/property_folders**', (r) => json(r, FOLDERS))
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
    db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
    guest_user_id: null, status: 'pending', claimed_at: null, created_at: NOW,
  }]))
  await page.route('**/rest/v1/db_members**', (r) => {
    // Перший запит `useDatabases` іде по user_id — це ВЛАСНІ членства, не члени бази.
    if (r.request().url().includes('user_id=eq.')) return json(r, [])
    return json(r, [{
      id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID,
      user_id: '00000000-0000-0000-0000-000000000077', role: 'editor',
      invite_token: 'dd00112233445566778899', label: 'Менеджер',
      member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/rpc/manage_share', (r) =>
    json(r, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))
  await emptyTables(page, ['property_files', 'property_photos', 'rent_payments',
    'rent_payment_records', 'property_views', 'notifications', 'collections'])
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Список баз — точка входу власника, з якої стартує кожен крок. */
async function atDbList(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
}

/**
 * Обʼєкти бази — у вигляді КАРТОК.
 *
 * Нормалізація виду тут обовʼязкова, і це не перестраховка: перемикач
 * «Картки/Компактно» зберігається в localStorage per user+db, тобто крок
 * `db-objects-compact` міняє стан для ВСІХ наступних кроків. Без цього
 * `property-detail` шукав `.obj-card`, якого вже не було, і чекав до самого
 * таймауту тесту.
 */
async function atDbObjects(page: Page) {
  await atDbList(page)
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible({ timeout: 15_000 })
  if (await page.locator('.obj-card').count() === 0) {
    await page.getByLabel('Картки').click()
    await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 10_000 })
  }
}

/** Пункт меню бази — усі owner-екрани другого рівня відкриваються звідти. */
async function viaDbMenu(page: Page, item: string, done: RegExp | string) {
  await atDbObjects(page)
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  // Шит виїжджає з-під низу (~320мс): тап по пункту під час руху промахується.
  await page.waitForTimeout(420)
  await page.getByText(item, { exact: true }).click()
  await expect(typeof done === 'string' ? page.getByText(done).first() : page.getByText(done).first())
    .toBeVisible({ timeout: 15_000 })
}

/** Пакетна дія — вхід у режим виділення й тап по пілюлі панелі обраних. */
async function viaBatch(page: Page, pill: string, done: RegExp) {
  await atDbObjects(page)
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText("Виділити об'єкти", { exact: true }).click()
  await page.waitForTimeout(400)
  await page.locator('.obj-card, .row').first().click()
  await page.getByRole('button', { name: new RegExp(pill) }).click()
  await expect(page.getByText(done).first()).toBeVisible({ timeout: 15_000 })
}

export const OWNER_SCREENS: ScreenStep[] = [
  { label: 'db-list', go: atDbList },
  { label: 'db-objects', go: atDbObjects },
  {
    label: 'db-objects-compact',
    go: async (page) => {
      await atDbObjects(page)
      await page.getByLabel('Компактно').click()
      await expect(page.locator('.row').first()).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'property-detail',
    go: async (page) => {
      await atDbObjects(page)
      await page.locator('.obj-card').first().locator('.obj-t').click()
      await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'property-form-new',
    go: async (page) => {
      await atDbObjects(page)
      await page.getByLabel("Додати об'єкт").click()
      await expect(page.getByText("Новий об'єкт")).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'create-db',
    go: async (page) => {
      await atDbList(page)
      await page.getByLabel('Створити базу').click()
      await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'sharing-analytics',
    go: (page) => viaDbMenu(page, 'Аналітика і поширення', /Аналітика|Поділитись/),
  },
  {
    label: 'payment-calendar',
    go: (page) => viaDbMenu(page, 'Календар платежів', /Календар платежів|Платежі —/),
  },
  {
    // Повноекранний маршрут із фази 2 переробки модалок. Без розкладу в
    // фікстурах календар малює блок «Немає розкладу» з кнопкою «Налаштувати».
    label: 'payment-schedule',
    go: async (page) => {
      await viaDbMenu(page, 'Календар платежів', /Календар платежів|Платежі —/)
      await page.getByRole('button', { name: /Налаштувати/ }).first().click()
      await expect(page.getByText('Налаштувати розклад')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    // Той самий маршрут, але екран підтвердження платежу — а він досяжний
    // ЛИШЕ коли розклад уже є, інакше в календарі немає жодного платіжного
    // рядка. Тому крок підміняє `rent_payments` ЛОКАЛЬНО: спільні фікстури
    // лишаються порожніми, щоб `payment-calendar` вище міряв свій звичайний
    // стан (Playwright бере обробник, зареєстрований ОСТАННІМ).
    label: 'payment-confirm',
    go: async (page) => {
      await page.route('**/rest/v1/rent_payments**', (r) => {
        const row = {
          id: '60000000-0000-0000-0000-000000000001',
          property_id: PROPERTIES[0].id, owner_id: OWNER.id,
          due_day: 5, notify_days_before: 3, is_active: true,
          created_at: NOW, updated_at: NOW,
        }
        return json(r, (r.request().headers()['accept'] ?? '').includes('object') ? row : [row])
      })
      await viaDbMenu(page, 'Календар платежів', /Календар платежів|Платежі —/)
      await page.getByRole('button', { name: /Отримано/ }).first().click()
      await expect(page.getByText('Підтвердити платіж')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'manage-guests',
    go: (page) => viaDbMenu(page, 'Управління гостями', /Гості|Запросити/),
  },
  {
    // Фаза 3: InviteSheet став повноекранним маршрутом. Два кроки одного
    // екрана — форма і показ готового лінка — це РІЗНІ стани рендера, тож
    // міряються обидва.
    label: 'create-invite',
    go: async (page) => {
      await viaDbMenu(page, 'Управління гостями', /Гості|Запросити/)
      await page.getByLabel('Запросити гостя').click()
      await expect(page.getByText('Запросити гостя')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'create-invite-created',
    go: async (page) => {
      // POST мусить віддати ОБʼЄКТ: код читає `.select('invite_token').single()`.
      await page.route('**/rest/v1/guest_links**', (r) => {
        if (r.request().method() === 'POST') {
          return json(r, { invite_token: 'ee00112233445566778899bb' })
        }
        return json(r, [])
      })
      await viaDbMenu(page, 'Управління гостями', /Гості|Запросити/)
      await page.getByLabel('Запросити гостя').click()
      await expect(page.getByText('Запросити гостя')).toBeVisible({ timeout: 15_000 })
      await page.getByRole('button', { name: 'Створити' }).click()
      await expect(page.getByText('Посилання створено!')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    // Оренда — фаза 5. Вхід із картки вільного обʼєкта через плаваючу дію.
    label: 'rent-property',
    go: async (page) => {
      await atDbObjects(page)
      await page.locator('.obj-t').filter({ hasText: 'Офіс 102' }).first().click()
      await expect(page.getByText(/Здати в оренду/).first()).toBeVisible({ timeout: 15_000 })
      await page.getByRole('button', { name: 'Здати в оренду' }).first().click()
      await expect(page.getByLabel('Орендар')).toBeVisible({ timeout: 15_000 })
    },
  },
  { label: 'folder-manage', go: (page) => viaDbMenu(page, 'Папки', /Групуйте|Додати папку/) },
  {
    // Пакетні пікери — окремі екрани з фази 4. Вхід лише через режим виділення,
    // тож крок відтворює його цілком: меню → «Виділити обʼєкти» → тап по картці.
    label: 'folder-picker',
    go: (page) => viaBatch(page, 'У папку', /Оберіть папку|Створити й перемістити/),
  },
  {
    label: 'db-picker',
    go: (page) => viaBatch(page, 'В базу', /буде переміщено|Створити й перенести/),
  },
  { label: 'team', go: (page) => viaDbMenu(page, 'Команда', /Команда|Запросити/) },
  { label: 'export', go: (page) => viaDbMenu(page, 'Експорт', /Формат файлу|Завантажити/) },
  {
    label: 'notifications',
    go: async (page) => {
      await atDbList(page)
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await expect(page.getByText(/Сповіщення|Немає сповіщень/).first()).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'profile',
    go: async (page) => {
      await atDbList(page)
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    // Видалення акаунта — фаза 5, останній шит, що став екраном. Вхід лише з
    // Профілю, тож крок повторює його шлях і йде на крок глибше.
    label: 'delete-account',
    go: async (page) => {
      await atDbList(page)
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
      await page.locator('.del-acc').click()
      await expect(page.getByLabel('Підтвердження видалення')).toBeVisible({ timeout: 15_000 })
    },
  },
]

// ── Рієлтор ───────────────────────────────────────────────────────────────────

export const REALTOR: HarnessUser = { ...DEFAULT_USER, role: 'realtor', first_name: 'Олена' }

export async function realtorFixtures(page: Page) {
  const RDB = { ...DB, owner_id: OTHER_OWNER }
  await setupApp(page, { user: REALTOR })
  await seedSession(page, REALTOR as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000009', realtor_id: REALTOR.id,
    db_id: DB_ID, created_at: NOW, database: RDB,
  }]))
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? RDB : [RDB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPERTIES[0] : PROPERTIES))
  await emptyTables(page, ['collections', 'collection_properties', 'db_members',
    'property_folders', 'property_photos', 'property_views', 'notifications',
    'rent_payments', 'rent_payment_records', 'property_files'])
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function atRealtorHome(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
}

export const REALTOR_SCREENS: ScreenStep[] = [
  { label: 'realtor-dashboard', go: atRealtorHome },
  {
    label: 'realtor-database',
    go: async (page) => {
      await atRealtorHome(page)
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText(/Всі \(/).first()).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'qr-scanner',
    go: async (page) => {
      await atRealtorHome(page)
      await page.getByRole('button', { name: 'Додати базу за QR' }).click()
      await expect(page.getByText(/Сканер|Відскануйте/).first()).toBeVisible({ timeout: 15_000 })
    },
  },
  {
    label: 'collections',
    go: async (page) => {
      await atRealtorHome(page)
      await page.locator('.tabbar [aria-label="Підбірки"]').click()
      await expect(page.getByText(/Підбірки|Немає підбірок/).first()).toBeVisible({ timeout: 15_000 })
    },
  },
]

// ── Гість ─────────────────────────────────────────────────────────────────────

export async function guestFixtures(page: Page) {
  const GUEST = { ...DEFAULT_USER, first_name: 'Гість' } as unknown as HarnessUser
  ;(GUEST as unknown as { role: string }).role = 'guest'
  const PROPERTY = { ...PROPERTIES[0], owner_id: OTHER_OWNER }
  await setupApp(page, { user: GUEST })
  await seedSession(page, GUEST as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '50000000-0000-0000-0000-000000000001', owner_id: PROPERTY.owner_id,
    property_id: PROPERTY.id, db_id: null, invite_token: 'gg000000000000000000001',
    label: 'Мій орендар', guest_user_id: GUEST.id, status: 'active', claimed_at: NOW,
    created_at: NOW, property: PROPERTY, database: null,
  }]))
  await page.route('**/rest/v1/properties**', (r) =>
    // `.single()` детальної чекає ОБʼЄКТ — масив лишає екран на спінері назавжди.
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPERTY : [PROPERTY]))
  await emptyTables(page, ['property_photos', 'property_files', 'rent_payments',
    'rent_payment_records', 'notifications', 'databases', 'db_members'])
}

export const GUEST_SCREENS: ScreenStep[] = [
  {
    label: 'guest-home',
    go: async (page) => {
      await page.goto('/')
      await expect(page.getByText("Мої об'єкти")).toBeVisible({ timeout: 20_000 })
    },
  },
  {
    label: 'guest-property',
    go: async (page) => {
      await page.goto('/')
      await expect(page.getByText("Мої об'єкти")).toBeVisible({ timeout: 20_000 })
      await page.getByText('Офіс 101').first().click()
      await expect(page.getByText('Корисна площа')).toBeVisible({ timeout: 15_000 })
    },
  },
]

// ── Онбординг ─────────────────────────────────────────────────────────────────
// Екрани, які користувач бачить РАНІШЕ за все інше, і які теж не міряв ніхто.

export async function onboardingFixtures(page: Page) {
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
}

export const ONBOARDING_SCREENS: ScreenStep[] = [
  {
    label: 'role-select',
    go: async (page) => {
      await page.goto('/')
      await expect(page.getByText('Власник').first()).toBeVisible({ timeout: 20_000 })
    },
  },
  {
    label: 'profile-setup',
    go: async (page) => {
      await page.goto('/')
      await expect(page.getByText('Власник').first()).toBeVisible({ timeout: 20_000 })
      await page.getByText('Власник').first().click()
      await page.getByText('Продовжити →').click()
      await expect(page.getByPlaceholder('you@email.com')).toBeVisible({ timeout: 15_000 })
    },
  },
]

/** Усі групи разом — для гардів, яким байдуже до ролі. */
export const ALL_GROUPS: { role: string; fixtures: (p: Page) => Promise<void>; screens: ScreenStep[] }[] = [
  { role: 'owner', fixtures: ownerFixtures, screens: OWNER_SCREENS },
  { role: 'realtor', fixtures: realtorFixtures, screens: REALTOR_SCREENS },
  { role: 'guest', fixtures: guestFixtures, screens: GUEST_SCREENS },
  { role: 'onboarding', fixtures: onboardingFixtures, screens: ONBOARDING_SCREENS },
]
