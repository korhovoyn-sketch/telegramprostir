import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession } from './helpers/harness'

// Меню бази й поверхня редагування × ролі.
//
// Ключовий гард — на дефекті «шлюз питає про РОЛЬ, а не про власність».
// `isOwner` був `user.role === 'owner' || memberDbIds.includes(dbId)`, тобто
// істинний для БУДЬ-ЯКОГО власника незалежно від того, чия база відкрита.
// Власник, що прийшов у ЧУЖУ базу гостьовим лінком, бачив FAB «Додати обʼєкт»,
// «Редагувати», «Дублювати» — кнопки виглядали живими, а запис блокував лише
// RLS. Права мусить визначати ВЛАСНІСТЬ рядка, а не роль акаунта.

const NOW = new Date().toISOString()
const DB_ID = '10000000-0000-0000-0000-000000000001'
const STRANGER = '99999999-9999-9999-9999-999999999999'

function makeDb(ownerId: string) {
  return {
    id: DB_ID, owner_id: ownerId, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
    type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
    share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
  }
}

function prop(ownerId: string) {
  return {
    id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: ownerId,
    name: 'Офіс 101', floor: '2', status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: 100, share_token: 'bb00000000000000000001', share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  }
}

interface RoleOpts {
  /** Хто ВОЛОДІЄ базою (за замовчуванням — сам користувач). */
  dbOwnerId?: string
  /** Членства в командах, які поверне db_members. */
  memberOf?: string[]
  /** Таблиця папок відсутня (бекенд без 043). */
  foldersUnavailable?: boolean
}

async function setup(page: Page, user: typeof DEFAULT_USER, opts: RoleOpts = {}) {
  const ownerId = opts.dbOwnerId ?? user.id
  const db = makeDb(ownerId)

  await setupApp(page, { user })
  await seedSession(page, { ...user })

  await page.route('**/rest/v1/databases**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? db : [db])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, wantsObject ? prop(ownerId) : [prop(ownerId)])
  })
  // RealtorDashboardScreen тягне базу ВКЛАДЕНИМ embed-ом (`database:databases(*)`),
  // тож самого `db_id` замало — без вкладеного обʼєкта member-база не зʼявиться.
  await page.route('**/rest/v1/db_members**', (r) =>
    jsonRoute(r, (opts.memberOf ?? []).map((dbId, i) => ({
      id: `40000000-0000-0000-0000-00000000000${i}`, db_id: dbId, user_id: user.id,
      role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер',
      member_name: 'Оля', status: 'active', claimed_at: NOW, created_at: NOW,
      database: db,
    }))))
  await page.route('**/rest/v1/property_folders**', (r) => {
    if (opts.foldersUnavailable) {
      return r.fulfill({
        status: 404, contentType: 'application/json',
        body: JSON.stringify({ code: '42P01', message: 'relation "property_folders" does not exist' }),
      })
    }
    return jsonRoute(r, [])
  })
  for (const t of ['rent_payments', 'rent_payment_records', 'property_views',
                   'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

async function openDbFromList(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

/** Назви рядків меню бази у порядку появи. */
async function menuRows(page: Page): Promise<string[]> {
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  return page.locator('.modal .sheet-row .sheet-lbl').allInnerTexts()
}

test('власник власної бази бачить повне меню з небезпечними діями', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setup(page, owner)
  await openDbFromList(page)

  const rows = await menuRows(page)
  expect(rows).toContain('Аналітика і поширення')
  expect(rows).toContain('Управління гостями')
  expect(rows).toContain('Команда')
  expect(rows).toContain('Редагувати базу')
  expect(rows).toContain('Видалити базу')
  expect(await page.locator('.modal .sheet-row.danger').count()).toBe(1)
})

test('без таблиці папок рядок «Папки» зникає, решта меню ціла', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setup(page, owner, { foldersUnavailable: true })
  await openDbFromList(page)

  const rows = await menuRows(page)
  expect(rows, 'без міграції 043 папок у меню нема').not.toContain('Папки')
  // Вимкнення фічі не має тягнути за собою решту меню.
  expect(rows).toContain('Експорт')
  expect(rows).toContain('Видалити базу')
})

test('редактор команди не бачить власницьких дій, але має поверхню редагування', async ({ page }) => {
  // Роль realtor + активне членство: саме та комбінація, на якій редактор
  // колись НАЗАВЖДИ губив доступ до своєї бази.
  const editor = { ...DEFAULT_USER, role: 'realtor' as const }
  await setup(page, editor, { dbOwnerId: STRANGER, memberOf: [DB_ID] })
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => jsonRoute(r, []))
  await page.goto('/')
  // Домашній екран рієлтора — дашборд, а не «Мої бази»: member-база живе там
  // із бейджем «Команда» і веде в повноцінний db-objects.
  await expect(page.getByText('Команда').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })

  const rows = await menuRows(page)
  expect(rows, 'шаринг — лише власнику').not.toContain('Аналітика і поширення')
  expect(rows).not.toContain('Управління гостями')
  expect(rows).not.toContain('Команда')
  expect(rows, 'перейменувати чужу базу редактор не може').not.toContain('Редагувати базу')
  expect(rows, 'видалити чужу базу редактор не може').not.toContain('Видалити базу')
  // …але редагування ВМІСТУ дозволене — саме за цим його й запросили. Перелік
  // ПОВНИЙ навмисно: інакше пункт, що тихо зник (напр. «Календар платежів»
  // після рефакторингу шлюзів), виглядав би як «тест і далі зелений».
  for (const allowed of ['Календар платежів', 'Експорт', 'Папки',
                         "Виділити об'єкти", 'Змінити порядок']) {
    expect(rows, `редактор мусить мати «${allowed}»`).toContain(allowed)
  }
})

test('власник у ЧУЖІЙ базі не отримує поверхню редагування', async ({ page }) => {
  // ГОЛОВНИЙ ГАРД. Акаунт із роллю owner відкриває базу, якою НЕ володіє і в
  // команді якої не перебуває. Раніше `isOwner` було істинним лише через роль,
  // і на чужій базі малювались FAB та дії картки.
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setup(page, owner, { dbOwnerId: STRANGER })
  await openDbFromList(page)

  await expect(page.getByLabel('Меню бази'), 'меню чужої бази недоступне').toHaveCount(0)
  await expect(page.getByRole('button', { name: /Додати об/ }), 'FAB на чужій базі не місце').toHaveCount(0)
  await expect(page.getByRole('button', { name: /^Редагувати$/ })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Дублювати/ })).toHaveCount(0)
})

test('власник у ЧУЖІЙ базі не отримує дій і на картці обʼєкта', async ({ page }) => {
  const owner = { ...DEFAULT_USER, role: 'owner' as const }
  await setup(page, owner, { dbOwnerId: STRANGER })
  await openDbFromList(page)
  await page.locator('.obj-t').first().click()
  await expect(page.getByText('Офіс 101').first()).toBeVisible({ timeout: 15_000 })

  // Здати в оренду / звільнити — теж запис, і теж не для чужого обʼєкта.
  await expect(page.getByRole('button', { name: /Здати в оренду/ })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Звільнити/ })).toHaveCount(0)
})
