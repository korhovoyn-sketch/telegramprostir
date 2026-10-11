import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute as json, seedSession, skipCoachmarks, type HarnessUser } from './helpers/harness'

// ДОСТУП, ЯКИЙ Є НА СЕРВЕРІ, МУСИТЬ БУТИ ДОСЯЖНИЙ В ІНТЕРФЕЙСІ — і навпаки.
//
// Права на дані в застосунку дає ЧЛЕНСТВО (підписка, гостьовий лінк, команда),
// а не `users.role`; роль вирішує лише, які вкладки в таббарі. Тож кожен розрив
// між цими двома шарами — тупик: сервер дозволяє, а кнопки немає, або екран
// каже «повторіть», коли повторювати нема чого. Тут зібрано ті, що знайшов
// аудит доступів (жовтень 2026), і кожен тест падав до свого фікса.

const NOW = new Date().toISOString()
const FOREIGN_OWNER = '00000000-0000-0000-0000-000000000099'
const TEAM_DB_ID = '10000000-0000-0000-0000-000000000002'
const SUB_DB_ID = '10000000-0000-0000-0000-000000000003'
const GUEST_PROP_ID = '20000000-0000-0000-0000-000000000009'

function db(id: string, name: string, ownerId = FOREIGN_OWNER) {
  return {
    id, owner_id: ownerId, name, address: 'вул. Тестова, 1', type: 'business_center',
    color: 'blue', created_at: NOW, updated_at: NOW, properties: [],
  }
}
const TEAM_DB = db(TEAM_DB_ID, 'БЦ Команди')
const SUB_DB = db(SUB_DB_ID, 'БЦ Підписки')

const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: TEAM_DB_ID, owner_id: FOREIGN_OWNER,
  name: 'Офіс 101', floor: '1', status: 'free', area_useful: 45, area_total: 52,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null, landlord_name: null,
  sort_order: 100, created_at: NOW, updated_at: NOW, photos: [],
}

const wantsObject = (r: Route) => (r.request().headers()['accept'] ?? '').includes('object')

/** Бекенд, де людина — редактор КОМАНДИ чужої бази і більше нічого. */
async function teamEditorBackend(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    if (r.request().url().includes('owner_id=eq.')) return json(r, [])
    return json(r, wantsObject(r) ? TEAM_DB : [TEAM_DB])
  })
  await page.route('**/rest/v1/db_members**', (r) => json(r, [{ db_id: TEAM_DB_ID, database: TEAM_DB }]))
  await page.route('**/rest/v1/properties**', (r) =>
    r.request().method() === 'GET' ? json(r, wantsObject(r) ? PROP : [PROP]) : r.fallback())
}

// ─── Права редактора на ХОЛОДНОМУ вході ──────────────────────────────────────
//
// Права на екрані бази бралися лише з `memberDbIds` у сторі, а його наповнюють
// два домашні екрани. Клейм `team_` кличе `navigateRoot` і одразу `navigate` —
// домашній не встигає змонтуватись, тож людина чула «Редагування доступне», а
// на екрані не було ні «Додати обʼєкт», ні меню бази. Для гостя домашнього з
// цим джерелом немає взагалі. Роль тут ні до чого, тому — усі три.

for (const role of ['owner', 'realtor', 'guest'] as const) {
  test(`team_ на холодному вході: редактор (${role}) одразу має права`, async ({ page }) => {
    await setupApp(page, { user: { ...DEFAULT_USER, role }, startParam: 'team_feedfacecafe00112233' })
    await skipCoachmarks(page)
    await page.route('**/rest/v1/rpc/claim_team_invite', (r) => json(r, { db_id: TEAM_DB_ID }))
    await teamEditorBackend(page)

    await page.goto('/')
    await expect(page.locator('.hdr-t', { hasText: 'БЦ Команди' })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Всі (1)')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Додати обʼєкт' })).toBeVisible()
    await page.getByRole('button', { name: 'Меню бази' }).click()
    await expect(page.getByText('Календар платежів')).toBeVisible()
    // Права РЕДАКТОРА, не власника: адміністрування самої бази лишається закритим.
    await expect(page.getByText('Видалити базу')).toHaveCount(0)
  })
}

test('prop_ на обʼєкт команди: картка обʼєкта одразу з правами редактора', async ({ page }) => {
  // Окремий шлях від `team_`: тут клейму немає, тож про членство НЕ знає ніхто,
  // крім самого екрана обʼєкта. Він і мусить спитати.
  const user = { ...DEFAULT_USER, role: 'guest' as const }
  await setupApp(page, { user, startParam: 'prop_bb0000000000000000000011' })
  await seedSession(page, user)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/rpc/lookup_shared_property', (r) =>
    json(r, [{ id: PROP.id, db_id: TEAM_DB_ID }]))
  await teamEditorBackend(page)

  await page.goto('/')
  await expect(page.getByText('Офіс 101').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByRole('button', { name: 'Редагувати обʼєкт' })).toBeVisible({ timeout: 10_000 })
  await expect(page.getByRole('button', { name: 'Здати в оренду' })).toBeVisible()
  // Шаринг обʼєкта — owner-only і для редактора теж.
  await expect(page.getByRole('button', { name: 'Поділитись обʼєктом' })).toHaveCount(0)
})

// ─── «Інші доступи» на домашніх екранах ──────────────────────────────────────
//
// Deep link приводив у чужу базу РІВНО ОДИН РАЗ. Після виходу домашній екран
// ролі показував лише «свій» вид доступу, і шлях назад зникав, хоч доступ на
// сервері лишався: власник, що підписався на базу колеги; гість, якого взяли в
// команду; рієлтор, що сам орендує офіс.

async function homeWith(page: Page, user: HarnessUser, opts: {
  subs?: boolean; guest?: boolean; team?: boolean
}) {
  await setupApp(page, { user })
  await seedSession(page, { ...user })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, opts.subs
    ? [{ id: '30000000-0000-0000-0000-000000000001', realtor_id: user.id, db_id: SUB_DB_ID, created_at: NOW, database: SUB_DB }]
    : []))
  await page.route('**/rest/v1/guest_links**', (r) => json(r, opts.guest
    ? [{
        id: '31000000-0000-0000-0000-000000000001', property_id: GUEST_PROP_ID, db_id: null,
        label: 'Офіс на Подолі', status: 'active', owner_id: FOREIGN_OWNER, guest_user_id: user.id,
        property: { id: GUEST_PROP_ID, db_id: SUB_DB_ID, name: 'Склад 7', status: 'occupied', floor: '1' },
        database: null,
      }]
    : []))
  await page.route('**/rest/v1/db_members**', (r) => json(r, opts.team
    ? [{ db_id: TEAM_DB_ID, database: TEAM_DB }] : []))
  await page.route('**/rest/v1/databases**', (r) => {
    const url = r.request().url()
    if (url.includes('owner_id=eq.')) return json(r, user.role === 'owner' ? [db('10000000-0000-0000-0000-000000000001', 'Моя база', user.id)] : [])
    const target = url.includes(SUB_DB_ID) ? SUB_DB : TEAM_DB
    return json(r, wantsObject(r) ? target : [target])
  })
  await page.route('**/rest/v1/properties**', (r) =>
    r.request().method() === 'GET' ? json(r, wantsObject(r) ? PROP : [PROP]) : r.fallback())
  await page.goto('/')
}

const otherAccess = (page: Page) => page.getByRole('region', { name: 'Інші доступи' })

test('гість, якого взяли в команду: база команди досяжна з домашнього, без «немає обʼєктів»', async ({ page }) => {
  await homeWith(page, { ...DEFAULT_USER, role: 'guest' }, { team: true })
  await expect(page.getByText('Мої обʼєкти')).toBeVisible({ timeout: 20_000 })

  const row = otherAccess(page).getByRole('button', { name: /БЦ Команди/ })
  await expect(row).toBeVisible({ timeout: 10_000 })
  // Порожній стан тут був би неправдою: доступ Є, просто іншого виду.
  await expect(page.getByText('Немає доступних обʼєктів')).toHaveCount(0)

  await row.click()
  await expect(page.locator('.hdr-t', { hasText: 'БЦ Команди' })).toBeVisible({ timeout: 15_000 })
  await expect(page.getByRole('button', { name: 'Додати обʼєкт' })).toBeVisible()
})

test('гість без інших доступів: порожній стан лишається (антивакуум)', async ({ page }) => {
  // Без цієї половини «порожній стан сховано» проходило б і тоді, коли його
  // ховають ЗАВЖДИ.
  await homeWith(page, { ...DEFAULT_USER, role: 'guest' }, {})
  await expect(page.getByText('Немає доступних обʼєктів')).toBeVisible({ timeout: 20_000 })
  await expect(otherAccess(page)).toHaveCount(0)
})

test('власник: підписка на чужу базу і гостьовий лінк — на «Моїх базах»', async ({ page }) => {
  await homeWith(page, { ...DEFAULT_USER, role: 'owner' }, { subs: true, guest: true })
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Моя база').first()).toBeVisible()

  const section = otherAccess(page)
  await expect(section.getByRole('button', { name: /БЦ Підписки/ })).toBeVisible({ timeout: 10_000 })
  await expect(section.getByRole('button', { name: /Склад 7/ })).toBeVisible()
  // Власна база — НЕ «інший доступ»: інакше вона стояла б на екрані двічі.
  await expect(section.getByText('Моя база')).toHaveCount(0)

  await section.getByRole('button', { name: /БЦ Підписки/ }).click()
  await expect(page.locator('.hdr-t', { hasText: 'БЦ Підписки' })).toBeVisible({ timeout: 15_000 })
})

test('рієлтор, що сам гість: гостьовий обʼєкт досяжний з дашборда', async ({ page }) => {
  await homeWith(page, { ...DEFAULT_USER, role: 'realtor' }, { guest: true })
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  const row = otherAccess(page).getByRole('button', { name: /Склад 7/ })
  await expect(row).toBeVisible({ timeout: 10_000 })
  await expect(row).toContainText('Офіс на Подолі')
})

// ─── prop_ для СТОРОННЬОГО ───────────────────────────────────────────────────
//
// `prop_` — головна кнопка публічної /v, тобто найчастіше його відкриває
// людина БЕЗ доступу до обʼєкта. Картка обʼєкта для неї порожня за RLS, і вона
// діставала «Обʼєкт не знайдено» замість оголошення, яке щойно бачила.

test('prop_ від стороннього: оголошення з контактом власника, а не «не знайдено»', async ({ page }) => {
  const user = { ...DEFAULT_USER, role: 'realtor' as const }
  const TOKEN = 'bb0000000000000000000011'
  await setupApp(page, { user, startParam: `prop_${TOKEN}` })
  await seedSession(page, user)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/rpc/lookup_shared_property', (r) =>
    json(r, [{ id: PROP.id, db_id: TEAM_DB_ID }]))
  // RLS чужого обʼєкта не віддає: порожній набір, без помилки.
  await page.route('**/rest/v1/properties**', (r) => json(r, []))
  let previewToken: string | undefined
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) => {
    previewToken = JSON.parse(r.request().postData() ?? '{}').p_token
    return json(r, [{
      property_id: PROP.id, property_name: 'Офіс 101', property_status: 'free',
      property_floor: '1', property_area_useful: 45, property_area_total: 52,
      property_area_basis: 'total', property_rent_type: 'per_m2', property_rent_rate: 18,
      property_sale_price: null, property_description: 'Світлий офіс біля метро',
      db_name: 'БЦ Команди', owner_first_name: 'Микола', owner_last_name: 'К.',
      owner_tg_username: 'mykola', owner_phone: null, owner_currency: 'USD', photos: [],
    }])
  })

  await page.goto('/')
  await expect(page.locator('.hdr-t', { hasText: 'Офіс 101' })).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Світлий офіс біля метро')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Написати' })).toBeVisible()
  await expect(page.getByText('Обʼєкт не знайдено')).toHaveCount(0)
  expect(previewToken, 'перегляд мусить авторизуватись ТОКЕНОМ лінка').toBe(TOKEN)
})

// ─── Рієлтор, у якого забрали базу ───────────────────────────────────────────
//
// Після ротації чи відкликання (069) підписки немає, і рядок бази RLS більше
// не віддає. «Перевір підключення і спробуй ще раз» тут — тупик: повтор не
// допоможе ніколи, а людина вважатиме, що зламався зв'язок.

async function realtorOpensSubscribedDb(page: Page, dbAnswer: (r: Route) => Promise<void>) {
  const user = { ...DEFAULT_USER, role: 'realtor' as const }
  await setupApp(page, { user })
  await seedSession(page, user)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r,
    [{ id: '30000000-0000-0000-0000-000000000001', realtor_id: user.id, db_id: SUB_DB_ID, created_at: NOW, database: SUB_DB }]))
  await page.route('**/rest/v1/databases**', dbAnswer)
  await page.route('**/rest/v1/properties**', (r) => json(r, []))
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.row', { hasText: 'БЦ Підписки' }).first().click()
}

test('рієлтор: доступ до бази забрали — екран каже це, а не «перевір зʼєднання»', async ({ page }) => {
  await realtorOpensSubscribedDb(page, (r) => r.fulfill({
    status: 406, contentType: 'application/json',
    body: JSON.stringify({ code: 'PGRST116', details: 'The result contains 0 rows', hint: null,
      message: 'JSON object requested, multiple (or no) rows returned' }),
  }))
  await expect(page.getByText('Доступу до бази більше немає')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByRole('button', { name: 'Спробувати ще раз' })).toHaveCount(0)
})

test('рієлтор: збій мережі лишається повтором (антивакуум)', async ({ page }) => {
  await realtorOpensSubscribedDb(page, (r) => r.fulfill({
    status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'boom' }),
  }))
  await expect(page.getByRole('button', { name: 'Спробувати ще раз' })).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Доступу до бази більше немає')).toHaveCount(0)
})

test('профіль гостя підписаний «Гість», а не «Ріелтор»', async ({ page }) => {
  await homeWith(page, { ...DEFAULT_USER, role: 'guest' }, {})
  await page.locator('.tabbar').getByRole('button', { name: 'Профіль' }).click()
  await expect(page.locator('.bdg', { hasText: 'Гість' })).toBeVisible({ timeout: 15_000 })
  await expect(page.locator('.bdg', { hasText: 'Ріелтор' })).toHaveCount(0)
})
