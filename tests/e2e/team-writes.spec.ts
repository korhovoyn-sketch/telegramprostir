import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession } from './helpers/harness'

/**
 * ЗАПИС редактора команди — інваріант, від якого залежить, чи його зміни взагалі
 * збережуться.
 *
 * `db_members` (041) дає редактору право писати в чужу базу, але `WITH CHECK`
 * вимагає, щоб рядок належав ВЛАСНИКУ бази. Тобто клієнт мусить проставляти
 * `owner_id` власника, а не свій. Шість шляхів роблять це по-різному, і чотири з
 * них беруть власника ЗІ СТОРУ з фолбеком на себе:
 *
 *   useProperties.createProperty / createProperties / moveToDatabase
 *   useFolders.createFolder
 *       const dbOwner = …databases.find(d => d.id === …)?.owner_id
 *       owner_id: dbOwner ?? user.id      ← для редактора фолбек хибний
 *
 * Наслідок хибного `owner_id` на живому бекенді — саме те, на що скаржаться:
 * «створив обʼєкт, а він не зберігся». `team-loop.spec.ts` цього не бачить: він
 * перевіряє PATCH, де `owner_id` не передається взагалі.
 *
 * Тому тут перевіряється ТІЛО запиту, а не факт його відправки.
 */

const OWNER_ID = '00000000-0000-0000-0000-000000000001'
const EDITOR = {
  ...DEFAULT_USER, role: 'realtor' as const,
  id: '00000000-0000-0000-0000-000000000077', tg_id: 777888999, first_name: 'Оля',
}

const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2026-01-15T10:00:00.000Z'

/** База НАЛЕЖИТЬ іншому користувачу — редактор лише член команди. */
const DB = {
  id: DB_ID, owner_id: OWNER_ID, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: OWNER_ID,
  name: 'Офіс 101', floor: '2', status: 'occupied', area_useful: 45, area_total: 52,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: 'ТОВ «Ромашка»', lease_start_date: '2025-01-01', lease_end_date: '2026-12-31',
  sort_order: 100, share_token: 'bb00000000000000000001', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const MEMBER = {
  id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID, user_id: EDITOR.id,
  role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер',
  member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW,
}

/** Тіла всіх записів, що полетіли на сервер, за таблицями. */
interface Sent { table: string; method: string; body: Record<string, unknown> }

async function editorInMemberDb(page: Page, sent: Sent[], opts: {
  /** Порожній список баз — імітує холодний вхід, коли стор ще нічого не знає. */
  emptyDbList?: boolean
  /**
   * PATCH відмовлено політикою RLS. Моделюється РЕАЛІСТИЧНО: `updateProperty`
   * ходить через `.select(…).single()`, а PostgREST на нуль рядків віддає
   * 406 + `PGRST116`, а не порожній масив зі статусом 200. Мок, що віддавав би
   * `[]`, зробив би тест доказом нічого — саме на цьому я тут і спалився.
   */
  blockPatch?: boolean
} = {}) {
  await setupApp(page, { user: EDITOR })
  await seedSession(page, { ...EDITOR })

  const capture = (table: string) => (r: Route) => {
    const rq = r.request()
    const m = rq.method()
    if (m === 'POST' || m === 'PATCH') {
      const raw = rq.postData() ?? '{}'
      const parsed = JSON.parse(raw) as Record<string, unknown> | Record<string, unknown>[]
      for (const b of Array.isArray(parsed) ? parsed : [parsed]) sent.push({ table, method: m, body: b })
      if (table === 'properties' && m === 'PATCH') {
        if (opts.blockPatch) {
          return r.fulfill({
            status: 406,
            contentType: 'application/json',
            body: JSON.stringify({
              code: 'PGRST116',
              details: 'The result contains 0 rows',
              hint: null,
              message: 'JSON object requested, multiple (or no) rows returned',
            }),
          })
        }
        return jsonRoute(r, { ...PROP, ...(Array.isArray(parsed) ? parsed[0] : parsed) })
      }
      if (table === 'properties') return jsonRoute(r, { ...PROP, id: '20000000-0000-0000-0000-0000000000ff' })
      if (table === 'property_folders') {
        return jsonRoute(r, [{ id: '50000000-0000-0000-0000-000000000001', db_id: DB_ID,
          owner_id: OWNER_ID, name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW }])
      }
      return jsonRoute(r, [{ id: '60000000-0000-0000-0000-000000000001' }])
    }
    if (table === 'properties') {
      return (rq.headers()['accept'] ?? '').includes('object') ? jsonRoute(r, PROP) : jsonRoute(r, [PROP])
    }
    return jsonRoute(r, [])
  }

  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) return jsonRoute(r, DB)
    // `emptyDbList` глушить лише СПИСКОВИЙ запит (`useDatabases`), лишаючи
    // одиночний select живим — саме так виглядає вхід повз db-list.
    if (opts.emptyDbList && !r.request().url().includes('id=eq.')) return jsonRoute(r, [])
    return jsonRoute(r, [DB])
  })
  await page.route('**/rest/v1/properties**', capture('properties'))
  await page.route('**/rest/v1/property_folders**', capture('property_folders'))
  await page.route('**/rest/v1/rent_payment_records**', capture('rent_payment_records'))
  await page.route('**/rest/v1/db_members**', (r) => jsonRoute(r, [{ ...MEMBER, database: DB }]))
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => jsonRoute(r, []))
  for (const t of ['rent_payments', 'notifications', 'property_views', 'guest_links',
                   'property_photos', 'property_files', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Домашній екран рієлтора-редактора → всередину member-бази. */
async function openMemberDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

const ownerIdsFor = (sent: Sent[], table: string, method = 'POST') =>
  sent.filter((s) => s.table === table && s.method === method).map((s) => s.body.owner_id)

// ── Запис редактора несе owner_id ВЛАСНИКА ───────────────────────────────────

test('створення обʼєкта редактором несе owner_id ВЛАСНИКА бази', async ({ page }) => {
  const sent: Sent[] = []
  await editorInMemberDb(page, sent)
  await openMemberDb(page)

  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible({ timeout: 15_000 })
  await page.getByLabel(/Назва об/).fill('Офіс 202')
  await page.locator('.mbtn').click()

  await expect.poll(() => ownerIdsFor(sent, 'properties').length, { timeout: 15_000 })
    .toBeGreaterThan(0)
  expect(ownerIdsFor(sent, 'properties'),
    'редактор мусить писати owner_id ВЛАСНИКА — інакше WITH CHECK у 041 відмовить, і обʼєкт «не збережеться»')
    .toEqual([OWNER_ID])
})

test('пакетне створення — окремий шлях, той самий інваріант', async ({ page }) => {
  // `createProperties` — інший рядок коду з власною копією `dbOwner ?? user.id`,
  // тож перший тест його НЕ покриває.
  const sent: Sent[] = []
  await editorInMemberDb(page, sent)
  await openMemberDb(page)

  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible({ timeout: 15_000 })
  await page.getByLabel(/Назва об/).fill('Офіс 301')
  await page.getByLabel(/Більше об/).click()
  await page.locator('.mbtn').click()

  await expect.poll(() => ownerIdsFor(sent, 'properties').length, { timeout: 15_000 })
    .toBeGreaterThan(1)
  expect([...new Set(ownerIdsFor(sent, 'properties'))],
    'усі рядки пакета належать власнику бази').toEqual([OWNER_ID])
})

test('папка, створена редактором, теж належить власнику бази', async ({ page }) => {
  const sent: Sent[] = []
  await editorInMemberDb(page, sent)
  await openMemberDb(page)

  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByPlaceholder('Нова папка…')).toBeVisible({ timeout: 15_000 })
  await page.getByPlaceholder('Нова папка…').fill('Перший поверх')
  // `Додати` неоднозначне (є ще «Додати обʼєкт» під шитом) — скоупимо в модалку.
  await page.locator('.modal').getByRole('button', { name: 'Додати', exact: true }).click()

  await expect.poll(() => ownerIdsFor(sent, 'property_folders').length, { timeout: 15_000 })
    .toBeGreaterThan(0)
  expect(ownerIdsFor(sent, 'property_folders')).toEqual([OWNER_ID])
})

test('холодний вхід без списку баз не збиває owner_id на редактора', async ({ page }) => {
  // Найпідозріліший шлях: `owner_id` береться зі СТОРУ, а той наповнює
  // `loadDatabases`. Якщо списковий запит нічого не дав, спрацював би фолбек
  // `?? user.id` — тобто редактор написав би рядок на себе, і сервер відмовив би.
  //
  // Рятує self-heal у `DatabaseObjectsScreen`: екран сам довантажує СВІЙ рядок
  // бази і кладе його в стор. Тест доводить, що ланцюг тримається, і падатиме,
  // якщо self-heal колись приберуть як «зайвий запит».
  const sent: Sent[] = []
  await editorInMemberDb(page, sent, { emptyDbList: true })

  await page.goto('/#')
  await page.evaluate((id) => {
    sessionStorage.setItem('ps_nav', JSON.stringify({ screen: 'db-objects', params: { dbId: id } }))
  }, DB_ID)
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 }).catch(() => {})

  // Якщо навігація через sessionStorage не підтримується — доходимо звичайним
  // шляхом; сенс тесту в порожньому СПИСКОВОМУ запиті, а не в способі входу.
  if (await page.getByLabel("Додати об'єкт").count() === 0) {
    await page.goto('/')
    await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
    await page.getByText('БЦ Рубін').first().click()
    await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  }

  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible({ timeout: 15_000 })
  await page.getByLabel(/Назва об/).fill('Офіс 404')
  await page.locator('.mbtn').click()

  await expect.poll(() => ownerIdsFor(sent, 'properties').length, { timeout: 15_000 })
    .toBeGreaterThan(0)
  expect(ownerIdsFor(sent, 'properties'),
    `owner_id поїхав на редактора — спрацював фолбек ?? user.id (${EDITOR.id})`)
    .toEqual([OWNER_ID])
})

// ── Доступ відкликали посеред роботи ─────────────────────────────────────────

test('відкликаний доступ ПОСЕРЕД роботи каже про себе, а не вдає успіх', async ({ page }) => {
  // Найтихіший спосіб втратити дані. PostgREST під RLS не вважає заблокований
  // запис помилкою: PATCH повертає ПОРОЖНІЙ набір і NULL у `error`, тобто
  // «зробив» і «не мав права» на дроті нерозрізненні. Без `assertAffected`
  // редактор побачив би оптимістичну зміну і пішов далі, а на сервері не
  // змінилось би нічого.
  const sent: Sent[] = []
  await editorInMemberDb(page, sent, { blockPatch: true })
  await openMemberDb(page)

  await page.locator('.obj-t').first().click()
  await expect(page.getByRole('button', { name: /Звільнити/ })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Звільнити/ }).click()

  // Підтвердження: нативного попапа в харнесі немає, тож це DOM-фолбек.
  const confirmBtn = page.locator('.modal').getByRole('button', { name: /Звільнити|Підтвердити/ })
  if (await confirmBtn.count() > 0) {
    await page.waitForTimeout(420)
    await confirmBtn.first().click()
  }

  // ОДНА перевірка, а не «видимий» + «текст»: тост гасне сам через 3.5с, і
  // друга проба ловила вже порожнечу.
  await expect(page.locator('.toast'))
    .toContainText(/Немає доступу|Не збереглося|Не вдалося|Помилка/i, { timeout: 15_000 })
  expect(sent.filter((s) => s.table === 'properties' && s.method === 'PATCH').length,
    'PATCH навіть не полетів — тест перевіряв би не те').toBeGreaterThan(0)
})
