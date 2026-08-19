import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Команда бази (db_members, міграція 041) ───────────────────────────────────
// Власник: TeamScreen (створення інвайта, revoke). Редактор: бейдж «Команда»
// в списку баз, edit-поверхня без owner-only шарингу. Deep link team_<token>.

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const NOW = new Date().toISOString()

const OWN_DB_ID = '10000000-0000-0000-0000-000000000001'
const TEAM_DB_ID = '10000000-0000-0000-0000-000000000002'
const FOREIGN_OWNER = '00000000-0000-0000-0000-000000000099'

function db(id: string, ownerId: string, name: string) {
  return {
    id, owner_id: ownerId, name, address: 'вул. Тестова, 1',
    type: 'business_center', color: 'blue',
    share_token: 'aabbccddeeff001122334455', share_expires_at: null,
    created_at: NOW, updated_at: NOW,
    properties: [],
  }
}

const PROP = {
  id: '20000000-0000-0000-0000-000000000001',
  db_id: TEAM_DB_ID, owner_id: FOREIGN_OWNER, name: 'Офіс 101', floor: '1',
  status: 'free', area_useful: 45, area_total: 52, rent_type: 'per_m2',
  rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 100, share_token: 'bb0000000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

function skipCoachmarks(page: Page) {
  return page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

// ─── Власник: керування командою ───────────────────────────────────────────────

test('owner: creates a team invite and revokes it', async ({ page }) => {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)

  const OWN_DB = db(OWN_DB_ID, OWNER.id, 'БЦ Рубін')
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? OWN_DB : [OWN_DB])
  })
  await page.route('**/rest/v1/properties**', (route) =>
    route.request().method() === 'GET' ? json(route, []) : route.fallback())

  // db_members: пустий список → після INSERT повертаємо створений рядок
  const members: Record<string, unknown>[] = []
  await page.route('**/rest/v1/db_members**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      const row = {
        id: '30000000-0000-0000-0000-000000000001', db_id: body.db_id,
        user_id: null, role: 'editor', invite_token: 'feedfacecafe00112233',
        label: body.label, member_name: null, status: 'pending',
        claimed_at: null, created_at: NOW,
      }
      members.push(row)
      return json(route, row, 201)
    }
    if (req.method() === 'PATCH') {
      const body = JSON.parse(req.postData() ?? '{}')
      Object.assign(members[0], body)
      return json(route, members)
    }
    return json(route, members)
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()

  // Меню бази → Команда
  await page.getByRole('button', { name: 'Меню бази' }).click()
  await page.getByText('Команда', { exact: true }).click()
  await expect(page.getByText('Команда бази')).toBeVisible()
  await expect(page.getByText('Команди поки немає')).toBeVisible()

  // Створення інвайта з підписом
  await page.getByRole('button', { name: 'Запросити в команду' }).click()
  await page.getByPlaceholder('напр. Менеджер Оля').fill('Менеджер Оля')
  await page.getByRole('button', { name: 'Створити' }).click()

  // Крок 'created' того самого повноекранного маршруту (фаза 3 переробки
  // модалок, atomic-riding-clock.md) — сам deep link у тест-оточенні '#':
  // бот-юзернейм не заданий у dev-сервері, buildDeepLink деградує. Головне —
  // INSERT пішов.
  await expect(page.getByText('Запрошення створено!')).toBeVisible()
  expect(members).toHaveLength(1)
  expect(members[0].db_id).toBe(OWN_DB_ID)
  expect(members[0].label).toBe('Менеджер Оля')
  // Бот-юзернейм у тест-оточенні не заданий, тож `buildDeepLink` віддає '#'.
  // Раніше екран спокійно давав скопіювати цей мертвий лінк і надіслати його —
  // власник дізнавався б про поломку від одержувача (той самий клас, що вже
  // давав прод-інцидент із TELEGRAM_APP_NAME). Тепер обидві дії неактивні.
  await expect(page.getByRole('button', { name: 'Скопіювати' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'У Telegram' })).toBeDisabled()
  await page.getByRole('button', { name: 'Назад' }).click()

  // Список показує pending-рядок з кнопками
  await expect(page.getByText('Менеджер Оля')).toBeVisible()
  await expect(page.getByText('Очікує')).toBeVisible()

  // Revoke через підтвердження
  await page.getByRole('button', { name: 'Відкликати' }).click()
  await expect(page.getByText('Відкликати доступ?')).toBeVisible()
  await page.locator('.modal-actions, [class*=modal]').getByRole('button', { name: 'Відкликати' }).last().click()
  await expect(page.getByText('Відкликано')).toBeVisible()
  expect(members[0].status).toBe('revoked')
})

// ─── Редактор: бейдж і edit-поверхня без owner-only дій ─────────────────────────

async function editorFixtures(page: Page) {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)

  const TEAM_DB = db(TEAM_DB_ID, FOREIGN_OWNER, 'БЦ Чужий')
  await page.route('**/rest/v1/databases**', (route) => {
    const url = route.request().url()
    // Запит власних баз (owner_id=eq.) → порожньо; запит member-баз (id=in.) → чужа база
    if (url.includes('owner_id=eq.')) return json(route, [])
    if (url.includes(`id=in.`)) return json(route, [TEAM_DB])
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? TEAM_DB : [TEAM_DB])
  })
  await page.route('**/rest/v1/db_members**', (route) =>
    json(route, [{ db_id: TEAM_DB_ID }]))
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() !== 'GET') return route.fallback()
    return json(route, accept.includes('object') ? PROP : [PROP])
  })
}

test('editor: member db shows «Команда» badge and full edit surface', async ({ page }) => {
  await editorFixtures(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  // Бейдж «Команда» на member-базі
  const row = page.locator('.row', { hasText: 'БЦ Чужий' })
  await expect(row.getByText('Команда')).toBeVisible()

  await row.click()
  await expect(page.getByText('Всі (1)')).toBeVisible()

  // Edit-поверхня редактора: FAB додавання і меню бази є…
  await expect(page.getByRole('button', { name: "Додати об'єкт" })).toBeVisible()
  await page.getByRole('button', { name: 'Меню бази' }).click()
  await expect(page.getByText('Календар платежів')).toBeVisible()
  // …а owner-only пункти шарингу/гостей/команди — ні
  await expect(page.getByText('Аналітика і поширення')).toHaveCount(0)
  await expect(page.getByText('Управління гостями')).toHaveCount(0)
  await expect(page.getByText('Команда', { exact: true })).toHaveCount(0)
  // …і адміністрування САМОЇ бази — теж ні: 041 дає редактору лише CRUD
  // об'єктів/фото/файлів/платежів, а не право стерти чи перейменувати чужу
  // базу (RLS це заборонить, але клієнт не мав би навіть пропонувати).
  await expect(page.getByText('Редагувати базу')).toHaveCount(0)
  await expect(page.getByText('Видалити базу')).toHaveCount(0)
})

// ─── Редактор з роллю 'realtor' — окремий домашній екран ────────────────────────
// OWNER-редактор і так має 'db-list' у таббарі (звичайний вхід уже покриває
// цей шлях вище). Але 041 навмисно НЕ чіпає users.role — редактором цілком
// може бути 'realtor', чий домашній таб веде на realtor-dashboard, а той читав
// ЛИШЕ realtor_subscriptions і ніколи не питав db_members. Результат: після
// одноразового deep-link team_<token> (який форсить db-list) редактор губив
// шлях до своєї бази НАЗАВЖДИ — «Бази» в таббарі більше нікуди не веде.

const REALTOR_EDITOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }

test('realtor-редактор: бачить member-базу на своєму домашньому екрані з повним доступом на запис', async ({ page }) => {
  await setupApp(page, { user: REALTOR_EDITOR })
  await skipCoachmarks(page)

  const TEAM_DB = db(TEAM_DB_ID, FOREIGN_OWNER, 'БЦ Чужий')
  await page.route('**/rest/v1/realtor_subscriptions**', (route) => json(route, []))
  await page.route('**/rest/v1/db_members**', (route) =>
    json(route, [{ db_id: TEAM_DB_ID, database: TEAM_DB }]))
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? TEAM_DB : [TEAM_DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() !== 'GET') return route.fallback()
    return json(route, accept.includes('object') ? PROP : [PROP])
  })

  await page.goto('/')
  // Домашній екран для role:'realtor' — RealtorDashboardScreen, не db-list.
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })

  const row = page.locator('.row', { hasText: 'БЦ Чужий' })
  await expect(row).toBeVisible()
  await expect(row.getByText('Команда')).toBeVisible()

  // Клік веде в ПОВНИЙ db-objects (CRUD), не в read-only realtor-database.
  await row.click()
  await expect(page.getByText('Всі (1)')).toBeVisible()
  await expect(page.getByRole('button', { name: "Додати об'єкт" })).toBeVisible()
  await page.getByRole('button', { name: 'Меню бази' }).click()
  await expect(page.getByText('Календар платежів')).toBeVisible()
})

test('editor: property detail hides share entry, keeps edit + status CTA', async ({ page }) => {
  await editorFixtures(page)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.row', { hasText: 'БЦ Чужий' }).click()
  await page.locator('.obj-card .obj-t', { hasText: 'Офіс 101' }).click()

  // Редагування і статусна CTA доступні редактору
  await expect(page.getByRole('button', { name: "Редагувати об'єкт" })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Здати в оренду' })).toBeVisible()
  // Шаринг-аналітика (токени) — тільки для справжнього власника
  await expect(page.getByRole('button', { name: "Поділитись об'єктом" })).toHaveCount(0)
})

// ─── Deep link team_<token> ─────────────────────────────────────────────────────

test('deep link: claim_team_invite success lands on the team db', async ({ page }) => {
  await setupApp(page, { user: OWNER, startParam: 'team_feedfacecafe00112233' })
  await skipCoachmarks(page)

  let claimedToken: string | null = null
  await page.route('**/rest/v1/rpc/claim_team_invite', (route) => {
    claimedToken = JSON.parse(route.request().postData() ?? '{}').p_token
    return json(route, { db_id: TEAM_DB_ID })
  })

  const TEAM_DB = db(TEAM_DB_ID, FOREIGN_OWNER, 'БЦ Чужий')
  await page.route('**/rest/v1/databases**', (route) => {
    const url = route.request().url()
    if (url.includes('owner_id=eq.')) return json(route, [])
    if (url.includes('id=in.')) return json(route, [TEAM_DB])
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? TEAM_DB : [TEAM_DB])
  })
  await page.route('**/rest/v1/db_members**', (route) => json(route, [{ db_id: TEAM_DB_ID }]))
  await page.route('**/rest/v1/properties**', (route) =>
    route.request().method() === 'GET' ? json(route, [PROP]) : route.fallback())

  await page.goto('/')
  await expect(page.getByText('Ви в команді! 🎉')).toBeVisible({ timeout: 20_000 })
  // Лендинг: db-objects бази команди (назва — у хедері екрана)
  await expect(page.locator('.hdr-t', { hasText: 'БЦ Чужий' })).toBeVisible()
  await expect(page.getByText('Всі (1)')).toBeVisible()
  expect(claimedToken).toBe('feedfacecafe00112233')
})

test('deep link: claim успішний, але сам рядок бази недоступний — RetryState, не вічний спінер', async ({ page }) => {
  await setupApp(page, { user: OWNER, startParam: 'team_feedfacecafe00112233' })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/rpc/claim_team_invite', (route) =>
    json(route, { db_id: TEAM_DB_ID }))
  // Клейм успішний (RPC — SECURITY DEFINER), але прямий SELECT рядка бази
  // (RLS звичайного клієнта) не повертає нічого: рядок видалили між клеймом
  // і навігацією, або RLS раптово не бачить його. db-list і db-members теж
  // порожні — стор ніколи не наповниться цією базою жодним іншим шляхом.
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? null : [])
  })
  await page.route('**/rest/v1/db_members**', (route) => json(route, []))
  await page.route('**/rest/v1/properties**', (route) =>
    route.request().method() === 'GET' ? json(route, []) : route.fallback())

  await page.goto('/')
  await expect(page.getByText('Ви в команді! 🎉')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Базу не знайдено')).toBeVisible({ timeout: 20_000 })
  // Кнопка повтору жива, а не декоративна — повторний запит той самий null,
  // тож екран лишається на RetryState, а не висить на голому спінері.
  await page.getByRole('button', { name: /Повторити|Спробувати/ }).click()
  await expect(page.getByText('Базу не знайдено')).toBeVisible({ timeout: 20_000 })
})

test('deep link: revoked invite shows the error toast and falls back home', async ({ page }) => {
  await setupApp(page, { user: OWNER, startParam: 'team_deadbeef' })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/rpc/claim_team_invite', (route) =>
    json(route, { error: 'revoked' }))

  await page.goto('/')
  await expect(page.getByText('Запрошення відкликано власником')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Мої бази')).toBeVisible()
})

// Решта гілок `claim_team_invite`. CLAUDE.md вимагає e2e на всі пʼять
// deep-link-префіксів, і team_ довго був покритий лише частково: успіх,
// revoked і недоступний рядок бази були, а помилки нижче — ні.
const CLAIM_ERRORS: Array<{ code: string; copy: string; why: string }> = [
  { code: 'not_found', copy: 'Запрошення не знайдено',
    why: 'токен видалили або він ніколи не існував' },
  { code: 'already_claimed', copy: 'Це запрошення вже використано',
    why: 'інвайт одноразовий — другий користувач по тому ж лінку має отримати відмову' },
  { code: 'cannot_claim_own_link', copy: 'Це ваша власна база',
    why: 'власник не може стати редактором сам у себе' },
]

for (const { code, copy, why } of CLAIM_ERRORS) {
  test(`deep link: claim_team_invite → ${code} (${why})`, async ({ page }) => {
    await setupApp(page, { user: OWNER, startParam: 'team_deadbeefcafe00112233' })
    await skipCoachmarks(page)
    await page.route('**/rest/v1/rpc/claim_team_invite', (route) => json(route, { error: code }))

    await page.goto('/')
    await expect(page.getByText(copy)).toBeVisible({ timeout: 20_000 })
    // Помилка клейму не лишає користувача в нікуди — падаємо на домашній екран.
    await expect(page.getByText('Мої бази')).toBeVisible()
  })
}

test('deep link: повторний claim тим самим користувачем ідемпотентний', async ({ page }) => {
  // `claim_team_invite` для ВЖЕ активного члена віддає {db_id} без помилки —
  // повторне відкриття свого ж лінка мусить просто відкрити базу, а не лаятись.
  await setupApp(page, { user: OWNER, startParam: 'team_feedfacecafe00112233' })
  await skipCoachmarks(page)

  let calls = 0
  await page.route('**/rest/v1/rpc/claim_team_invite', (route) => {
    calls++
    return json(route, { db_id: TEAM_DB_ID })
  })
  const TEAM_DB = db(TEAM_DB_ID, FOREIGN_OWNER, 'БЦ Чужий')
  await page.route('**/rest/v1/databases**', (route) => {
    const url = route.request().url()
    if (url.includes('owner_id=eq.')) return json(route, [])
    if (url.includes('id=in.')) return json(route, [TEAM_DB])
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? TEAM_DB : [TEAM_DB])
  })
  await page.route('**/rest/v1/db_members**', (route) => json(route, [{ db_id: TEAM_DB_ID }]))
  await page.route('**/rest/v1/properties**', (route) =>
    route.request().method() === 'GET' ? json(route, [PROP]) : route.fallback())

  await page.goto('/')
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Помилка доступу')).toHaveCount(0)
  // Диспетчер має відпрацювати РІВНО раз за сесію (гард `handled`), інакше
  // повторний клейм полетів би на кожен ре-рендер.
  expect(calls, 'клейм відпрацьовує один раз за сесію').toBe(1)
})
