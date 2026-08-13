import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks, seedSession } from './helpers/harness'

// Життєвий цикл бази: створення / редагування / ВИДАЛЕННЯ / завантаження списку.
//
// Видалення бази до цього спека не мало ЖОДНОГО функціонального тесту — лише
// два непрямі дотики (team.spec перевіряє, що рядка немає в редактора;
// verify-session рахує один `.danger`). Тобто найдеструктивніша дія застосунку
// не була перевірена взагалі.
//
// ГОЛОВНИЙ ГАРД тут — порядок деструктивних кроків. PostgREST під RLS повертає
// на DELETE **0 рядків і NULL-помилку**, тож «видалив» і «не мав права» на
// дроті виглядають ОДНАКОВО. Стара реалізація стирала storage ПЕРЕД рядком:
// заблокований DELETE давав тост «Базу видалено», база лишалась жива, а всі
// фото були вже знищені безповоротно.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс 10${n}`, floor: String(n), status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

interface Wire {
  /** Порядок операцій — саме він і є предметом перевірки. */
  ops: string[]
  dbDeletes: number
  storageRemoves: number
  posts: Record<string, unknown>[]
  patches: Record<string, unknown>[]
}

interface Opts {
  /** DELETE бази віддає 0 рядків — так виглядає блокування RLS. */
  dbDeleteBlocked?: boolean
  props?: ReturnType<typeof prop>[]
  photos?: { storage_path: string }[]
}

async function setup(page: Page, wire: Wire, opts: Opts = {}) {
  const props = opts.props ?? [prop(1), prop(2)]
  const photos = opts.photos ?? [{ storage_path: `${props[0]?.id}/1.jpg` }]

  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() === 'DELETE') {
      wire.ops.push('db.delete')
      wire.dbDeletes++
      // Заблоковано RLS → 200 і ПОРОЖНІЙ масив, без помилки. Саме так це
      // виглядає на дроті, і саме тому мовчазний провал так довго жив.
      return jsonRoute(r, opts.dbDeleteBlocked ? [] : [{ id: DB_ID }])
    }
    if (rq.method() === 'PATCH') {
      wire.patches.push(JSON.parse(rq.postData() ?? '{}'))
      return jsonRoute(r, wantsObject ? DB : [DB])
    }
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      wire.posts.push(body)
      const created = { ...DB, ...body, id: '10000000-0000-0000-0000-0000000000ff' }
      return jsonRoute(r, wantsObject ? created : [created])
    }
    return jsonRoute(r, wantsObject ? DB : [DB])
  })

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if ((rq.headers()['accept'] ?? '').includes('object')) {
      const m = rq.url().match(/id=eq\.([0-9a-f-]+)/)
      return jsonRoute(r, props.find((p) => p.id === m?.[1]) ?? props[0])
    }
    return jsonRoute(r, props)
  })

  await page.route('**/rest/v1/property_photos**', (r) => jsonRoute(r, photos))
  await page.route('**/rest/v1/property_files**', (r) => jsonRoute(r, []))
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records',
                   'property_views', 'property_folders', 'guest_links', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  // Видалення зі storage йде через POST …/storage/v1/object/<bucket>/remove.
  await page.route('**/storage/v1/object/**', (r) => {
    if (r.request().method() === 'POST' || r.request().method() === 'DELETE') {
      wire.ops.push('storage.remove')
      wire.storageRemoves++
    }
    return jsonRoute(r, [])
  })
}

function freshWire(): Wire {
  return { ops: [], dbDeletes: 0, storageRemoves: 0, posts: [], patches: [] }
}

async function openDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

async function openMenu(page: Page) {
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420) // виїзд шита
}

// ─── Видалення ───────────────────────────────────────────────────────────────

test('видалення бази: підтвердження називає кількість обʼєктів, Скасувати нічого не чіпає', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)
  await openMenu(page)
  await page.getByText('Видалити базу', { exact: true }).click()

  const confirm = page.locator('.modal').last()
  // Апостроф у копії застосунку — прямий; regex, щоб гард не ламався від
  // друкарського варіанта в тесті.
  await expect(confirm).toContainText(/2 об.єкти/)
  await confirm.getByRole('button', { name: /Скасувати/ }).click()
  await page.waitForTimeout(400)

  expect(wire.dbDeletes, 'Скасувати не має слати DELETE').toBe(0)
  expect(wire.storageRemoves, 'Скасувати не має чіпати storage').toBe(0)
})

test('видалення бази: рядок видаляється ПЕРШИМ, storage чиститься лише після нього', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)
  await openMenu(page)
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити$/ }).click()

  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 15_000 })
  expect(wire.dbDeletes).toBe(1)

  // Порядок — суть гарда: знищувати файли можна ЛИШЕ після того, як рядок
  // справді зник. Інакше заблокований DELETE залишає базу без фотографій.
  const firstDelete = wire.ops.indexOf('db.delete')
  const firstStorage = wire.ops.indexOf('storage.remove')
  expect(firstDelete, 'DELETE рядка мусить статись').toBeGreaterThanOrEqual(0)
  if (firstStorage >= 0) {
    expect(firstStorage, 'storage чиститься ПІСЛЯ видалення рядка').toBeGreaterThan(firstDelete)
  }
})

test('видалення бази: заблокований RLS DELETE не стирає фото і не бреше про успіх', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { dbDeleteBlocked: true })
  await openDb(page)
  await openMenu(page)
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити$/ }).click()
  await page.waitForTimeout(1200)

  expect(wire.storageRemoves, 'жодного файлу не можна знищити, коли рядок не видалився').toBe(0)
  await expect(page.getByText('Базу видалено')).toHaveCount(0)
  await expect(page.locator('.toast')).toContainText(/Помилка|доступ/i)
})

test('видалення бази: Back після видалення не веде на мертву базу', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)
  await openMenu(page)
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити$/ }).click()
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 15_000 })

  const wentBack = await page.evaluate(() => {
    const tg = (window as unknown as { Telegram?: { WebApp?: { BackButton?: { isVisible?: boolean } } } }).Telegram
    return tg?.WebApp?.BackButton?.isVisible ?? false
  })
  expect(wentBack, 'на списку баз кнопка Назад не потрібна').toBe(false)
})

test('видалення порожньої бази взагалі не чіпає storage', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { props: [], photos: [] })
  await openDb(page)
  await openMenu(page)
  await page.getByText('Видалити базу', { exact: true }).click()
  await page.locator('.modal').last().getByRole('button', { name: /^Видалити$/ }).click()
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 15_000 })

  expect(wire.storageRemoves).toBe(0)
  expect(wire.dbDeletes).toBe(1)
})

// ─── Створення ───────────────────────────────────────────────────────────────

test('створення бази: шлюз порожньої назви, потім коректний POST', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /Створити базу|Додати базу/ }).first().click()

  const cta = page.locator('.mbtn').first()
  await expect(cta).toBeDisabled()

  // Самі пробіли — теж порожня назва.
  const name = page.locator('input').first()
  await name.fill('   ')
  await expect(cta, 'пробіли не є назвою').toBeDisabled()

  // Назва є, типу ще немає — `canCreate` вимагає обидва.
  await name.fill('  БЦ Новий  ')
  await expect(cta, 'без типу створювати не можна').toBeDisabled()
  expect(wire.posts.length).toBe(0)

  await page.locator('.type-card').first().click()
  await expect(cta).toBeEnabled()
  await cta.click()
  await page.waitForTimeout(800)

  expect(wire.posts.length).toBe(1)
  const body = wire.posts[0]
  expect(body.name, 'назва мусить бути обрізана').toBe('БЦ Новий')
  expect(body.owner_id).toBe(USER.id)
  expect(body.type).toBeTruthy()
})

test('створення бази: 403 лишає на формі і не веде в неіснуючу базу', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await page.route('**/rest/v1/databases**', (r) => {
    if (r.request().method() === 'POST') {
      return r.fulfill({
        status: 403, contentType: 'application/json',
        body: JSON.stringify({ code: '42501', message: 'new row violates row-level security policy' }),
      })
    }
    return jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /Створити базу|Додати базу/ }).first().click()
  await page.locator('input').first().fill('БЦ Новий')
  await page.locator('.type-card').first().click()
  await page.locator('.mbtn').first().click()
  await page.waitForTimeout(900)

  await expect(page.locator('.toast')).toBeVisible()
  // Лишаємось на формі — CTA створення на місці, у базу не провалились.
  await expect(page.locator('.mbtn').first()).toBeVisible()
  await expect(page.getByText(/Всі \(/)).toHaveCount(0)
})

// ─── Редагування ─────────────────────────────────────────────────────────────

test('редагування бази: префіл працює на холодному вході (список баз ніколи не вантажився)', async ({ page }) => {
  // Форма редагування бере назву ЛИШЕ зі стору (`databases.find`). Само по собі
  // це крихко, але недосяжно: `edit-db` відкривається ВИКЛЮЧНО з меню
  // `db-objects`, а той екран, не знайшовши базу в сторі, довантажує рядок сам
  // і КЛАДЕ ЙОГО В СТОР. Саме цей ланцюг тут і закріплюється — зламавши
  // self-heal, форма почне малювати порожні поля, а збереження затре назву й тип.
  //
  // ГАРД ВІД ВАКУУМНОСТІ: списковий запит навмисно віддає `[]`, тобто
  // `loadDatabases` не наповнює стор нічим. Пройти можна лише через self-heal.
  const wire = freshWire()
  await setupApp(page, { user: USER, startParam: `db_${DB.share_token}` })
  // Без сесії Splash веде deep link на публічний превʼю замість гілки useDeepLink.
  await seedSession(page, USER)
  await page.route('**/rest/v1/rpc/subscribe_to_shared_db', (r) =>
    jsonRoute(r, [{ db_id: DB_ID, db_name: DB.name, error: 'own_db' }]))
  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() === 'PATCH') {
      wire.patches.push(JSON.parse(rq.postData() ?? '{}'))
      return jsonRoute(r, wantsObject ? DB : [DB])
    }
    // Розрізняємо за фільтром, а не за Accept: `maybeSingle()` не завжди шле
    // object-заголовок, тож самим Accept одиночний запит не впізнати.
    // Списковий (без `id=eq.`) — ПОРОЖНІЙ; адресний — віддає рядок.
    const byId = /id=eq\./.test(rq.url())
    if (byId) return jsonRoute(r, wantsObject ? DB : [DB])
    return jsonRoute(r, wantsObject ? DB : [])
  })
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, [prop(1)]))
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 20_000 })
  await openMenu(page)
  await page.getByText('Редагувати базу', { exact: true }).click()
  await page.waitForTimeout(1500)

  await expect(page.locator('input').first()).toHaveValue('БЦ Рубін')
})
