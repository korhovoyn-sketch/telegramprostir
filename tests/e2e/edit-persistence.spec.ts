import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, objectAction } from './helpers/harness'

// Чи РЕАЛЬНО зберігаються зміни: перехоплюємо PATCH і перевіряємо, що
// відредаговані поля долітають до бекенда, а екран показує їх після повернення.
// (Регресія з area_basis: форма зберігала, але колонки не було → тихий фейл.)

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const PROP = {
  id: PROP_ID, db_id: DB_ID, owner_id: USER.id, name: 'Офіс 101', floor: '2',
  status: 'occupied', area_useful: 100, area_total: 120, area_basis: 'total',
  rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: 'ТОВ «Ромашка»', lease_start_date: '2026-01-01', lease_end_date: '2027-01-01',
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

/** Мутований стан «БД» — PATCH його оновлює, наступний GET віддає оновлене. */
function makeState() {
  return { prop: { ...PROP }, db: { ...DB } }
}

async function setup(page: Page, state: ReturnType<typeof makeState>,
                    captured: { propPatch?: Record<string, unknown>; dbPatch?: Record<string, unknown> }) {
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      captured.dbPatch = JSON.parse(rq.postData() ?? '{}')
      state.db = { ...state.db, ...captured.dbPatch }
      return jsonRoute(r, [state.db])
    }
    const accept = rq.headers()['accept'] ?? ''
    return jsonRoute(r, accept.includes('object') ? state.db : [state.db])
  })

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      captured.propPatch = JSON.parse(rq.postData() ?? '{}')
      state.prop = { ...state.prop, ...captured.propPatch }
      // `.select().single()` просить саме обʼєкт (Accept: …pgrst.object+json)
      const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? state.prop : [state.prop])
    }
    if (rq.method() !== 'GET') return r.fallback()
    const accept = rq.headers()['accept'] ?? ''
    return jsonRoute(r, accept.includes('object') ? state.prop : [state.prop])
  })

  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('редагування ОБʼЄКТА: зміни долітають у PATCH і видно після збереження', async ({ page }) => {
  const state = makeState()
  const captured: { propPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible()

  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()

  // Міняємо кілька різнотипних полів: текст, число, ставку експлуатації
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByPlaceholder('47').fill('111')          // корисна площа
  await page.getByPlaceholder('2.5').fill('7.25')        // ставка експлуатаційних
  await page.locator('.fr', { hasText: 'Найменування' }).locator('input').fill('ТОВ «Нова Назва»')

  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await patchReq

  await expect.poll(() => captured.propPatch, { timeout: 10_000 }).toBeTruthy()
  const p = captured.propPatch!
  expect(p.name, 'назва в PATCH').toBe('Офіс 101-А')
  expect(Number(p.area_useful), 'корисна площа в PATCH').toBe(111)
  expect(Number(p.utilities_rate), 'ставка експлуатації в PATCH').toBe(7.25)
  expect(p.tenant_name, 'орендар у PATCH').toBe('ТОВ «Нова Назва»')

  // Збереження з картки списку повертає в СПИСОК, і він показує нову назву
  // (а не стару з SWR-кешу).
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101-А' })).toBeVisible({ timeout: 10_000 })
})

test('редагування БАЗИ: зміни долітають у PATCH', async ({ page }) => {
  const state = makeState()
  const captured: { dbPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible()

  await page.getByLabel('Меню бази').click()
  await page.getByText('Редагувати базу').click()
  await expect(page.getByPlaceholder('БЦ Олімп')).toBeVisible()

  await page.getByPlaceholder('БЦ Олімп').fill('БЦ Рубін Плаза')
  await page.getByPlaceholder(/Хрещатик/).fill('вул. Січових Стрільців, 5')

  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/databases') && r.method() === 'PATCH')
  await page.getByRole('button', { name: /Зберегти/ }).click()
  await patchReq

  await expect.poll(() => captured.dbPatch, { timeout: 10_000 }).toBeTruthy()
  const d = captured.dbPatch!
  expect(d.name, 'назва бази в PATCH').toBe('БЦ Рубін Плаза')
  expect(d.address, 'адреса бази в PATCH').toBe('вул. Січових Стрільців, 5')
})

/**
 * ДЗЕРКАЛО тесту про очищене поле ОБʼЄКТА (нижче). Клас той самий —
 * `JSON.stringify` викидає ключі з `undefined`, тож очищене поле не доїжджає
 * до PATCH, колонка лишається старою, а тост каже «Базу оновлено», — але для
 * БАЗИ гарда не було, і саме там він і вижив: `address` писався через
 * `|| undefined`, тоді як сусідній `landlord_name` уже через `|| null`.
 *
 * Тримати обидві половини поруч обовʼязково: без цієї наступна правка знову
 * розведе форму бази з формою обʼєкта.
 */
test('редагування БАЗИ: очищена адреса долітає як null, а не зникає з PATCH', async ({ page }) => {
  const state = makeState()
  const captured: { dbPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible()

  await page.getByLabel('Меню бази').click()
  await page.getByText('Редагувати базу').click()
  await expect(page.getByPlaceholder('БЦ Олімп')).toBeVisible()

  // Фікстура має непорожню адресу — саме тому очищення тут щось означає.
  await page.getByPlaceholder(/Хрещатик/).fill('')

  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/databases') && r.method() === 'PATCH')
  await page.getByRole('button', { name: /Зберегти/ }).click()
  await patchReq

  await expect.poll(() => captured.dbPatch, { timeout: 10_000 }).toBeTruthy()
  const d = captured.dbPatch!

  // `toBeNull()` тут замало: відсутній ключ теж дає `undefined == null` при
  // нестрогому порівнянні, а саме ВІДСУТНІСТЬ ключа і була дефектом.
  expect(Object.prototype.hasOwnProperty.call(d, 'address'),
    'address: ключ ВІДСУТНІЙ у PATCH — адреса лишиться старою, а тост скаже «Базу оновлено»').toBe(true)
  expect(d.address, 'очищена адреса мусить бути null').toBeNull()
})

test('редагування ОБʼЄКТА зі статусом «зайнято»: ставка експлуатації зберігається', async ({ page }) => {
  // Саме цей кейс користувач ловив як «не зберігається» (area_basis-регресія).
  const state = makeState()
  const captured: { propPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()

  await page.getByPlaceholder('2.5').fill('9.99')
  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await patchReq

  await expect.poll(() => captured.propPatch, { timeout: 10_000 }).toBeTruthy()
  expect(Number(captured.propPatch!.utilities_rate)).toBe(9.99)
  expect(captured.propPatch!.status, 'статус не загубився').toBe('occupied')
  // area_basis мусить бути в payload — без нього бекенд не знає бази розрахунку
  expect(captured.propPatch!).toHaveProperty('area_basis')
})

/**
 * ОЧИЩЕННЯ ПОЛЯ — окремий випадок, і саме він був зламаний.
 *
 * Форма слала порожні опційні поля як `undefined`, а `JSON.stringify` такі
 * ключі ВИКИДАЄ — тобто PATCH їх просто не містив, і колонка лишалась старою.
 * PostgREST повертав 200 з незміненим рядком, стор писав його в кеш, тост казав
 * «Збережено», а після повторного відкриття значення поверталось. Очистити раз
 * заповнене поле було неможливо ВЗАГАЛІ.
 *
 * Три наявні тести вище цього не бачили, бо всі вони ЗАДАЮТЬ значення.
 */
test('редагування ОБʼЄКТА: очищене поле долітає як null, а не зникає з PATCH', async ({ page }) => {
  const state = makeState()
  const captured: { propPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible()

  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()

  // Чистимо різнотипні опційні поля: текстове, числове й ставку.
  await page.locator('.fr', { hasText: 'Поверх' }).locator('input').fill('')
  await page.getByPlaceholder('47').fill('')      // корисна площа
  await page.getByPlaceholder('2.5').fill('')     // ставка експлуатаційних

  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await patchReq

  await expect.poll(() => captured.propPatch, { timeout: 10_000 }).toBeTruthy()
  const p = captured.propPatch!

  // Ключ МУСИТЬ бути присутній зі значенням null. `toBeNull()` тут замало:
  // відсутній ключ теж дає `undefined == null` при нестрогому порівнянні, а
  // саме відсутність і була дефектом.
  for (const col of ['floor', 'area_useful', 'utilities_rate']) {
    expect(Object.prototype.hasOwnProperty.call(p, col),
      `${col}: ключ ВІДСУТНІЙ у PATCH — колонка лишиться старою, а форма скаже «Збережено»`).toBe(true)
    expect(p[col], `${col}: очищене поле мусить бути null`).toBeNull()
  }
})

/**
 * КРУГОВИЙ РЕЙС ПАРКІНГА — тест, що озброює проєкцію `select=`.
 *
 * Дефект, заради якого написано: `PROPERTY_COLUMNS` не містив `parking_type` і
 * `ev_charger`. Форма префілиться з рядка ЦЬОГО select-а, тож вони приходили
 * `undefined` → поля скидались → PATCH писав `null`, а тост казав «Збережено».
 * Створення при цьому працювало, тобто бив дефект саме по редагуванню вже
 * заповненого паркінга.
 *
 * Сам по собі гард `select-columns.test.ts` тримає це джерельно. Тут — друга
 * половина: рантайм. Вона стала МОЖЛИВОЮ лише після того, як харнес почав
 * проєктувати відповідь через `select=`; доти мок віддавав фікстуру цілком, і
 * пропущена колонка була невидима в принципі.
 *
 * Тобто цей тест падає РІВНО тоді, коли колонка зникає зі списку читання —
 * і не падає, коли зникає лише з фікстури.
 */
test('редагування ПАРКІНГА: тип місця і зарядка переживають круговий рейс', async ({ page }) => {
  const state = makeState()
  state.prop = {
    ...state.prop,
    name: 'Місце A-15',
    has_parking: true,
    parking_spaces: 1,
    parking_type: 'underground',
    ev_charger: true,
  } as unknown as typeof state.prop
  // База типу `parking` — саме вона вмикає паркінг-специфічні поля у формі.
  state.db = { ...state.db, type: 'parking' }

  const captured: { propPatch?: Record<string, unknown> } = {}
  await setup(page, state, captured)

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })

  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible({ timeout: 15_000 })

  // Міняємо ЛИШЕ назву. Усе інше має доїхати назад незмінним.
  // Форма адаптується під базу типу `parking`: підпис поля стає «Номер місця».
  await page.getByLabel('Номер місця').fill('Місце A-16')

  const patchReq = page.waitForRequest(r => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await patchReq

  await expect.poll(() => captured.propPatch, { timeout: 15_000 }).toBeTruthy()
  const patch = captured.propPatch!
  expect(patch.name).toBe('Місце A-16')
  expect(patch.parking_type,
    'тип місця стерто: колонки немає в READ-select, тож форма не побачила значення')
    .toBe('underground')
  expect(patch.ev_charger,
    'зарядку стерто: та сама причина — редагування пише те, чого не прочитало')
    .toBe(true)
})
