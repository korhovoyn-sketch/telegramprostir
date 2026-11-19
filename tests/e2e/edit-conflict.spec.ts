import { test, expect, type Page, type Request } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, objectAction } from './helpers/harness'

/**
 * ВТРАЧЕНЕ ОНОВЛЕННЯ НА ФОРМІ РЕДАГУВАННЯ — і чому гард живе на ДРОТІ.
 *
 * Форма шле в PATCH усі ~25 полів зі стану, знятого при відкритті. Якщо колега
 * тим часом змінив обʼєкт, пізніше збереження мовчки повертає його зміни. Тепер
 * PATCH несе `updated_at=eq.<мітка з відкриття>`, а сервер (мок моделює
 * PostgREST) на розбіжність віддає 0 рядків — PGRST116.
 *
 * Мітка в фікстурі навмисно у ФОРМАТІ POSTGREST (мікросекунди і `+00:00`):
 * саме `+` у query ламається, якщо його не закодувати, а мікросекунди
 * губляться, якщо мітку прогнати через Date. Тест читає значення так, як
 * його побачив би сервер — із декодованого URL.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()
const T1 = '2026-11-01T10:00:00.123456+00:00'
const T2 = '2026-11-01T10:05:00.654321+00:00'

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
  created_at: NOW, updated_at: T1, photos: [],
}

// `description` у фікстурі `null`, а колега може його заповнити — тип мусить це дозволяти.
type Row = Omit<typeof PROP, 'description'> & { description: string | null }
type Patch = { precondition: string | null; body: Record<string, unknown>; applied: boolean }

/**
 * «Сервер»: PATCH з передумовою `updated_at` застосовується лише якщо вона
 * збігається з поточною міткою рядка; інакше — 406 PGRST116, як віддає
 * PostgREST на `.single()` без рядків. `denyAll` моделює відмову RLS: нуль
 * рядків при ТІЙ САМІЙ мітці.
 */
function makeServer(opts: { denyAll?: boolean } = {}) {
  const state = { prop: { ...PROP } as Row, patches: [] as Patch[] }
  const handler = async (page: Page) => {
    await setupApp(page, { user: USER })
    await page.route('**/rest/v1/databases**', (r) =>
      jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
    await page.route('**/rest/v1/properties**', (r) => {
      const rq: Request = r.request()
      if (rq.method() === 'PATCH') {
        const pre = new URL(rq.url()).searchParams.get('updated_at')
        const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
        const expected = `eq.${state.prop.updated_at}`
        const applied = !opts.denyAll && (pre === null || pre === expected)
        state.patches.push({ precondition: pre, body, applied })
        if (!applied) {
          return r.fulfill({
            status: 406,
            contentType: 'application/json',
            headers: { 'access-control-allow-origin': '*' },
            body: JSON.stringify({
              code: 'PGRST116', details: 'The result contains 0 rows', hint: null,
              message: 'Cannot coerce the result to a single JSON object',
            }),
          })
        }
        state.prop = { ...state.prop, ...body } as Row
        return jsonRoute(r, state.prop)
      }
      if (rq.method() !== 'GET') return r.fallback()
      const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? state.prop : [state.prop])
    })
    for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members']) {
      await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
    }
    await page.addInitScript(() =>
      localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
  }
  return { state, handler }
}

async function openEditForm(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible()
  // Префіл відбувся: інакше нижче «зберегли» б порожню форму.
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Офіс 101')
}

test('збереження без чужих правок: PATCH несе мітку з відкриття, і вона дожила рядком', async ({ page }) => {
  const { state, handler } = makeServer()
  await handler(page)
  await openEditForm(page)

  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  await expect.poll(() => state.patches.length, { timeout: 10_000 }).toBe(1)
  // Антивакуум: без цієї перевірки «конфлікту немає» проходило б і тоді, коли
  // передумови в запиті немає взагалі. `+` і мікросекунди — повні, не обрізані.
  expect(state.patches[0].precondition).toBe(`eq.${T1}`)
  expect(state.patches[0].applied).toBe(true)
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101-А' })).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Обʼєкт змінили в іншому місці')).toHaveCount(0)
})

test('колега змінив обʼєкт, поки форма була відкрита: конфлікт, форма лишається, перезапис — свідомий', async ({ page }) => {
  const { state, handler } = makeServer()
  await handler(page)
  await openEditForm(page)

  // Колега зберіг свою правку ПІСЛЯ того, як форма прочитала рядок.
  state.prop = { ...state.prop, description: 'Правка колеги', updated_at: T2 }

  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  // Повідомлення про конфлікт, а не про «помилку»; форма не закрилась.
  await expect(page.getByText('Обʼєкт змінили в іншому місці')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Редагування')).toBeVisible()
  expect(state.patches).toHaveLength(1)
  expect(state.patches[0].precondition).toBe(`eq.${T1}`)
  expect(state.patches[0].applied).toBe(false)
  // Чужа правка на сервері ЦІЛА: перший запис не перезаписав нічого.
  expect(state.prop.description).toBe('Правка колеги')
  expect(state.prop.name).toBe('Офіс 101')

  // Дія «Перезаписати» зберігає ще раз — з НОВОЮ міткою, тобто свідомо.
  await page.getByRole('button', { name: 'Перезаписати' }).click()
  await expect.poll(() => state.patches.length, { timeout: 10_000 }).toBe(2)
  expect(state.patches[1].precondition).toBe(`eq.${T2}`)
  expect(state.patches[1].applied).toBe(true)
  expect(state.prop.name).toBe('Офіс 101-А')
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101-А' })).toBeVisible({ timeout: 10_000 })
})

test('після конфлікту дія тоста бере ПОТОЧНІ значення полів, а не ті, що були на момент конфлікту', async ({ page }) => {
  const { state, handler } = makeServer()
  await handler(page)
  await openEditForm(page)

  state.prop = { ...state.prop, updated_at: T2 }
  await page.getByPlaceholder('Офіс 101').fill('Перша назва')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()
  await expect(page.getByText('Обʼєкт змінили в іншому місці')).toBeVisible({ timeout: 10_000 })

  // Користувач править далі, ПОКИ тост ще на екрані, і лише тоді тисне дію.
  await page.getByPlaceholder('Офіс 101').fill('Друга назва')
  await page.getByRole('button', { name: 'Перезаписати' }).click()

  await expect.poll(() => state.patches.length, { timeout: 10_000 }).toBe(2)
  expect(state.patches[1].body.name, 'дія тоста не має слати застарілу назву').toBe('Друга назва')
})

test('відмова RLS (0 рядків, мітка та сама) — НЕ конфлікт: перезаписувати нічого', async ({ page }) => {
  const { state, handler } = makeServer({ denyAll: true })
  await handler(page)
  await openEditForm(page)

  await page.getByPlaceholder('Офіс 101').fill('Офіс 101-А')
  await page.getByRole('button', { name: 'Зберегти зміни' }).click()

  // Заблокований запис показує ПОМИЛКУ. Хибне «обʼєкт змінили» штовхало б
  // людину перезаписувати там, де запис їй взагалі не дозволено.
  await expect(page.locator('.toast.err')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('Обʼєкт змінили в іншому місці')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Перезаписати' })).toHaveCount(0)
  expect(state.patches).toHaveLength(1)
})
