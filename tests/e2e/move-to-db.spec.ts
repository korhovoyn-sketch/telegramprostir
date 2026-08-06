import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// Перенос обраних обʼєктів в іншу базу (або в нову, створену тут же).
// Ключові інваріанти: db_id/owner_id приймача, folder_id скидається (папка
// належить базі-джерелу), обʼєкти зникають зі списку джерела.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_A = '10000000-0000-0000-0000-00000000000a'
const DB_B = '10000000-0000-0000-0000-00000000000b'
const NOW = new Date().toISOString()

function db(id: string, name: string) {
  return {
    id, owner_id: USER.id, name, address: 'вул. Хрещатик, 1', type: 'business_center',
    color: 'pink', share_token: `token${id.slice(-1)}`.padEnd(22, '0'), share_expires_at: null,
    created_at: NOW, updated_at: NOW, properties: [],
  }
}
const DBS = [db(DB_A, 'БЦ Рубін'), db(DB_B, 'БЦ Сапфір')]

function prop(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_A, owner_id: USER.id,
    name: `Офіс 10${n}`, floor: '2', status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: '40000000-0000-0000-0000-0000000000a1',
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

interface Captured {
  patches: { url: string; body: Record<string, unknown> }[]
  newDb?: Record<string, unknown>
}

async function setup(page: Page, captured: Captured, dbs = DBS) {
  const state = { props: [prop(1), prop(2), prop(3)], dbs: [...dbs] }
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/databases**', (r) => {
    const rq = r.request()
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      captured.newDb = body
      const created = { ...db(DB_B, String(body.name)), ...body, id: '10000000-0000-0000-0000-00000000000c' }
      state.dbs.push(created)
      return jsonRoute(r, wantsObject ? created : [created])
    }
    if (wantsObject) {
      const m = rq.url().match(/id=eq\.([0-9a-f-]+)/)
      return jsonRoute(r, state.dbs.find((d) => d.id === m?.[1]) ?? state.dbs[0])
    }
    return jsonRoute(r, state.dbs)
  })

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      captured.patches.push({ url: decodeURIComponent(rq.url()), body })
      // Перенос застосовуємо до стану, щоб база-джерело справді спорожніла
      const ids = decodeURIComponent(rq.url()).match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      state.props = state.props.map((p) => (ids.includes(p.id) ? { ...p, ...body } : p))
      return jsonRoute(r, [])
    }
    if (rq.method() !== 'GET') return r.fallback()
    const url = decodeURIComponent(rq.url())
    const wantsObject = (rq.headers()['accept'] ?? '').includes('object')
    const target = url.match(/db_id=eq\.([0-9a-f-]+)/)?.[1]
    let rows = target ? state.props.filter((p) => p.db_id === target) : state.props
    // Мінімальна повага до order/limit: запит «максимальний sort_order приймача»
    // інакше повернув би ПЕРШИЙ рядок, і перевірка порядку стала б безглуздою.
    if (url.includes('order=sort_order.desc')) {
      rows = [...rows].sort((a, b) => (b.sort_order ?? 0) - (a.sort_order ?? 0))
    }
    const limit = url.match(/limit=(\d+)/)?.[1]
    if (limit) rows = rows.slice(0, Number(limit))
    return jsonRoute(r, wantsObject ? rows[0] : rows)
  })

  await page.route('**/rest/v1/property_folders**', (r) => jsonRoute(r, [{
    id: '40000000-0000-0000-0000-0000000000a1', db_id: DB_A, owner_id: USER.id,
    name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW,
  }]))
  for (const t of ['property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

async function selectTwo(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible({ timeout: 15_000 })

  await page.getByLabel('Меню бази').click()
  await page.getByText('Виділити об\'єкти').click()
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).locator('.obj-t').click()
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await expect(page.getByText('2 обрано')).toBeVisible()
}

test('перенос обраних у ІНШУ базу: db_id/owner_id приймача, папку скинуто', async ({ page }) => {
  const captured: Captured = { patches: [] }
  await setup(page, captured)
  await selectTwo(page)

  await page.getByRole('button', { name: /В базу/ }).click()
  await expect(page.getByText('Перенести в базу')).toBeVisible()
  await expect(page.getByText(/2 об.єкти буде переміщено/)).toBeVisible()
  // Поточної бази у списку приймачів бути не повинно
  await expect(page.locator('.sheet-row', { hasText: 'БЦ Рубін' })).toHaveCount(0)
  await page.locator('.sheet-row', { hasText: 'БЦ Сапфір' }).click()

  await expect.poll(() => captured.patches.length, { timeout: 10_000 }).toBeGreaterThan(0)
  const move = captured.patches[0]
  expect(move.body.db_id, 'нова база').toBe(DB_B)
  expect(move.body.owner_id, 'власник бази-приймача').toBe(USER.id)
  expect(move.body.folder_id, 'папка джерела скинута').toBeNull()
  expect(move.url, 'патчиться саме вибрана пара').toContain('id=in.')
  expect(move.url).toContain('20000000-0000-0000-0000-000000000001')
  expect(move.url).toContain('20000000-0000-0000-0000-000000000002')

  // Джерело спорожніло до одного обʼєкта, тост пропонує відкрити приймача
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Відкрити' }).click()
  await expect(page.locator('.hdr-t')).toContainText('БЦ Сапфір', { timeout: 10_000 })
})

test('нова база з обраних: створюється і одразу отримує обʼєкти', async ({ page }) => {
  const captured: Captured = { patches: [] }
  await setup(page, captured, [DBS[0]])
  await selectTwo(page)

  await page.getByRole('button', { name: /В базу/ }).click()
  await expect(page.getByText('Інших баз ще немає')).toBeVisible()
  await page.getByRole('button', { name: /Нова база з обраних/ }).click()
  await page.locator('.fold-mng-input').fill('БЦ Новий')
  await page.getByRole('button', { name: 'Створити', exact: true }).click()

  await expect.poll(() => captured.newDb, { timeout: 10_000 }).toBeTruthy()
  expect(captured.newDb!.name).toBe('БЦ Новий')
  // Тип і колір успадковані від бази-джерела — форма обʼєкта залежить від типу
  expect(captured.newDb!.type).toBe('business_center')
  expect(captured.newDb!.color).toBe('pink')

  await expect.poll(() => captured.patches.length, { timeout: 10_000 }).toBeGreaterThan(0)
  expect(captured.patches[0].body.db_id).toBe('10000000-0000-0000-0000-00000000000c')
  expect(captured.patches[0].body.folder_id).toBeNull()
})

test('перенос ставить sort_order у КІНЕЦЬ бази-приймача', async ({ page }) => {
  const captured: Captured = { patches: [] }
  await setup(page, captured)
  await selectTwo(page)

  await page.getByRole('button', { name: /В базу/ }).click()
  await page.locator('.sheet-row', { hasText: 'БЦ Сапфір' }).click()

  // Перший PATCH — сам перенос; далі по одному на порядок
  await expect.poll(() => captured.patches.length, { timeout: 10_000 }).toBe(3)
  const orders = captured.patches.slice(1).map((p) => Number(p.body.sort_order))
  expect(orders, 'номери зростають і не нульові').toEqual([300, 400])
})
