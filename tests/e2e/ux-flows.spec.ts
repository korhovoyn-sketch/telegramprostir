import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Workflow tests for the UX package ─────────────────────────────────────────
// Optimistic status change + undo, rollback on failure, drafts, duplicate,
// SWR cold-start cache, native MainButton, bulk name-collision skipping.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, rent_type: 'per_m2',
    rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
    parking_type: null, ev_charger: false,
    utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01' }),
  prop(2, {}),
  prop(3, {}),
]

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    const accept = req.headers()['accept'] ?? ''
    if (req.method() === 'GET' && accept.includes('object')) {
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      return json(route, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    if (req.method() === 'GET') return json(route, PROPERTIES)
    return route.fallback()
  })
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openDetail(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
  await page.locator('.obj-card', { hasText: 'Офіс 101' }).click()
  await expect(page.getByText('Назад', { exact: true }).first()).toBeVisible()
}

test('optimistic free: instant status flip, undo restores the tenant', async ({ page }) => {
  await fixtures(page)
  const patches: Record<string, unknown>[] = []
  await page.route('**/rest/v1/properties?id=eq.*', (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    const body = JSON.parse(route.request().postData() ?? '{}')
    patches.push(body)
    return json(route, { ...PROPERTIES[0], ...body })
  })

  await openDetail(page)
  await page.getByRole('button', { name: "Звільнити об'єкт" }).click()

  // Instant optimistic flip: the CTA becomes «Здати в оренду» without waiting
  await expect(page.getByRole('button', { name: 'Здати в оренду' })).toBeVisible()
  await expect.poll(() => patches.length).toBe(1)
  expect(patches[0].status).toBe('free')
  expect(patches[0].tenant_name).toBeNull()

  // Undo from the toast restores the previous tenant + lease fields
  await page.locator('.toast-act', { hasText: 'Скасувати' }).click()
  await expect(page.getByRole('button', { name: "Звільнити об'єкт" })).toBeVisible()
  await expect.poll(() => patches.length).toBe(2)
  expect(patches[1].status).toBe('occupied')
  expect(patches[1].tenant_name).toBe('ТОВ «Ромашка»')
  expect(patches[1].lease_start_date).toBe('2025-01-01')
})

test('optimistic free: server failure rolls the status back with an error toast', async ({ page }) => {
  await fixtures(page)
  await page.route('**/rest/v1/properties?id=eq.*', async (route) => {
    if (route.request().method() !== 'PATCH') return route.fallback()
    // Delay the failure so the optimistic window is reliably observable —
    // an instant 500 can roll back before the first assertion polls.
    await new Promise(r => setTimeout(r, 400))
    return json(route, { message: 'boom' }, 500)
  })

  await openDetail(page)
  await page.getByRole('button', { name: "Звільнити об'єкт" }).click()
  // Optimistic flip happens first…
  await expect(page.getByRole('button', { name: 'Здати в оренду' })).toBeVisible()
  // …then the failed PATCH rolls it back and explains itself
  await expect(page.getByText('Не збереглося — повернуто як було')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByRole('button', { name: "Звільнити об'єкт" })).toBeVisible()
})

test('draft: typed input survives leaving the form and can be discarded', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  await page.getByPlaceholder('Офіс 101').fill('Недописаний офіс')
  await page.waitForTimeout(900) // debounce 600ms

  // Leave without saving, come back
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()

  await expect(page.getByText('Чернетку відновлено')).toBeVisible()
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Недописаний офіс')

  // «Очистити» discards the draft and resets the form
  await page.locator('.toast-act', { hasText: 'Очистити' }).click()
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('')
})

test('duplicate: opens the form prefilled with the next free name, tenant not copied', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()

  await page.locator('.obj-card', { hasText: 'Офіс 101' })
    .getByRole('button', { name: 'Дублювати' }).click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  // 101..103 taken → the copy becomes 104; fields copied, tenant NOT
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Офіс 104')
  await expect(page.locator('.fr-seg-b.on', { hasText: 'Вільно' })).toBeVisible()
})

test('SWR: db list paints from the local snapshot even when the network is down', async ({ page }) => {
  await fixtures(page)
  // Seed the snapshot a cold start would read, then kill the GET
  await page.addInitScript(({ userId, db }) => {
    localStorage.setItem(
      `snap_v1:${userId}:databases`,
      JSON.stringify({ t: Date.now(), data: [{ ...db, _property_count: 3, _free_count: 2, _occupied_count: 1, _monthly_income: 1800 }] }),
    )
  }, { userId: USER.id, db: DB })
  await page.route('**/rest/v1/databases**', (route) => route.abort('failed'))

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  // The list is there — served from cache despite the dead network
  await expect(page.getByText('БЦ Рубін')).toBeVisible()
})

test('native MainButton drives the form when Telegram provides one', async ({ page }) => {
  await fixtures(page)
  // Attach a MainButton to the harness Telegram stub (runs after its init script)
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const wa = (window as any).Telegram?.WebApp
    if (!wa) return
    wa.MainButton = {
      text: '', isVisible: false, _cb: null, _params: null,
      setText(t: string) { this.text = t },
      setParams(p: Record<string, unknown>) { this._params = p },
      show() { this.isVisible = true }, hide() { this.isVisible = false },
      enable() {}, disable() {}, showProgress() {}, hideProgress() {},
      onClick(f: () => void) { this._cb = f }, offClick() { this._cb = null },
    }
  })
  let posted: Record<string, unknown> | null = null
  await page.route('**/rest/v1/properties**', (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    posted = JSON.parse(route.request().postData() ?? '{}')
    return json(route, { ...PROPERTIES[1], ...posted }, 201)
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  // Native button takes over → the DOM fallback is gone
  await expect(page.getByRole('button', { name: "Додати об'єкт", exact: true })).toHaveCount(0)
  await page.getByPlaceholder('Офіс 101').fill('Офіс 200')
  await expect.poll(() => page.evaluate(() =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).Telegram.WebApp.MainButton.text
  )).toBe("Додати об'єкт")

  // Clicking the native button submits the form
  await page.evaluate(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram.WebApp.MainButton._cb?.()
  })
  await expect.poll(() => posted, { timeout: 10_000 }).not.toBeNull()
  expect(posted!.name).toBe('Офіс 200')
})

test('bulk: name run skips names that already exist in the database', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  // 101, 102, 103 exist → the run must jump to 104
  await page.getByPlaceholder('Офіс 101').fill('Офіс 101')
  await page.getByLabel("Більше об'єктів").click()
  await page.getByLabel("Більше об'єктів").click()
  await expect(page.getByText('Буде створено')).toBeVisible()
  for (const n of ['Офіс 104', 'Офіс 105', 'Офіс 106']) {
    await expect(page.getByPlaceholder(n, { exact: true })).toBeVisible()
  }
})

test('bulk: per-row areas and a name override land in the INSERT; empty rows fall back', async ({ page }) => {
  await fixtures(page)
  let postBody: Record<string, unknown>[] | null = null
  await page.route('**/rest/v1/properties**', (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    postBody = JSON.parse(route.request().postData() ?? '[]')
    const rows = (postBody ?? []).map((b, i) => ({ ...PROPERTIES[1], ...b, id: `20000000-0000-0000-0000-00000000020${i}`, photos: [] }))
    return json(route, rows, 201)
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  await page.getByPlaceholder('Офіс 101', { exact: true }).fill('Офіс 201')
  await page.getByLabel("Більше об'єктів").click()
  await page.getByLabel("Більше об'єктів").click() // count = 3

  // Shared «Площа» acts as the fallback for rows that leave theirs empty
  await page.getByPlaceholder('47', { exact: true }).fill('40')

  // Row 1: own areas; row 2: name override + own useful area; row 3: untouched
  await page.getByLabel("Корисна площа об'єкта 1").fill('45')
  await page.getByLabel("Загальна площа об'єкта 1").fill('52')
  await page.getByLabel("Назва об'єкта 2").fill('Кабінет 5')
  await page.getByLabel("Корисна площа об'єкта 2").fill('62')

  await page.getByRole('button', { name: "Додати 3 об'єкти" }).click()
  await expect.poll(() => postBody, { timeout: 10_000 }).not.toBeNull()

  const rows = postBody!
  expect(rows.map(r => r.name)).toEqual(['Офіс 201', 'Кабінет 5', 'Офіс 203'])
  expect(rows.map(r => r.area_useful)).toEqual([45, 62, 40])
  expect(rows[0].area_total).toBe(52)
  // Deterministic in-batch order: sequential sort_order past the current max (300)
  expect(rows.map(r => r.sort_order)).toEqual([400, 500, 600])
})

test('bulk: a duplicated manual name is rejected with a clear toast', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  await page.getByPlaceholder('Офіс 101', { exact: true }).fill('Офіс 201')
  await page.getByLabel("Більше об'єктів").click()
  // Manual override collides with the existing «Офіс 102»
  await page.getByLabel("Назва об'єкта 2").fill('Офіс 102')

  await page.getByRole('button', { name: "Додати 2 об'єкти" }).click()
  await expect(page.getByText('Ім\'я повторюється')).toBeVisible()
})
