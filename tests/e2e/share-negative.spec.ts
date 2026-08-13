import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ShareSheet: шляхи ВІДМОВИ й реактивація мертвого лінка.
//
// `share-flow.spec.ts` покриває щасливі шляхи всіх чотирьох дій. Тут — те, чого
// там немає: відмова бекенда (RPC каже `forbidden`, або HTTP 403) і
// `askRevive` — окреме підтвердження на оживлення відкликаного посилання.
//
// Чому askRevive узагалі існує: `revoke` ставить лише `share_expires_at = now()`,
// але ТОКЕН лишається. Тобто будь-який `set_expiry`/`clear_expiry` після
// відкликання воскрешає доступ УСІМ, хто зберіг старе посилання — непомітно для
// власника. Саме тому пресет терміну на мертвому лінку не має спрацьовувати
// одразу.

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()
const PAST = new Date(Date.now() - 86_400_000).toISOString()

function makeDb(expiresAt: string | null) {
  return {
    id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
    type: 'business_center', color: 'pink',
    share_token: 'aabbccddeeff001122334455', share_expires_at: expiresAt,
    created_at: NOW, updated_at: NOW, properties: [],
  }
}

interface Opts {
  /** Термін дії лінка; PAST → лінк мертвий. */
  expiresAt?: string | null
  /** RPC відповідає структурованою відмовою. */
  rpcError?: string
  /** RPC падає транспортом (403). */
  httpStatus?: number
}

const json = (route: Route, body: unknown) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

async function setup(page: Page, calls: Record<string, unknown>[], opts: Opts = {}) {
  const db = makeDb(opts.expiresAt ?? null)
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? db : [db])
  })
  await page.route('**/rest/v1/properties**', (route) => json(route, []))
  await page.route('**/rest/v1/property_views**', (route) => json(route, []))
  for (const t of ['db_members', 'rent_payments', 'property_folders', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (route) => json(route, []))
  }

  await page.route('**/rest/v1/rpc/manage_share', (route) => {
    calls.push(JSON.parse(route.request().postData() ?? '{}'))
    if (opts.httpStatus) {
      return route.fulfill({
        status: opts.httpStatus, contentType: 'application/json',
        body: JSON.stringify({ code: '42501', message: 'permission denied' }),
      })
    }
    if (opts.rpcError) {
      return json(route, [{ share_token: null, share_expires_at: null, error: opts.rpcError }])
    }
    return json(route, [{ share_token: db.share_token, share_expires_at: db.share_expires_at, error: null }])
  })

  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openShareSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (0)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText('Аналітика бази')).toBeVisible()
  await page.getByRole('button', { name: 'Поділитися' }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(450)
}

test('RPC каже forbidden — шит лишається живим і показує помилку', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  await setup(page, calls, { rpcError: 'forbidden' })
  await openShareSheet(page)

  await page.getByRole('button', { name: '7 днів' }).click()
  await page.waitForTimeout(900)

  expect(calls.some((c) => c.p_action === 'set_expiry'), 'виклик мусив полетіти').toBe(true)
  await expect(page.locator('.toast')).toBeVisible()
  // Шит НЕ закривається на помилці — користувач має бачити, що стан не змінився.
  await expect(page.locator('.modal')).toBeVisible()
})

test('HTTP 403 на RPC не вбиває екран', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  await setup(page, calls, { httpStatus: 403 })
  await openShareSheet(page)

  await page.getByRole('button', { name: '30 днів' }).click()
  await page.waitForTimeout(900)

  await expect(page.locator('.toast')).toBeVisible()
  await expect(page.locator('.modal')).toBeVisible()
  // ErrorBoundary не спіймав екран.
  await expect(page.getByText(/Щось пішло не так/)).toHaveCount(0)
})

test('мертвий лінк: пресет терміну ВИМАГАЄ окремого підтвердження', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  await setup(page, calls, { expiresAt: PAST })
  await openShareSheet(page)

  await page.getByRole('button', { name: '7 днів' }).click()
  await page.waitForTimeout(500)

  // Замість негайного set_expiry — підтвердження про воскресіння старого лінка.
  await expect(page.getByText('Активувати старе посилання?')).toBeVisible()
  expect(calls.length, 'до підтвердження жодного RPC бути не має').toBe(0)
})

test('мертвий лінк: відмова від підтвердження не оживляє доступ', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  await setup(page, calls, { expiresAt: PAST })
  await openShareSheet(page)

  await page.getByRole('button', { name: '7 днів' }).click()
  await expect(page.getByText('Активувати старе посилання?')).toBeVisible()
  await page.locator('.modal').last().getByRole('button', { name: /Скасувати/ }).click()
  await page.waitForTimeout(600)

  expect(calls.length, 'скасування = жодного RPC').toBe(0)
})

test('мертвий лінк: підтвердження оживляє саме тим пресетом, який натиснули', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  await setup(page, calls, { expiresAt: PAST })
  await openShareSheet(page)

  await page.getByRole('button', { name: '30 днів' }).click()
  await expect(page.getByText('Активувати старе посилання?')).toBeVisible()
  await page.locator('.modal').last().getByRole('button', { name: /Активувати старе/ }).click()
  await page.waitForTimeout(900)

  const call = calls.find((c) => c.p_action === 'set_expiry')
  expect(call, 'після підтвердження RPC мусить полетіти').toBeTruthy()
  expect(call!.p_days, 'саме натиснутий пресет, а не дефолт').toBe(30)
})
