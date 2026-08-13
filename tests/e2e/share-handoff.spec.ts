import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession, skipCoachmarks } from './helpers/harness'

// Наскрізна передача доступу: власник → рієлтор → ВІДКЛИКАННЯ.
//
// Чому саме це найважливіший гард релізу. `share-flow.spec.ts` перевіряє, що
// власник натиснув «Оновити посилання» і полетів RPC `rotate`. Але жоден тест
// не перевіряв ДРУГИЙ бік: чи справді той, кому лінк уже роздали, втрачає
// доступ. Тобто ротація могла бути повним no-op для вже підписаних рієлторів, і
// весь набір лишався б зеленим — а власник був би впевнений, що доступ закрито.
//
// Тут перевіряються обидва боки як одна історія.

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, id: '00000000-0000-0000-0000-000000000001' }
const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, id: '00000000-0000-0000-0000-000000000002', tg_id: 444555666 }

const DB_ID = '10000000-0000-0000-0000-000000000001'
const OLD_TOKEN = 'aabbccddeeff001122334455'
const NEW_TOKEN = 'ffee0011223344556677aabb'
const NOW = new Date().toISOString()

function db(token: string, expiresAt: string | null = null) {
  return {
    id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
    type: 'business_center', color: 'pink', share_token: token, share_expires_at: expiresAt,
    created_at: NOW, updated_at: NOW, properties: [],
  }
}

const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: OWNER.id,
  name: 'Офіс 101', floor: '2', status: 'free', area_useful: 45, area_total: 52,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: null, description: null, address: null, sale_price: null,
  tenant_name: null, lease_start_date: null, lease_end_date: null,
  sort_order: 100, share_token: 'bb00000000000000000001', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [],
}

const json = (r: Route, b: unknown) => jsonRoute(r, b)

// ─── Бік ВЛАСНИКА ────────────────────────────────────────────────────────────

test('власник: ротація змінює токен, і QR показує вже НОВИЙ', async ({ page }) => {
  const calls: Record<string, unknown>[] = []
  let token = OLD_TOKEN

  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return json(r, wantsObject ? db(token) : [db(token)])
  })
  await page.route('**/rest/v1/properties**', (r) => json(r, [PROP]))
  await page.route('**/rest/v1/property_views**', (r) => json(r, []))
  for (const t of ['db_members', 'rent_payments', 'property_folders', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.route('**/rest/v1/rpc/manage_share', (r) => {
    const body = JSON.parse(r.request().postData() ?? '{}')
    calls.push(body)
    if (body.p_action === 'rotate') token = NEW_TOKEN
    return json(r, [{ share_token: token, share_expires_at: null, error: null }])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText('Аналітика бази')).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: 'Поділитися' }).click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(450)

  // До ротації лінк несе старий токен.
  await expect(page.locator('.modal')).toContainText(OLD_TOKEN)

  await page.getByRole('button', { name: /Оновити посилання/ }).click()
  // Скоуп на діалог підтвердження за його заголовком: у самому шиті теж є
  // кнопка «Оновити посилання», тож `/Оновити/` по всьому DOM неоднозначне.
  await page.locator('.modal', { hasText: 'Оновити посилання?' })
    .getByRole('button', { name: /^Оновити$/ }).click()
  await page.waitForTimeout(900)

  expect(calls.some((c) => c.p_action === 'rotate'), 'ротація мусить полетіти').toBe(true)
  // І показане посилання МУСИТЬ оновитись — інакше власник роздасть мертвий лінк.
  await expect(page.locator('.modal')).toContainText(NEW_TOKEN)
  await expect(page.locator('.modal')).not.toContainText(OLD_TOKEN)
})

// ─── Бік ОДЕРЖУВАЧА ──────────────────────────────────────────────────────────

/** Рієлтор відкриває db_-лінк; RPC вирішує, чи токен ще живий. */
async function realtorOpensLink(page: Page, token: string, rpcAnswer: Record<string, unknown>) {
  await setupApp(page, { user: REALTOR, startParam: `db_${token}` })
  await seedSession(page, { ...REALTOR })
  await page.route('**/rest/v1/rpc/subscribe_to_shared_db', (r) => json(r, [rpcAnswer]))
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, []))
  await page.route('**/rest/v1/db_members**', (r) => json(r, []))
  await page.route('**/rest/v1/databases**', (r) => {
    const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
    return json(r, wantsObject ? db(token) : [db(token)])
  })
  await page.route('**/rest/v1/properties**', (r) => json(r, [PROP]))
  for (const t of ['rent_payments', 'property_folders', 'notifications', 'property_views']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.goto('/')
}

test('рієлтор: живий лінк дає підписку і доступ до бази', async ({ page }) => {
  await realtorOpensLink(page, OLD_TOKEN, { db_id: DB_ID, db_name: 'БЦ Рубін', error: null })
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 101').first()).toBeVisible()
})

test('рієлтор: ВІДКЛИКАНИЙ лінк не дає доступу і пояснює причину', async ({ page }) => {
  // Головний гард. Після revoke/rotate сервер більше не знаходить токен, і
  // одержувач мусить лишитись БЕЗ бази — з поясненням, а не з порожнім екраном.
  await realtorOpensLink(page, OLD_TOKEN, { db_id: null, db_name: null, error: 'not_found' })

  await expect(page.locator('.toast')).toBeVisible({ timeout: 20_000 })
  // У базу не провалились.
  await expect(page.getByText('Офіс 101')).toHaveCount(0)
})

test('публічна /v зі старим токеном після відкликання — мертва', async ({ page }) => {
  // Другий канал доступу: навіть без Telegram старий лінк не має відкривати дані.
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, []))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, null))
  await page.goto(`/v/?db=${OLD_TOKEN}`)

  // `.first()`: заголовок і пояснення обидва містять слова про недійсність.
  await expect(page.getByText(/недійсн|не знайдено|застаріло/i).first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 101')).toHaveCount(0)
})
