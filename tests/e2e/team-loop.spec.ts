import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession, skipCoachmarks } from './helpers/harness'

// Замикання циклу команди.
//
// `team.spec.ts` перевіряє створення інвайта, його відкликання і гілки клейму.
// Але дві ланки лишались недоведеними:
//   1) власник ніколи не бачив КЛЕЙМНУТОГО учасника у своєму списку — тобто
//      «запросив» і «в команді» ніде не змикались;
//   2) «редактор має доступ» стверджувалось ВИДИМІСТЮ КНОПОК, а не жодним
//      реальним записом. Кнопка може бути на місці, а PATCH — не полетіти.
// Тут закривається саме це.

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, id: '00000000-0000-0000-0000-000000000001' }
const EDITOR = { ...DEFAULT_USER, role: 'realtor' as const, id: '00000000-0000-0000-0000-000000000077', tg_id: 777888999 }

const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
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

function member(status: string, claimed: boolean) {
  return {
    id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID,
    user_id: claimed ? EDITOR.id : null, role: 'editor',
    invite_token: 'dd00112233445566778899', label: 'Менеджер',
    member_name: claimed ? 'Оля Петренко' : null,
    status, claimed_at: claimed ? NOW : null, created_at: NOW,
  }
}

test('власник БАЧИТЬ клейнутого учасника у списку команди', async ({ page }) => {
  // Ланка, якої бракувало: інвайт «pending» перетворюється на активного члена
  // з іменем — тобто цикл «запросив → приєднався» справді змикається.
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, [PROP]))
  await page.route('**/rest/v1/db_members**', (r) => {
    // Запит useDatabases (по user_id) — не члени, а власні членства.
    if (r.request().url().includes('user_id=eq.')) return jsonRoute(r, [])
    return jsonRoute(r, [member('active', true)])
  })
  for (const t of ['rent_payments', 'property_folders', 'notifications', 'property_views', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Команда', { exact: true }).click()

  // Імʼя приходить із `member_name` (власник не може прочитати чужий users-рядок
  // під RLS, тож `claim_team_invite` копіює його в момент клейму).
  await expect(page.getByText('Оля Петренко')).toBeVisible({ timeout: 15_000 })
})

test('редактор робить РЕАЛЬНИЙ запис у чужу базу, а не лише бачить кнопки', async ({ page }) => {
  const patches: Record<string, unknown>[] = []

  await setupApp(page, { user: EDITOR })
  await seedSession(page, { ...EDITOR })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      patches.push(body)
      return jsonRoute(r, [{ ...PROP, ...body }])
    }
    if ((rq.headers()['accept'] ?? '').includes('object')) return jsonRoute(r, PROP)
    return jsonRoute(r, [PROP])
  })
  await page.route('**/rest/v1/db_members**', (r) =>
    jsonRoute(r, [{ ...member('active', true), database: DB }]))
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => jsonRoute(r, []))
  for (const t of ['rent_payments', 'property_folders', 'notifications', 'property_views',
                   'guest_links', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  // Домашній екран рієлтора — дашборд; member-база веде в повноцінний db-objects.
  await expect(page.getByText('Команда').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })

  // Здаємо обʼєкт в оренду — це справжня мутація, доступна редактору.
  await page.locator('.obj-t').first().click()
  await expect(page.getByRole('button', { name: /Здати в оренду/ })).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Здати в оренду/ }).first().click()
  // Оренда — повноекранний маршрут (фаза 5), а не шит.
  await expect(page.getByLabel('Орендар')).toBeVisible({ timeout: 15_000 })

  await page.getByLabel('Орендар').fill('ТОВ «Ромашка»')
  await page.getByRole('button', { name: 'Здати в оренду', exact: true }).click()
  await expect.poll(() => patches.length, { timeout: 15_000 }).toBeGreaterThan(0)

  const patch = patches[patches.length - 1]
  expect(patch.status, 'редактор реально змінює статус обʼєкта').toBe('occupied')
  expect(patch.tenant_name).toBe('ТОВ «Ромашка»')
})

test('відкликаний редактор більше не потрапляє в базу', async ({ page }) => {
  // Дзеркало попереднього: після revoke членство не активне, база не приходить
  // у список — і в неї немає входу з домашнього екрана.
  await setupApp(page, { user: EDITOR })
  await seedSession(page, { ...EDITOR })
  await page.route('**/rest/v1/db_members**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, []))
  for (const t of ['rent_payments', 'property_folders', 'notifications', 'property_views']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText(/Немає підписок|Відскануй QR/).first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('БЦ Рубін')).toHaveCount(0)
})
