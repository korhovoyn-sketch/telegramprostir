import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// `GuestDatabaseScreen` — задеплоєний екран БЕЗ жодного тесту.
//
// Це перший екран, який бачить людина без сесії, що прийшла по чужому лінку:
// Splash веде сюди і `db_`, і `guest_` (див. no-session гілку SplashScreen).
// Тобто це найперша точка контакту з застосунком для запрошеного — і саме вона
// не була покрита нічим.
//
// Екран має ДВА режими на одному компоненті:
//   • guestMode → RPC `get_guest_property_preview` (гостьове запрошення);
//   • без нього → RPC `get_public_db_preview` (рієлторський превʼю бази).
// Кожен зі своїм набором відмов, і саме відмови тут найважливіші: помилка на
// цьому екрані означає, що людина не потрапить у застосунок узагалі.

const NOW = new Date().toISOString()
const TOKEN = 'cc00112233445566778899aa'

/** Рядок публічного превʼю бази (форма `get_public_db_preview`). */
function previewRow(over: Record<string, unknown> = {}) {
  return {
    db_id: '10000000-0000-0000-0000-000000000001',
    db_name: 'БЦ Рубін',
    db_type: 'business_center',
    db_color: 'pink',
    db_address: 'вул. Хрещатик, 1',
    property_id: '20000000-0000-0000-0000-000000000001',
    property_name: 'Офіс 101',
    property_status: 'free',
    property_area_useful: 45,
    property_area_total: 52,
    property_rent_type: 'per_m2',
    property_rent_rate: 18,
    property_sale_price: null,
    property_floor: '2',
    owner_currency: 'USD',
    created_at: NOW,
    ...over,
  }
}

/**
 * Відкриває екран БЕЗ сесії — саме так, як це бачить запрошений.
 * `noAutoLogin` лишає Splash на публічній гілці замість входу.
 */
async function openAsStranger(page: Page, startParam: string) {
  await setupApp(page, { noAutoLogin: true, startParam })
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

// ─── Рієлторський превʼю бази (db_) ──────────────────────────────────────────

test('превʼю бази: показує назву й обʼєкти незнайомцю без сесії', async ({ page }) => {
  await openAsStranger(page, `db_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => jsonRoute(r, [previewRow()]))
  await page.goto('/')

  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('Офіс 101').first()).toBeVisible()
})

test('превʼю бази: порожня відповідь = лінк застарів, а не порожній екран', async ({ page }) => {
  // RPC фільтрує `share_expires_at > now()` на сервері, тож відкликаний лінк
  // повертає саме порожній масив — це нормальний шлях, не збій.
  await openAsStranger(page, `db_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => jsonRoute(r, []))
  await page.goto('/')

  await expect(page.getByText(/не знайдена|застаріло/i).first()).toBeVisible({ timeout: 20_000 })
})

test('превʼю бази: обрив мережі дає пояснення, а не тиху порожню базу', async ({ page }) => {
  // Цей шлях описаний коментарем у коді: без catch екран провалювався у гілку
  // публічного превʼю з порожнім dbInfo — «база» без назви й без натяку на збій.
  await openAsStranger(page, `db_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => r.abort())
  await page.goto('/')

  await expect(page.getByText(/Не вдалося завантажити/i).first()).toBeVisible({ timeout: 20_000 })
})

// ─── Гостьове запрошення (guest_) ────────────────────────────────────────────

test('гостьове запрошення: превʼю обʼєкта видно до входу', async ({ page }) => {
  await openAsStranger(page, `guest_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_guest_property_preview', (r) => jsonRoute(r, {
    status: 'pending',
    property_name: 'Офіс 101',
    db_name: 'БЦ Рубін',
    owner_name: 'Микола',
  }))
  await page.goto('/')

  await expect(page.getByText(/Запрошення/).first()).toBeVisible({ timeout: 20_000 })
})

test('гостьове запрошення: ВІДКЛИКАНЕ не пускає і пояснює, куди йти', async ({ page }) => {
  // Найважливіша відмова цього екрана. Всі проблеми з лінком СВІДОМО зводяться
  // в одну картку: точний `errorMsg` лише класифікує її (`isLinkProblem`), а
  // показана копія чесно перелічує всі три причини разом — «застаріло, видалено
  // або відкликано» — і відсилає до власника. Тому гард стоїть на тому, що
  // користувач БАЧИТЬ, а не на внутрішньому рядку.
  await openAsStranger(page, `guest_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_guest_property_preview', (r) =>
    jsonRoute(r, { status: 'revoked', property_name: 'Офіс 101' }))
  await page.goto('/')

  await expect(page.getByText('Посилання недійсне')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText(/Зверніться до власника/)).toBeVisible()
  // І головне — вміст обʼєкта не протікає повз відмову.
  await expect(page.getByText('Офіс 101')).toHaveCount(0)
})

test('гостьове запрошення: неіснуючий токен не лишає порожнього екрана', async ({ page }) => {
  await openAsStranger(page, `guest_${TOKEN}`)
  await page.route('**/rest/v1/rpc/get_guest_property_preview', (r) => jsonRoute(r, null))
  await page.goto('/')

  await expect(page.getByText(/не знайдено|відкликано/i).first()).toBeVisible({ timeout: 20_000 })
})
