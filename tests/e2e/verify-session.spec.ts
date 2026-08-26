import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── Verification drive-through of this session's changes ─────────────────────
// Screens: home (no header bell), objects (compact view toggle, Apple action
// sheet), property form (in-flow CTA), ShareSheet (QR + expiry + manage).

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID,
  owner_id: USER.id,
  name: 'БЦ Рубін',
  address: 'вул. Хрещатик, 1',
  type: 'business_center',
  color: 'pink',
  share_token: 'aabbccddeeff001122334455',
  share_expires_at: null,
  created_at: NOW,
  updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'occupied', rent_rate: 2500, area_useful: 80, rent_type: 'fixed' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID,
    owner_id: USER.id,
    name: `Офіс ${100 + n}`,
    floor: String(n + 1),
    status: 'free',
    area_useful: 45,
    area_total: 52,
    rent_type: 'per_m2',
    rent_rate: null,
    utilities_rate: null,
    has_parking: false,
    parking_spaces: 0,
    utilities: null,
    description: null,
    address: null,
    sale_price: null,
    tenant_name: null,
    lease_start_date: null,
    lease_end_date: null,
    sort_order: n,
    share_token: `bb00000000000000000000${n}${n}`,
    share_expires_at: null,
    created_at: NOW,
    updated_at: NOW,
    photos: [],
    ...over,
  }
}

const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5, lease_end_date: '2029-02-28' }),
  prop(2, { status: 'occupied', tenant_name: 'ФОП Іванов', rent_type: 'fixed', rent_rate: 2500, area_useful: 80, area_total: 90 }),
  prop(3, { rent_rate: 15 }),
  prop(4, { status: 'for_sale', sale_price: 120000 }),
]

async function setupFixtures(page: Page) {
  await setupApp(page, { user: USER })
  // Later page.route registrations win over the harness catch-all.
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => json(route, PROPERTIES))
  await page.route('**/rest/v1/rpc/manage_share', (route) =>
    json(route, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))

  // Skip onboarding coach marks
  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

test('drive-through: home → objects → compact → action sheet → form → ShareSheet', async ({ page }, testInfo) => {
  await setupFixtures(page)
  await page.goto('/')

  // ── 1. Home (db-list): header has NO notifications bell; tab bar has it ────
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.hdr [aria-label="Сповіщення"]')).toHaveCount(0)
  await expect(page.locator('.tabbar [aria-label="Сповіщення"]')).toHaveCount(1)
  await page.screenshot({ path: testInfo.outputPath('01-home.png'), fullPage: false })

  // ── 2. Open the database ────────────────────────────────────────────────────
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (4)')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('02-objects-cards.png') })

  // ── 3. Occupied tab → compact toggle → compact rows ────────────────────────
  await page.getByText('Зайнято (2)').click()
  await expect(page.getByLabel('Компактно')).toBeVisible()
  await page.getByLabel('Компактно').click()
  await expect(page.getByText('ТОВ «Ромашка»')).toBeVisible()
  await expect(page.getByText('ФОП Іванов')).toBeVisible()
  // green monthly total = rent 100*18 + utils 120*2.5 = 2100
  await expect(page.locator('.row-tot').first()).toContainText('2')
  await page.screenshot({ path: testInfo.outputPath('03-compact-list.png') })

  // ── 3b. Вільно tab shares the compact preference; right column = СИРА ставка
  await page.getByText('Вільно (1)').click()
  await expect(page.getByLabel('Компактно')).toBeVisible()
  await expect(page.locator('.row-tot').first()).toContainText('15')
  await expect(page.locator('.row-tot-u').first()).toHaveText('/м²')
  await page.screenshot({ path: testInfo.outputPath('03b-compact-free.png') })

  // ── 3c. Продаж tab: права колонка = ціна продажу (без суфікса)
  await page.getByText('Продаж (1)').click()
  await expect(page.locator('.row-tot').first()).toContainText('120')
  await expect(page.locator('.row-tot-u')).toHaveCount(0)

  // ── 3d. Всі tab: компакт успадковується, статусні крапки, стат-панель схована
  await page.getByText('Всі (4)').click()
  await expect(page.locator('.list .fdot')).toHaveCount(4)
  await expect(page.getByText('Зайнятість')).toHaveCount(0)
  await page.screenshot({ path: testInfo.outputPath('03d-compact-all.png') })
  // Повернення до карток показує панель знову
  await page.getByLabel('Картки').click()
  await expect(page.getByText('Зайнятість')).toBeVisible()
  await page.getByLabel('Компактно').click()

  // ── 4. Apple action sheet ───────────────────────────────────────────────────
  await page.getByLabel('Меню бази').click()
  await expect(page.getByText('Дії з базою')).toBeVisible()
  // 10 пунктів для власника: аналітика, календар, гості, команда (041),
  // експорт, папки (043), виділити, порядок, редагувати, видалити
  await expect(page.locator('.sheet-row')).toHaveCount(10)
  await expect(page.locator('.sheet-row.danger')).toHaveCount(1)
  await page.screenshot({ path: testInfo.outputPath('04-action-sheet.png') })
  await page.getByText('Скасувати').click()

  // ── 5. Property form: CTA is in-flow at the end of the fields ──────────────
  await page.getByText('Всі (4)').click()
  await page.getByLabel("Додати обʼєкт").click()
  await expect(page.getByText("Новий обʼєкт")).toBeVisible()
  const cta = page.locator('button.mbtn')
  await expect(cta).toHaveCount(1)
  await cta.scrollIntoViewIfNeeded()
  await page.screenshot({ path: testInfo.outputPath('05-form-inflow-cta.png') })
  await page.getByText('База', { exact: true }).click() // header back

  // ── 6. ShareSheet via Аналітика і поширення ────────────────────────────────
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText('Аналітика бази')).toBeVisible()
  await page.getByRole('button', { name: 'Поділитися' }).click()
  await expect(page.getByText('Термін дії')).toBeVisible()
  await expect(page.getByText('безстрокове')).toBeVisible()
  await expect(page.locator('.fr-seg-b', { hasText: '7 днів' })).toBeVisible()
  await expect(page.locator('.fr-seg-b', { hasText: 'Без обмежень' })).toBeVisible()
  await expect(page.getByText('Оновити посилання')).toBeVisible()
  await expect(page.getByText('Відкликати доступ')).toBeVisible()
  await expect(page.locator('.qr-wrap svg')).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('06-share-sheet.png') })
})
