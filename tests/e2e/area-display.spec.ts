import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * ДВІ ПЛОЩІ ОДНОГО ОБʼЄКТА НА ЕКРАНІ.
 *
 * Модель — рівно два числа (корисна, розрахункова) плюс база. Кімнати на
 * поверсі — окремі обʼєкти з однаковим текстом `floor`; ієрархії немає. Тому
 * єдине місце, де «кілька площ» стосуються одного обʼєкта, — ця пара, і кожен
 * рядок списку мусить показувати її однаково:
 *
 *  • обидві → «45/52»;
 *  • лише корисна → «45» (а не «45/45»: розрахункової, яку вигадувало
 *    `area_total ?? area_useful`, ніхто не вводив);
 *  • лише розрахункова → «—/52». Було: нічого — обʼєкт із базою за замовчуванням
 *    «розрахункова» і єдиною заповненою площею не показував площі, хоча ціну
 *    рахували з неї;
 *  • 0 → нічого, а не літеральне «0» (`{p.area_useful && …}` друкує нуль).
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, areas: { useful: number | null; total: number | null }) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Кімната ${n}`, floor: '2', status: 'free',
    area_useful: areas.useful, area_total: areas.total, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, landlord_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  }
}

const PROPS = [
  prop(1, { useful: 45, total: 52 }),
  prop(2, { useful: 45, total: null }),
  prop(3, { useful: null, total: 52 }),
  prop(4, { useful: 0, total: 0 }),
]

async function openList(page: Page) {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, PROPS))
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'property_folders', 'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (4)')).toBeVisible({ timeout: 15_000 })
}

/** Рядок метаданих обʼєкта за назвою — і в картках, і в компактному вигляді. */
const metaOf = (page: Page, name: string) =>
  page.locator('.obj-card, .row', { hasText: name }).first()

test('картки: пара площ однакова для всіх чотирьох випадків', async ({ page }) => {
  await openList(page)
  await page.getByLabel('Картки').click()

  await expect(metaOf(page, 'Кімната 1').locator('.obj-s')).toContainText('45/52 м²')
  // Саме «45», а не «45/45»: розрахункової, що збігалась би з корисною, ніхто не вводив.
  await expect(metaOf(page, 'Кімната 2').locator('.obj-s')).toContainText(/(^|[\s·])45 м²/)
  await expect(metaOf(page, 'Кімната 2').locator('.obj-s')).not.toContainText('45/45')
  // Було: площі немає взагалі, хоча $936 нижче рахується саме з 52 м².
  await expect(metaOf(page, 'Кімната 3').locator('.obj-s')).toContainText('—/52 м²')
  // Нуль — не площа: ні «0», ні лінійки.
  await expect(metaOf(page, 'Кімната 4').locator('.obj-s')).not.toContainText(/\b0\b/)
})

test('компактний вигляд: корисна, а за її відсутності видно пару', async ({ page }) => {
  await openList(page)
  await page.getByLabel('Компактно').click()

  await expect(metaOf(page, 'Кімната 1').locator('.row-s')).toContainText('45 м²')
  await expect(metaOf(page, 'Кімната 3').locator('.row-s')).toContainText('—/52 м²')
  await expect(metaOf(page, 'Кімната 4').locator('.row-s')).not.toContainText(/\b0\b/)
})

test('сортування «за площею»: обʼєкт лише з розрахунковою площею не падає на дно', async ({ page }) => {
  await openList(page)
  await page.getByLabel('Картки').click()
  await page.getByText('За площею', { exact: true }).click()

  // 52 (лише розрахункова) > 45 > 45 > нуль: порядок за розміром, а не «0 для
  // обʼєкта, площа якого — лише розрахункова». Раніше «Кімната 3» стояла б
  // разом з порожньою «Кімнатою 4» внизу.
  const names = await page.locator('.obj-card .obj-t').allTextContents()
  expect(names.map((n) => n.trim())).toEqual(['Кімната 3', 'Кімната 1', 'Кімната 2', 'Кімната 4'])
})
