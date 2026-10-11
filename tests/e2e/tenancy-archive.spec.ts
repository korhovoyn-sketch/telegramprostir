import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * АРХІВ ПРАВОВІДНОСИН (міграція 067).
 *
 * Найважливіше, що тут перевіряється, — НЕ те, що екран малює список, а
 * правило звʼязку платежів: вони належать оренді за ПЕРІОДОМ, а не за
 * зовнішнім ключем. Помилка в ньому тиха й грошова — сума просто інша, і
 * жодної помилки при цьому не видно. Тому гард годує платежі ПО ОБИДВА БОКИ
 * межі й вимагає, щоб у суму зайшли рівно ті, що всередині.
 *
 * Другий клас — толерантність до відсутньої таблиці: застосувати 067 із цього
 * середовища неможливо, тож фронт мусить деплоїтись раніше за неї.
 */

const OWNER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const PROP_ID = '20000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function tenancy(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `70000000-0000-0000-0000-00000000000${n}`, owner_id: OWNER.id, db_id: DB_ID,
    property_id: PROP_ID, property_name: 'Офіс 101', tenant_name: `Орендар ${n}`,
    landlord_name: null, rent_rate: 1000, rent_type: 'fixed', utilities_rate: null,
    area_basis: 'useful', area_useful: 50, area_total: 60, currency: 'USD',
    lease_start_date: null, lease_end_date: null,
    started_at: '2024-03-01T10:00:00.000Z', ended_at: '2024-11-20T10:00:00.000Z',
    created_at: NOW, updated_at: NOW, ...over,
  }
}

/** Платіж: `due_date` — єдине, що вирішує, до якої оренди він належить. */
const paid = (due: string, amount: number) =>
  ({ id: `80000000-0000-0000-0000-${due.replace(/-/g, '')}`, property_id: PROP_ID,
     owner_id: OWNER.id, due_date: due, amount, status: 'paid' })

interface Opts {
  rows?: ReturnType<typeof tenancy>[]
  records?: ReturnType<typeof paid>[]
  /** SELECT падає з 42703 — так виглядає бекенд БЕЗ міграції 067. */
  noTable?: boolean
  /** GET падає — мережа/політика лягли. */
  loadFails?: boolean
}

interface Wire { urls: string[] }

async function openArchive(page: Page, wire: Wire, opts: Opts = {}) {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    r.request().method() === 'GET' ? jsonRoute(r, []) : r.fallback())
  for (const t of ['db_members', 'guest_links', 'rent_payments',
                   'property_views', 'property_folders', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, opts.records ?? []))

  await page.route('**/rest/v1/tenancies**', (r) => {
    wire.urls.push(decodeURIComponent(r.request().url()))
    if (opts.noTable) {
      return r.fulfill({ status: 404, contentType: 'application/json',
        body: JSON.stringify({ code: '42P01', message: 'relation "public.tenancies" does not exist' }) })
    }
    if (opts.loadFails) {
      return r.fulfill({ status: 500, contentType: 'application/json',
        body: JSON.stringify({ message: 'server exploded' }) })
    }
    return jsonRoute(r, opts.rows ?? [tenancy(1)])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Архів оренд', { exact: true }).click()
  await expect(page.locator('.hdr-t')).toContainText('Архів оренд', { timeout: 15_000 })
}

test('оренда лишається в архіві після звільнення — і запит фільтрує по СВОЇЙ базі', async ({ page }) => {
  const wire: Wire = { urls: [] }
  await openArchive(page, wire, {
    rows: [tenancy(1, { tenant_name: 'ТОВ «Альфа»', ended_at: null }), tenancy(2)],
  })

  await expect(page.getByText('ТОВ «Альфа»')).toBeVisible()
  await expect(page.getByText('Орендар 2')).toBeVisible()
  await expect(page.locator('.acc-badge').filter({ hasText: 'Триває' })).toHaveCount(1)
  await expect(page.locator('.acc-badge').filter({ hasText: 'Завершено' })).toHaveCount(1)

  // Без цього лічильник на екрані був би правильний, а запит — чужий: та сама
  // пастка, що вже ловилась на аналітиці підбірки.
  expect(wire.urls.some((u) => u.includes(`db_id=eq.${DB_ID}`)),
    `запит архіву не фільтрує по базі: ${wire.urls.join(' | ')}`).toBe(true)
})

test('отримане рахується ПЕРІОДОМ оренди, а не всіма платежами обʼєкта', async ({ page }) => {
  const wire: Wire = { urls: [] }
  await openArchive(page, wire, {
    // Оренда: 2024-03-01 → 2024-11-20. Платежі по ОБИДВА боки межі.
    rows: [tenancy(1)],
    records: [
      paid('2024-02-15', 900),   // ДО початку — не рахується
      paid('2024-04-05', 1000),  // всередині
      paid('2024-10-05', 1000),  // всередині
      paid('2024-11-20', 700),   // рівно в день закриття — межа ВІДКРИТА справа
      paid('2024-12-05', 800),   // після — не рахується
    ],
  })

  // 1000 + 1000 = 2000; будь-яка інша сума означає, що межа зрушилась.
  // Порівнюємо ЦИФРИ, а не форматований рядок: українська локаль ставить
  // НЕРОЗРИВНИЙ пробіл у тисячах, тож «$2,000» не збіглося б ніколи — гард
  // падав би на форматері, а не на правилі, яке він міряє.
  const digits = async () =>
    ((await page.locator('.ten-sum.ok').first().textContent()) ?? '').replace(/\D/g, '')
  await expect.poll(digits, { timeout: 10_000 }).toBe('2000')
})

test('без міграції 067 екран ПРАЦЮЄ — просто без архіву', async ({ page }) => {
  const wire: Wire = { urls: [] }
  await openArchive(page, wire, { noTable: true })

  await expect(page.getByText('Архів ще не увімкнено')).toBeVisible({ timeout: 10_000 })
  // Антивакуум: екран живий, а не в ErrorBoundary.
  await expect(page.locator('.err-boundary, [data-error-boundary]')).toHaveCount(0)
})

test('збій завантаження дає ПОВТОР, а не «оренд не було»', async ({ page }) => {
  const wire: Wire = { urls: [] }
  await openArchive(page, wire, { loadFails: true })

  // «Оренд ще не було» — упевнена відповідь про дані, яких екран не бачив.
  await expect(page.getByText('Оренд ще не було')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Спробувати|Повторити/ })).toBeVisible({ timeout: 10_000 })
})
