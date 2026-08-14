import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession } from './helpers/harness'
import { IN_SANDBOX } from './helpers/env'

/**
 * ВІЗУАЛЬНИЙ БЕЙСЛАЙН СТАНІВ — того, чого `screenshots.spec.ts` не знімає.
 *
 * Ті 27 кадрів — це 27 ЩАСЛИВИХ, заповнених екранів. Тобто нуль кадрів на:
 * скелетон, порожній стан, `RetryState` (вживається на ВОСЬМИ екранах і не був
 * сфотографований жодного разу), тост, фолбек `ConfirmHost`, `CoachMark`,
 * галерею, сплеш, гостьовий превʼю, легальні сторінки.
 *
 * `loading-states.spec.ts` перевіряє ГЕОМЕТРІЮ трьох станів на двох екранах —
 * тобто що заглушка не зсуває хром. Як вони ВИГЛЯДАЮТЬ, не перевіряє ніщо: у
 * стані помилки може поїхати верстка, зникнути іконка чи злитись кнопка з фоном,
 * і жоден із 280 тестів цього не побачить.
 *
 * ── Власник бейслайна ─────────────────────────────────────────────────────
 * Той самий, що і в `screenshots.spec.ts`: ТІЛЬКИ раннер
 * (`.github/workflows/update-snapshots.yml`). Пісочниця має заморожений
 * Chromium 141 проти 148 на CI, і сім мажорів різниці дають ratio 0.02 при
 * порозі 0.01 БЕЗ жодного зсуву геометрії. Кадр, знятий тут, на раннері
 * читається як «дизайн поїхав».
 */
test.skip(IN_SANDBOX, 'бейслайни знімає й перевіряє лише раннер (див. helpers/env.ts)')

const NOW = '2025-09-01T09:00:00.000Z'
const FROZEN = new Date('2025-09-15T09:00:00.000Z')

async function determinism(page: Page) {
  await page.clock.setFixedTime(FROZEN)
  await page.emulateMedia({ reducedMotion: 'reduce' })
}

/**
 * Знімок стану. На відміну від `snap()` у `screenshots.spec.ts`, тут НЕ можна
 * чекати зникнення `.skel` — половина кадрів саме про скелетон.
 */
async function shot(page: Page, name: string) {
  await expect(page.locator('.modal-overlay.closing')).toHaveCount(0, { timeout: 6_000 })
  await expect(page).toHaveScreenshot(`${name}.png`)
}

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: OWNER.id,
  name: 'Офіс 101', floor: '2', status: 'occupied', area_useful: 100, area_total: 120,
  area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
  has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
  folder_id: null, utilities: ['electricity'], description: 'Світлий офіс.',
  address: 'вул. Хрещатик, 1', sale_price: null, tenant_name: 'ТОВ «Ромашка»',
  lease_start_date: '2025-01-01', lease_end_date: '2026-01-01', sort_order: 1,
  share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
}

/** Роути, спільні для всіх станів власника; список баз задає викликач. */
async function ownerBase(page: Page, dbRoute: (r: Route) => unknown) {
  await setupApp(page, { user: OWNER })
  await seedSession(page, OWNER as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/databases**', dbRoute)
  for (const t of ['properties', 'property_folders', 'db_members', 'notifications',
                   'property_views', 'rent_payments', 'rent_payment_records',
                   'property_files', 'property_photos', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

const skipCoach = (page: Page) => page.addInitScript(() =>
  localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

// ── Стани завантаження й відмови ──────────────────────────────────────────────

test('states · скелетон списку баз', async ({ page }) => {
  await determinism(page)
  // Відповідь свідомо не приходить: скелетон — це і є предмет кадру.
  await ownerBase(page, () => { /* навмисно висить */ })
  await skipCoach(page)
  await page.goto('/')
  await expect(page.locator('.skel').first()).toBeVisible({ timeout: 20_000 })
  await shot(page, 'skeleton-db-list')
})

test('states · порожній список баз', async ({ page }) => {
  await determinism(page)
  await ownerBase(page, (r) => jsonRoute(r, []))
  await skipCoach(page)
  await page.goto('/')
  await expect(page.getByText(/Створіть першу базу|Немає баз|Мої бази/).first())
    .toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.skel')).toHaveCount(0, { timeout: 15_000 })
  await shot(page, 'empty-db-list')
})

test('states · панель повтору після збою мережі', async ({ page }) => {
  await determinism(page)
  // `RetryState` живе на ВОСЬМИ екранах і не був знятий жодного разу.
  await ownerBase(page, (r) => r.abort())
  await skipCoach(page)
  await page.goto('/')
  await expect(page.locator('.retry-wrap')).toBeVisible({ timeout: 20_000 })
  await shot(page, 'retry-db-list')
})

// ── Накладені шари ────────────────────────────────────────────────────────────

test('states · коачмарк першого запуску', async ({ page }) => {
  await determinism(page)
  await ownerBase(page, (r) => jsonRoute(r, [DB]))
  // Коачмарк гасить САМ ХАРНЕС (`setupApp` сідає `ob_v1`), тож «просто не
  // викликати skipCoach» недостатньо — ключ треба зняти. Init-скрипти біжать у
  // порядку реєстрації, тому цей мусить іти ПІСЛЯ `setupApp`. Перший екран
  // нового користувача інакше не бачив жоден кадр із 27.
  await page.addInitScript(() => localStorage.removeItem('ob_v1'))
  await page.goto('/')
  await expect(page.locator('.cmark-bubble')).toBeVisible({ timeout: 20_000 })
  await shot(page, 'coachmark-first-run')
})

test('states · тост помилки', async ({ page }) => {
  await determinism(page)
  await ownerBase(page, (r) => jsonRoute(r, [DB]))
  await skipCoach(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  // Офлайн-гард дає тост помилки І глобальний банер — два стани хрому в одному
  // кадрі. Але викликає його САМЕ мутація: тап по «Створити базу» лише
  // навігує, тож гард там не спрацьовує. Тому доходимо до форми і тиснемо
  // збереження.
  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })
  // Кнопка активна лише коли Є І назва, І тип (`canCreate`), тож обидва кроки
  // обовʼязкові — інакше тап іде по `disabled` і тест висить до таймауту.
  await page.getByLabel('Назва бази').fill('БЦ Рубін')
  await page.locator('.type-card').first().click()
  await page.evaluate(() => window.dispatchEvent(new Event('offline')))
  await page.locator('.mbtn').click()
  await expect(page.locator('.toast')).toBeVisible({ timeout: 15_000 })
  // БЮДЖЕТ: тост гасне САМ через 3.5с реального часу. `clock.setFixedTime`
  // фіксує лише `Date.now()` і таймери НЕ спиняє, тож між появою тоста і
  // знімком не можна вставляти ані очікувань, ані додаткових перевірок —
  // інакше кадр зніметься вже без нього і НІКОЛИ не зійдеться з бейслайном.
  // Тримається це на `reducedMotion:'reduce'`: без анімації перший же знімок
  // збігається, і цикл повторів `toHaveScreenshot` не встигає з'їсти вікно.
  await shot(page, 'toast-offline')
})

test('states · власне підтвердження, коли Telegram не дає попапа', async ({ page }) => {
  await determinism(page)
  // `showPopup` у харнесі вимкнений за замовчуванням — тобто це шлях слабшого
  // клієнта, `ConfirmHost`. Він рендериться порталом і не потрапив у жоден кадр.
  await ownerBase(page, (r) => jsonRoute(r, [DB]))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, [PROP]))
  await skipCoach(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Видалити базу', { exact: true }).click()
  await expect(page.locator('.modal', { hasText: 'Видалити' }).last()).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(420)
  await shot(page, 'confirm-fallback')
})

// ── Екрани, до яких тур не доходив ────────────────────────────────────────────

test('states · превʼю бази для незнайомця без сесії', async ({ page }) => {
  await determinism(page)
  // `GuestDatabaseScreen` — перша точка контакту запрошеного, і в бейслайні його
  // немає взагалі.
  await setupApp(page, { noAutoLogin: true, startParam: 'db_cc00112233445566778899aa' })
  await skipCoach(page)
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => jsonRoute(r, [{
    db_id: DB_ID, db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
    db_address: 'вул. Хрещатик, 1', property_id: PROP.id, property_name: 'Офіс 101',
    property_status: 'free', property_area_useful: 45, property_area_total: 52,
    property_rent_type: 'per_m2', property_rent_rate: 18, property_sale_price: null,
    property_floor: '2', owner_currency: 'USD', created_at: NOW,
  }]))
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await shot(page, 'guest-database-preview')
})

test('states · легальні сторінки', async ({ page }) => {
  await determinism(page)
  // Дві сторінки, на які веде Профіль і які не має жодного тесту взагалі.
  await page.goto('/privacy/')
  await expect(page.getByText('Політика конфіденційності').first()).toBeVisible({ timeout: 20_000 })
  await shot(page, 'legal-privacy')

  await page.goto('/terms/')
  await expect(page.getByText('Умови використання').first()).toBeVisible({ timeout: 20_000 })
  await shot(page, 'legal-terms')
})
