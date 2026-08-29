import { test, expect, type Page, type Route, type Locator } from '@playwright/test'
import { setupApp, DEFAULT_USER, type HarnessUser } from './helpers/harness'
import { IN_SANDBOX } from './helpers/env'

// ─── Візуальний бейслайн кожного досяжного екрана ─────────────────────────────
//
// Раніше це був ТУР: робив 20+ PNG у gitignored-теку і нічого не перевіряв. Тобто
// «зсунулось на 3px», «зник градієнт», «текст поїхав під іконку» ловило лише
// людське око. Гірше — `tryShot` глушив помилки навігації через catch, тож
// зламаний перехід виглядав як пропущений кадр, а не як падіння.
//
// Тепер кожен кадр порівнюється з бейслайном у `screenshots.spec.ts-snapshots/`.
//
// БЕЙСЛАЙНОМ ВОЛОДІЄ CI, І ЦЕ НЕ ОРГАНІЗАЦІЙНА УМОВНІСТЬ. Пісочниця Claude Code
// ганяє ЗАМОРОЖЕНИЙ предвстановлений Chromium (141), CI ставить свій (148) — сім
// мажорів різниці в растеризації тексту. Кадр, знятий тут, на раннері дає ratio
// 0.02 при порозі 0.01 БЕЗ жодного зсуву геометрії, тобто виглядає як «дизайн
// поїхав», хоч CSS ніхто не чіпав. Саме так main простояв червоним три мерджі.
// Бейслайни іменуються по ПЛАТФОРМІ (`…-iphone-se-linux.png`), а не по збірці
// браузера, тож розбіжність невидима, доки не побіжить CI.
//
// Тому: `--update-snapshots` ЛОКАЛЬНО НЕ ЗАПУСКАТИ. Після свідомої зміни дизайну —
// dispatch воркфлоу `.github/workflows/update-snapshots.yml` на своїй гілці; він
// перезніме кадри на раннері й закомітить їх туди ж.
//
test.skip(IN_SANDBOX, 'Візуальний бейслайн знімає й перевіряє CI: тутешній Chromium 141 растеризує текст інакше за раннерівський 148 (див. helpers/env.ts)')
//
// Три джерела нестабільності знято:
//  • анімації — `reducedMotion: 'reduce'` (застосунок має цей блок у globals.css)
//    плюс `animations: 'disabled'` у конфігу;
//  • час — `clock.setFixedTime`, інакше `formatDate` дає «щойно / 2 дні тому», а
//    бейджі протермінування рахуються від справжнього «сьогодні» і поїдуть за
//    місяць;
//  • прогрес-смуга заповненості — маскується.
//
// deviceScaleFactor: 1 — бейслайни легші вчетверо (4.3 МБ проти 10.1 МБ на 22
// екрани). Для ВИЯВЛЕННЯ регресії масштаб не важить: порівнюється однакове з
// однаковим, а зсув чи зниклий градієнт видно однаково.
test.use({ deviceScaleFactor: 1 })

// Фікстурні дати теж фіксовані: `new Date()` у Node не підпадає під clock
// сторінки, тож «живі» дати мігрували б щодня і валили бейслайн.
const NOW = '2025-09-01T09:00:00.000Z'
/** Оренда фікстур активна на цю дату (2025-01-01 → 2026-01-01). */
const FROZEN = new Date('2025-09-15T09:00:00.000Z')

async function determinism(page: Page) {
  await page.clock.setFixedTime(FROZEN)
  await page.emulateMedia({ reducedMotion: 'reduce' })
}

/** Крок туру: навігація + порівняння з бейслайном. Падає, а не логує. */
async function snap(page: Page, name: string, nav: () => Promise<void>, extraMask: Locator[] = []) {
  await nav()
  // Шит меню бази виходить ~320мс уже ПОВЕРХ нового екрана, і його
  // `backdrop-filter` приглушує ВЕСЬ кадр. Два прогони стабілізувались на різних
  // станах цього затухання: діф `team.png` показував рівномірну різницю по всьому
  // тексту без жодного зсуву геометрії — 0.02 при порозі 0.01.
  await expect(page.locator('.modal-overlay.closing')).toHaveCount(0, { timeout: 6_000 })
  // Скелетон мусить ЗНИКНУТИ до кадру. Умова навігації часто слабша за
  // «екран домальовано»: `realtor-database` чекав лише на сегмент «Всі (»,
  // який зʼявляється РАНІШЕ за картки, тож кадр ловив частково відрендерений
  // список — і стан цієї частковості залежить від швидкості машини.
  await expect(page.locator('.skel')).toHaveCount(0, { timeout: 15_000 })
  await expect(page).toHaveScreenshot(`${name}.png`, {
    // Смуга заповненості — єдиний елемент, чия ширина залежить від даних, які
    // цей екран рахує наживо.
    mask: [page.locator('.dash-bar-fill'), ...extraMask],
  })
}
const json = (route: Route, body: unknown) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

// ── Owner fixtures ────────────────────────────────────────────────────────────
const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола', last_name: 'К.', phone: '+380670000000' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
  properties: [
    { status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' },
    { status: 'occupied', rent_rate: 2500, area_useful: 80, rent_type: 'fixed' },
    { status: 'free', rent_rate: null, area_useful: 45, rent_type: 'per_m2' },
  ],
}
function prop(i: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    utilities: null, description: 'Світлий офіс у центрі міста.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, utilities_rate: 2.5, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01' }),
  prop(2, { status: 'occupied', tenant_name: 'ФОП Іванов', rent_type: 'fixed', rent_rate: 2500, area_useful: 80, area_total: 90 }),
  prop(3, { status: 'free', sale_price: null }),
]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
    db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
    guest_user_id: null, status: 'pending', claimed_at: null, created_at: NOW,
  }]))
  await page.route('**/rest/v1/db_members**', (r) => {
    // Список членів для TeamScreen; перший запит useDatabases по user_id
    // теж сюди влучає — йому байдуже, зайві поля він ігнорує
    if (r.request().url().includes('user_id=eq.')) return json(r, [])
    return json(r, [
      { id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID, user_id: '00000000-0000-0000-0000-000000000077', role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер', member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW },
      { id: '40000000-0000-0000-0000-000000000002', db_id: DB_ID, user_id: null, role: 'editor', invite_token: 'ee00112233445566778899', label: 'Бухгалтер', member_name: null, status: 'pending', claimed_at: null, created_at: NOW },
    ])
  })
  // `.maybeSingle()` у повноекранних платіжних формах: Accept вирішує форму
  // відповіді, масив замість обʼєкта лишає екран у RetryState.
  await page.route('**/rest/v1/rent_payments**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? null : []))
  await page.route('**/rest/v1/rent_payment_records**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? null : []))
  await page.route('**/rest/v1/property_views**', (r) => json(r, []))
  await page.route('**/rest/v1/rpc/manage_share', (r) => json(r, [{ share_token: DB.share_token, share_expires_at: null, error: null }]))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('screens · owner journey', async ({ page }) => {
  await determinism(page)
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  await snap(page, 'db-list', async () => {
    await page.goto('/')
    await page.getByText('Мої бази').waitFor({ timeout: 20_000 })
  })
  await snap(page, 'db-objects', async () => {
    await page.getByText('БЦ Рубін').first().click()
    await page.getByText('Всі (3)').waitFor()
  })
  // Компактний вигляд — окремий рендер картки, який card-view не покриває.
  // Саме тут живе плитка іконки 22×22, чий інлайновий радіус був поза шкалою.
  await snap(page, 'db-objects-compact', async () => {
    await page.getByLabel('Компактно').click()
    await page.locator('.row').first().waitFor()
  })
  await snap(page, 'db-objects', async () => {
    await page.getByLabel('Картки').click()
    await page.locator('.obj-card').first().waitFor()
  })
  await snap(page, 'property-detail', async () => {
    await page.locator('.obj-card', { hasText: 'Офіс 101' }).click()
    await page.getByText('Назад', { exact: true }).first().waitFor()
  })
  await snap(page, 'property-form-edit', async () => {
    await page.getByLabel(/Редагувати|Змінити/).first().click().catch(() => page.getByText('Редагувати').first().click())
    await page.getByText(/Редагування|Зберегти зміни/).first().waitFor()
  })
  // back to objects for the menu-driven screens
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  // Оренда — фаза 5. Вхід лише з картки ВІЛЬНОГО обʼєкта (у зайнятого те саме
  // місце займає «Звільнити обʼєкт»), тож крок іде саме на «Офіс 103».
  await snap(page, 'rent-property', async () => {
    await page.locator('.obj-card', { hasText: 'Офіс 103' }).click()
    await page.getByRole('button', { name: 'Здати в оренду' }).first().click()
    await page.getByLabel('Орендар').waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'property-form-new', async () => {
    await page.getByLabel("Додати обʼєкт").click()
    await page.getByText("Новий обʼєкт").waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'sharing-analytics', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Аналітика і поширення').click()
    await page.getByText(/Аналітика|Поділитись/).first().waitFor()
  })
  await snap(page, 'share-sheet', async () => {
    await page.getByRole('button', { name: /Поділитися/ }).click()
    await page.getByText('Поділитися').first().waitFor()
    // QR приходить ПІСЛЯ підпису шита і змінює його висоту (шит привʼязаний до
    // низу екрана, тож увесь вміст їде вгору). Без цього очікування кадр залежав
    // від того, чи встиг намалюватись код — саме тут dev і прод-білд дали різні
    // бейслайни на ~8px.
    await page.locator('.qr-wrap svg').first().waitFor({ timeout: 15_000 })
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'payment-calendar', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Календар платежів').click()
    await page.getByText(/Календар платежів|Прострочено/).first().waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  // Повноекранні маршрути з фаз 2-3 переробки модалок. Кадру не мав жоден із
  // них, тобто вигляд трьох нових екранів не був зафіксований ніде.
  await snap(page, 'payment-schedule', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Календар платежів').click()
    await page.getByText(/Календар платежів|Прострочено/).first().waitFor()
    await page.getByRole('button', { name: /Налаштувати/ }).first().click()
    await page.getByText('Налаштувати розклад').waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  // Повноекранні маршрути з фази 4 (три колишні пікери). Той самий обовʼязок,
  // що для фаз 2-3: новий екран = новий кадр тим самим дифом.
  await snap(page, 'folder-manage', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Папки', { exact: true }).click()
    await page.getByRole('button', { name: 'Додати папку' }).waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'folder-picker', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText("Виділити обʼєкти", { exact: true }).click()
    await page.locator('.obj-card').first().click()
    await page.getByRole('button', { name: /У папку/ }).click()
    await page.getByRole('button', { name: 'Створити й перемістити' }).waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'db-picker', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText("Виділити обʼєкти", { exact: true }).click()
    await page.locator('.obj-card').first().click()
    await page.getByRole('button', { name: /В базу/ }).click()
    await page.getByRole('button', { name: 'Створити й перенести' }).waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'manage-guests', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Управління гостями').click()
    await page.getByLabel('Запросити гостя').waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'create-invite', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Управління гостями').click()
    await page.getByLabel('Запросити гостя').click()
    await page.getByRole('button', { name: 'Створити' }).waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'team', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Команда', { exact: true }).click()
    await page.getByLabel('Запросити в команду').waitFor()
  })
  await page.goto('/'); await page.getByText('Мої бази').waitFor()
  await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()

  await snap(page, 'export', async () => {
    await page.getByLabel('Меню бази').click()
    await page.getByText('Експорт').click()
    await page.getByText(/Формат файлу|Завантажити/).first().waitFor()
  })
  await snap(page, 'import-objects', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()
    await page.getByLabel('Меню бази').click()
    await page.getByText('Імпорт із CSV').click()
    await page.getByText('Обрати файл').waitFor()
  })
  await snap(page, 'create-db', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.getByLabel('Створити базу').click()
    await page.getByText('Нова база').waitFor()
  })
  await snap(page, 'notifications', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.locator('.tabbar [aria-label="Сповіщення"]').click()
    await page.getByText(/Сповіщення|Немає сповіщень/).first().waitFor()
  })
  await snap(page, 'profile', async () => {
    await page.locator('.tabbar [aria-label="Профіль"]').click()
    await page.getByText('Налаштування').waitFor()
  })
  // Видалення акаунта — фаза 5. Незворотна дія з набором слова, тобто єдиний
  // екран, чия кнопка СВІДОМО лишається неактивною на кадрі: саме так його й
  // бачить користувач, доки не вписав підтвердження.
  await snap(page, 'delete-account', async () => {
    await page.locator('.del-acc').click()
    await page.getByLabel('Підтвердження видалення').waitFor()
  })

  // Блок «Хто переглядав» — другий СТАН екрана сповіщень. Підміна
  // `property_views` іде ПІСЛЯ кадру `notifications`, інакше той втратив би
  // свій порожній стан; сам блок малюється лише за іменованих глядачів.
  await page.route('**/rest/v1/property_views**', (r) => json(r, [
    { property_id: PROPERTIES[0].id, db_id: null, viewer_id: 'v-realtor', viewer_name: 'Олена Ріелтор', created_at: '2025-09-14T10:00:00.000Z' },
    { property_id: PROPERTIES[1].id, db_id: null, viewer_id: 'v-realtor', viewer_name: 'Олена Ріелтор', created_at: '2025-09-14T09:00:00.000Z' },
    { property_id: null, db_id: DB_ID, viewer_id: 'v-editor', viewer_name: 'Оля Редактор', created_at: '2025-09-12T18:30:00.000Z' },
  ]))
  await snap(page, 'notifications-viewers', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.locator('.tabbar [aria-label="Сповіщення"]').click()
    await page.getByText('Хто переглядав').waitFor()
  })

  // Підтвердження платежу — СВІДОМО останнім кадром власника. Екран досяжний
  // лише коли розклад уже є, а підміна `rent_payments` живого розкладу зачепила
  // б і «Сповіщення» (useUpcomingPayments рахує найближчий платіж саме звідти),
  // тобто перемалювала б чужий бейслайн. Останнім кроком підміняти безпечно.
  await page.route('**/rest/v1/rent_payments**', (r) => {
    const row = {
      id: '60000000-0000-0000-0000-000000000001', property_id: PROPERTIES[0].id,
      owner_id: OWNER.id, due_day: 5, notify_days_before: 3, is_active: true,
      created_at: NOW, updated_at: NOW,
    }
    return json(r, (r.request().headers()['accept'] ?? '').includes('object') ? row : [row])
  })
  await snap(page, 'payment-confirm', async () => {
    await page.goto('/'); await page.getByText('Мої бази').waitFor()
    await page.getByText('БЦ Рубін').first().click(); await page.getByText('Всі (3)').waitFor()
    await page.getByLabel('Меню бази').click()
    await page.getByText('Календар платежів').click()
    await page.getByText(/Календар платежів|Прострочено/).first().waitFor()
    await page.getByRole('button', { name: /Отримано/ }).first().click()
    await page.getByText('Підтвердити платіж').waitFor()
  })
})

// ── Realtor ───────────────────────────────────────────────────────────────────
test('screens · realtor', async ({ page }) => {
  await determinism(page)
  const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }
  const RDB = { ...DB, owner_id: '00000000-0000-0000-0000-000000000099' }
  await setupApp(page, { user: REALTOR })
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [{
    id: '30000000-0000-0000-0000-000000000009', realtor_id: REALTOR.id, db_id: DB_ID, created_at: NOW, database: RDB,
  }]))
  await page.route('**/rest/v1/properties**', (r) => json(r, PROPERTIES))
  await page.route('**/rest/v1/collections**', (r) => json(r, []))
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))

  await snap(page, 'realtor-dashboard', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor({ timeout: 20_000 })
  })
  await snap(page, 'realtor-database', async () => {
    await page.getByText('БЦ Рубін').first().click()
    await page.getByText(/Всі \(/).first().waitFor()
    // Останній видимий рядок сідає рівно на межу `--tg-vh` (568px), де
    // стилізований контент бази переходить у чистий чорний фон екрана. `.obj-card`
    // — це `.glass-s` з `backdrop-filter: blur`, і саме на цій різкій межі
    // світло↔чорне його блюр-семпл найчутливіший до GPU/драйвера: на CI й тут дає
    // видимо інший відтінок картки за ідентичного DOM/даних (перевірено —
    // ARIA-дерево й увесь інший кадр збігаються піксель-в-піксель, різниця лежить
    // рівно в межах цього рядка). Не гарди дизайну заради цього — маскуємо
    // ЛИШЕ рядок, що впирається у межу.
  }, [page.locator('.obj-card').last()])
  await snap(page, 'qr-scanner', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor()
    await page.getByRole('button', { name: 'Додати базу за QR' }).click()
    await page.getByText(/Сканер|Відскануйте/).first().waitFor()
  })
  await snap(page, 'collections', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor()
    await page.locator('.tabbar [aria-label="Підбірки"]').click()
    await page.getByText(/Підбірки|Немає підбірок/).first().waitFor()
  })
  // Кадр ОСТАННІЙ: підміна `collections` живе на сторінці до кінця прогону, а
  // кадр `collections` вище знімає саме порожній стан.
  await page.route('**/rest/v1/collections**', (r) => json(r, [{
    id: '70000000-0000-0000-0000-000000000001', realtor_id: REALTOR.id,
    name: 'Для клієнта А', is_draft: false, share_token: 'ff00112233445566778899aa',
    share_expires_at: null, created_at: NOW, updated_at: NOW,
  }]))
  await page.route('**/rest/v1/property_views**', (r) => json(r, [
    { id: 'cv1', property_id: null, viewer_id: null, viewer_name: 'Веб-перегляд підбірки', action: 'view', created_at: '2025-09-14T10:00:00.000Z' },
    { id: 'cv2', property_id: null, viewer_id: null, viewer_name: 'Веб-перегляд підбірки', action: 'view', created_at: '2025-09-12T18:30:00.000Z' },
  ]))
  await snap(page, 'collection-analytics', async () => {
    await page.goto('/'); await page.getByText('Робочі бази').waitFor()
    await page.locator('.tabbar [aria-label="Підбірки"]').click()
    await page.getByText('Для клієнта А').first().click()
    await page.getByText('Аналітика підбірки').click()
    await page.locator('.hdr-t').getByText('Аналітика підбірки').waitFor()
  })
})

// ── Guest ─────────────────────────────────────────────────────────────────────
test('screens · guest', async ({ page }) => {
  await determinism(page)
  const GUEST = { ...DEFAULT_USER, first_name: 'Гість' } as unknown as HarnessUser
  ;(GUEST as unknown as { role: string }).role = 'guest'
  const PROPERTY = { ...PROPERTIES[0], owner_id: '00000000-0000-0000-0000-000000000099' }
  await setupApp(page, { user: GUEST })
  await page.route('**/rest/v1/guest_links**', (r) => json(r, [{
    id: '50000000-0000-0000-0000-000000000001', owner_id: PROPERTY.owner_id,
    property_id: PROPERTY.id, db_id: null, invite_token: 'gg000000000000000000001',
    label: 'Мій орендар', guest_user_id: GUEST.id, status: 'active', claimed_at: NOW,
    created_at: NOW, property: PROPERTY, database: null,
  }]))
  await page.route('**/rest/v1/properties**', (r) => {
    // .single() детальної чекає ОБʼЄКТ — масив у відповідь лишає екран на спінері
    const accept = r.request().headers()['accept'] ?? ''
    return json(r, accept.includes('object') ? PROPERTY : [PROPERTY])
  })

  await snap(page, 'guest-home', async () => {
    await page.goto('/'); await page.getByText("Мої обʼєкти").waitFor({ timeout: 20_000 })
  })
  await snap(page, 'guest-property', async () => {
    await page.getByText('Офіс 101').first().click()
    await page.getByText('Корисна площа').waitFor({ timeout: 15_000 })
  })
})

// ── Auth / onboarding ─────────────────────────────────────────────────────────
test('screens · welcome', async ({ page }) => {
  await determinism(page)
  await snap(page, 'welcome', async () => {
    await setupApp(page, { user: { ...DEFAULT_USER, role: null }, noAutoLogin: true })
    await page.goto('/?fromLogout=1')
    await page.waitForTimeout(1600)
  })
})

test('screens · onboarding', async ({ page }) => {
  await determinism(page)
  // A role:null user auto-logs-in and lands on role-select (useAuth navigateRoot).
  await setupApp(page, { user: { ...DEFAULT_USER, role: null } })
  await snap(page, 'role-select', async () => {
    await page.goto('/')
    await page.getByText('Власник').first().waitFor({ timeout: 20_000 })
  })
  await snap(page, 'profile-setup', async () => {
    await page.getByText('Власник').first().click()
    await page.getByText('Продовжити →').click()
    await page.getByPlaceholder('you@email.com').waitFor()
  })
})

// ── Public /v viewer ──────────────────────────────────────────────────────────
test('screens · public /v', async ({ page }) => {
  await determinism(page)
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram = { WebApp: { openTelegramLink() {}, ready() {}, expand() {} } }
  })
  const PROP_PREVIEW = {
    property_id: '2', property_name: 'Офіс 101', property_status: 'free',
    property_floor: '3', property_area_useful: 100, property_area_total: 120,
    property_rent_type: 'per_m2', property_rent_rate: 18, property_utilities_rate: 2.5,
    property_description: 'Світлий офіс у центрі.', property_address: 'вул. Хрещатик, 1',
    property_has_parking: false, property_parking_spaces: 0, property_parking_type: null,
    property_ev_charger: false, property_sale_price: null, share_expires_at: null,
    db_id: '1', db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
    owner_first_name: 'Микола', owner_last_name: 'К.', owner_tg_username: 'mykola',
    owner_phone: '+380670000000', owner_currency: 'USD', photos: [],
  }
  const DB_ROWS = [{
    db_id: '1', db_name: 'БЦ Рубін', db_type: 'business_center', db_color: 'pink',
    share_expires_at: null, property_id: '2', property_name: 'Офіс 101',
    property_status: 'free', property_floor: '3', property_area_useful: 100,
    property_area_total: 120, property_rent_type: 'per_m2', property_rent_rate: 18,
    property_sale_price: null,
    property_description: 'Світлий офіс у центрі, панорамні вікна.',
    owner_first_name: 'Микола', owner_last_name: 'К.',
    owner_tg_username: 'mykola', owner_phone: '+380670000000', owner_currency: 'UAH',
    first_photo: null,
  }]
  const COL_ROWS = [{
    collection_id: '4', collection_name: 'Підбірка для клієнта', share_expires_at: null,
    realtor_first_name: 'Олена', realtor_last_name: 'Р.', realtor_tg_username: 'olena',
    realtor_phone: '+380670000001', property_id: '2', property_name: 'Квартира 12',
    property_status: 'free', property_floor: '5', property_area_useful: 60,
    property_area_total: 65, property_rent_type: 'per_m2', property_rent_rate: 15,
    property_description: null, db_id: '1', db_name: 'ЖК Липки', db_type: 'residential',
    db_color: 'blue', first_photo: null,
  }]
  await page.route('**/rest/v1/rpc/get_public_property_preview', (r) => json(r, [PROP_PREVIEW]))
  await page.route('**/rest/v1/rpc/get_public_db_preview', (r) => json(r, DB_ROWS))
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (r) => json(r, COL_ROWS))
  await page.route('**/rest/v1/rpc/record_public_view', (r) => json(r, true))

  await snap(page, 'v-property', async () => {
    await page.goto('/v/?prop=aabbccddeeff001122334455')
    await page.getByText('Офіс 101').first().waitFor({ timeout: 20_000 })
  })
  await snap(page, 'v-database', async () => {
    await page.goto('/v/?db=aabbccddeeff001122334455')
    await page.getByText('БЦ Рубін').first().waitFor({ timeout: 20_000 })
  })
  await snap(page, 'v-collection', async () => {
    await page.goto('/v/?col=aabbccddeeff001122334455')
    await page.getByText('Підбірка для клієнта').first().waitFor({ timeout: 20_000 })
  })
})
