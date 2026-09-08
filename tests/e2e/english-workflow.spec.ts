import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, type HarnessUser } from './helpers/harness'

/**
 * НАСКРІЗНИЙ ВОРКФЛОУ АНГЛОМОВНОГО КОРИСТУВАЧА — від входу до видалення акаунта.
 *
 * Чим це відрізняється від `language.spec.ts` і від аудиту екранів: ті питають,
 * ЯК ВИГЛЯДАЄ інтерфейс. Тут питання інше — чи ПРАЦЮЮТЬ самі флоу, коли мова
 * англійська. Клас дефектів, який видно лише так: рядок, що бере участь у
 * ПОРІВНЯННІ або в умові, перекладений — гілка мовчки йде не туди, а екран при
 * цьому виглядає бездоганно.
 */

const EN_USER: HarnessUser = {
  ...DEFAULT_USER,
  role: 'owner',
  first_name: 'Mykola',
  last_name: 'T',
  // Саме так виглядає користувач, чий Telegram англійською: edge-функція
  // пише `tgUser.language_code ?? 'uk'`, тобто 'en' потрапляє в базу з
  // ПЕРШОГО входу — ще до того, як він щось перемикав руками.
  language_code: 'en',
}

const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

async function seedBackend(page: Page, user: HarnessUser) {
  await setupApp(page, { user })
  await page.route('**/rest/v1/users**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? user : [user])
  })
  for (const t of ['databases', 'properties', 'notifications', 'property_views', 'db_members',
                   'rent_payments', 'rent_payment_records', 'collections', 'guest_links',
                   'property_photos', 'property_files', 'property_folders', 'realtor_subscriptions']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }
  await page.addInitScript(() => localStorage.setItem('ob_v1',
    JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test.describe('вхід англомовного користувача', () => {
  test('профіль каже en — застосунок стартує англійською БЕЗ ручного перемикання', async ({ page }) => {
    await seedBackend(page, EN_USER)
    // Кешований профіль є (звичайний холодний старт), а `ps_lang` НЕМАЄ —
    // саме так виглядає перший запуск, новий пристрій або почищений вебвʼю.
    await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), EN_USER)

    await page.goto('/')
    await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
    const txt = (await page.locator('#app-root').innerText()).trim()
    expect(CYR.test(txt), `екран український, хоч профіль каже en:\n${txt.slice(0, 300)}`).toBe(false)
  })

  test('перемикач лагодить розбіжність, а не відмовляється працювати', async ({ page }) => {
    await seedBackend(page, EN_USER)
    await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), EN_USER)
    // Симулюємо ВЖЕ наявну розбіжність: у профілі 'en', на пристрої 'uk'.
    await page.addInitScript(() => localStorage.setItem('ps_lang', 'uk'))

    await page.goto('/')
    await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await page.getByLabel('Профіль').click()
    await expect(page.getByText('Мова')).toBeVisible()

    // Профіль каже 'en', тож сегмент «Eng» уже підсвічений. Тап по ньому мусить
    // ПОЛАГОДИТИ мову — інакше користувач у пастці: показано англійську,
    // намальовано українську, і кнопка, яка це лікує, нічого не робить.
    await page.getByRole('button', { name: 'Eng' }).click()
    await expect(page.getByText('Language')).toBeVisible({ timeout: 10_000 })
  })
})

test('НОВИЙ користувач: онбординг цілком англійською, роль доїжджає на сервер', async ({ page }) => {
  // Ані `ps_lang`, ані кешу профілю — перший запуск у житті. Мова може прийти
  // ЛИШЕ з відповіді edge-функції, куди її кладе Telegram.
  await seedBackend(page, { ...EN_USER, role: null })

  await page.goto('/')
  await expect(page.getByText('Who are you?')).toBeVisible({ timeout: 20_000 })
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)

  // Картка ролі — не іменований клас, а `glass-s`/`glass-d` (обране/ні).
  await page.locator('.glass-s, .glass-d').filter({ hasText: 'Owner' }).first().click()
  const rolePatch = page.waitForRequest((r) => r.url().includes('/rest/v1/users') && r.method() === 'PATCH')
  await page.getByRole('button', { name: 'Continue →' }).click()
  const body = JSON.parse((await rolePatch).postData() ?? '{}')
  expect(body.role, 'роль не доїхала на сервер').toBe('owner')

  await expect(page.getByText('Contacts', { exact: true })).toBeVisible({ timeout: 10_000 })
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)
})

test('створення бази: форма англійська, POST несе введене', async ({ page }) => {
  await seedBackend(page, EN_USER)
  await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), EN_USER)

  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  // Порожній стан має ВЛАСНУ первинну дію, а плаваючий FAB там свідомо
  // схований (`fab-off`) — двох однакових дій на екрані бути не повинно.
  await page.getByRole('button', { name: 'Create the first database' }).click()
  await expect(page.getByText('New database')).toBeVisible()

  await page.getByPlaceholder('Olimp Business Centre').fill('Rubin BC')
  await page.locator('.type-card', { hasText: 'Business centre' }).click()
  const post = page.waitForRequest((r) => r.url().includes('/rest/v1/databases') && r.method() === 'POST')
  await page.getByRole('button', { name: 'Create database' }).click()
  const sent = JSON.parse((await post).postData() ?? '{}')
  const row = Array.isArray(sent) ? sent[0] : sent
  expect(row.name).toBe('Rubin BC')
  // ТИП МУСИТЬ ЛИШИТИСЬ СЛУЖБОВИМ ЗНАЧЕННЯМ, а не перекладеним підписом:
  // «Business centre» у колонці `type` зробила б базу нерозпізнаваною для
  // форми обʼєкта (паркінг-гілка) і для публічного превʼю.
  expect(row.type, 'у базу поїхав ПІДПИС замість значення').toBe('business_center')
})

// ── Фікстури для екранів, що потребують даних ────────────────────────────────
const DB = {
  id: 'db-1', name: 'Rubin BC', type: 'business_center', color: 'blue', icon: 'building',
  owner_id: EN_USER.id, created_at: '2026-01-01T00:00:00Z', share_token: 'dbtok',
  share_expires_at: null, landlord_name: null, description: null,
}
const PROP = {
  id: 'p-1', db_id: 'db-1', owner_id: EN_USER.id, name: 'Office 101', status: 'free',
  area_useful: 50, area_total: 60, area_basis: 'total', rent_type: 'per_m2', rent_rate: 18,
  utilities_rate: 2.5, floor: 3, sort_order: 100, created_at: '2026-01-01T00:00:00Z',
  tenant_name: null, lease_start_date: null, lease_end_date: null, sale_price: null,
  address: null, description: null, folder_id: null, share_token: 'ptok',
  parking_type: null, ev_charger: null, landlord_name: null,
}

async function seedWithData(page: Page, user = EN_USER) {
  await seedBackend(page, user)
  await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), user)
  await page.route('**/rest/v1/databases**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? PROP : [PROP])
  })
}

test('обʼєкти: статуси, гроші і суфікси одиниць англійською', async ({ page }) => {
  await seedWithData(page)
  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Rubin BC').first().click()

  await expect(page.getByText('All (1)')).toBeVisible({ timeout: 10_000 })
  // «Вільно» — це Vacant, а не Free: англійське `free` читається як
  // «безкоштовно», тобто статус перетворився б на обіцянку ціни.
  await expect(page.getByText('Vacant (1)')).toBeVisible()
  await expect(page.getByText('Occupied (0)')).toBeVisible()
  await expect(page.getByText('For sale (0)')).toBeVisible()

  // ГРОШІ: база розрахунку 'total' → 60 м² × 18 = 1080 оренда, × 2.5 = 150
  // експлуатаційні, разом 1230; роздільник тисяч — АНГЛІЙСЬКИЙ (кома).
  await expect(page.getByText('$1,230')).toBeVisible()
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)
})

test('оренда: форма англійська, PATCH несе службові значення', async ({ page }) => {
  await seedWithData(page)
  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Rubin BC').first().click()
  await page.getByText('Office 101').first().click()
  await expect(page.getByRole('button', { name: 'Let out' })).toBeVisible({ timeout: 10_000 })

  await page.getByRole('button', { name: 'Let out' }).click()
  await expect(page.getByText('Tenant')).toBeVisible({ timeout: 10_000 })
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)

  await page.getByLabel(/Tenant/i).first().fill('Acme Ltd')
  const patch = page.waitForRequest((r) => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
  await page.getByRole('button', { name: /^(Save|Let out)$/ }).first().click()
  const sent = JSON.parse((await patch).postData() ?? '{}')
  expect(sent.tenant_name).toBe('Acme Ltd')
  // СТАТУС — службове значення, а не підпис: 'Occupied' у колонці зробив би
  // обʼєкт невидимим для кожного фільтра і для публічного превʼю.
  expect(sent.status, 'у статус поїхав ПІДПИС замість значення').toBe('occupied')
})

test('вихід з акаунту: підтвердження англійське і застосунок вертає на Welcome', async ({ page }) => {
  await seedWithData(page)
  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByLabel('Profile').click()
  await expect(page.getByText('Settings')).toBeVisible({ timeout: 10_000 })
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)

  await page.getByRole('button', { name: 'Sign out' }).click()
  // Нативного `showPopup` у харнесі немає за замовчуванням — це слабший
  // клієнт, і тоді підтвердження малює наш `ConfirmHost`.
  await expect(page.getByText('Sign out?')).toBeVisible({ timeout: 10_000 })
  expect(CYR.test(await page.locator('#app-root').innerText()),
    'діалог виходу лишився українським').toBe(false)
})

test('видалення акаунта: слово підтвердження ПЕРЕКЛАДЕНЕ і збігається з перевіркою', async ({ page }) => {
  await seedWithData(page)
  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByLabel('Profile').click()
  await page.getByRole('button', { name: 'Delete account' }).click()
  await expect(page.getByText('Delete account?', { exact: true })).toBeVisible({ timeout: 10_000 })
  expect(CYR.test(await page.locator('#app-root').innerText())).toBe(false)

  const del = page.getByRole('button', { name: 'Delete account', exact: true }).last()
  await expect(del).toBeDisabled()

  // УКРАЇНСЬКЕ слово НЕ сміє вмикати кнопку англійською — інакше показане
  // слово і те, що перевіряється, розійшлись би, і користувач вписував би
  // «DELETE» у поле, яке чекає «ВИДАЛИТИ».
  await page.getByRole('textbox').first().fill('ВИДАЛИТИ')
  await expect(del, 'кнопку вмикає слово, якого на екрані немає').toBeDisabled()

  await page.getByRole('textbox').first().fill('DELETE')
  await expect(del, 'показане слово не вмикає кнопку — видалити акаунт НЕМОЖЛИВО').toBeEnabled()

  const rpc = page.waitForRequest((r) => r.url().includes('/rpc/delete_my_account'))
  await del.click()
  await rpc
})

test('платежі: календар англійський, сума — МІСЯЧНА, а не сира ставка', async ({ page }) => {
  const OCCUPIED = { ...PROP, status: 'occupied', tenant_name: 'Acme Ltd',
                     lease_start_date: '2026-01-01', lease_end_date: '2027-01-01' }
  await seedBackend(page, EN_USER)
  await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), EN_USER)
  await page.route('**/rest/v1/databases**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? OCCUPIED : [OCCUPIED])
  })
  // Без розкладу календар порожній ЗА ПОБУДОВОЮ — і саме на цьому перша
  // редакція тесту проходила, нічого не перевіряючи.
  const SCHEDULE = {
    id: 'rp-1', property_id: 'p-1', owner_id: EN_USER.id, due_day: 5,
    notify_days_before: 3, is_active: true,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  }
  await page.route('**/rest/v1/rent_payments**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? SCHEDULE : [SCHEDULE])
  })

  // ЧАС МОРОЗИМО, і це не перестраховка: хук бере день місяця з розкладу, тож
  // сама дата прогону вирішує, в яку секцію (і чи взагалі) впаде платіж. Перша
  // редакція без цього давала 2 проходи з 5 — нестабільний гард гірший за
  // відсутній. 2 червня при `due_day: 5` — платіж попереду й у ЦЬОМУ ж місяці.
  await page.clock.setFixedTime(new Date('2026-06-02T10:00:00Z'))

  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Rubin BC').first().click()
  await page.getByText('Office 101').first().click()
  await expect(page.getByText('Payments').first()).toBeVisible({ timeout: 10_000 })
  await page.getByText('Payments').first().click()

  await expect(page.getByText(/Payment calendar|Payments —/)).toBeVisible({ timeout: 10_000 })
  const txt = await page.locator('#app-root').innerText()
  expect(CYR.test(txt), `календар лишився українським:\n${txt.slice(0, 200)}`).toBe(false)
  // АНТИВАКУУМ: без цього рядка перевірка нижче проходить і на ПОРОЖНЬОМУ
  // екрані — сирої ставки там немає за побудовою, як не було й кирилиці в
  // спінері, на чому вже спалився інструмент живого обходу.
  expect(/\$1,0?80/.test(txt), `місячної суми на екрані немає:\n${txt.slice(0, 300)}`).toBe(true)
  // Сира ставка ($18/м²) на екрані платежів була б брехнею про суму до сплати —
  // той самий клас помилки, що вже коштував $2 160 замість $1 800.
  expect(txt.includes('$18\n') || /\$18\b(?!,)/.test(txt),
    'на екрані платежів сира ставка замість місячної суми').toBe(false)
})

test('експорт: екран англійський, і формат лишається службовим значенням', async ({ page }) => {
  await seedWithData(page)
  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Rubin BC').first().click()
  // Екран експорту відкривається з меню бази.
  await page.locator('.hdr-a').last().click()
  await page.waitForTimeout(420)
  const row = page.locator('.sheet-row').filter({ hasText: 'Export' })
  await expect(row.first()).toBeVisible({ timeout: 10_000 })
  await row.first().click()

  await expect(page.getByText('Download PDF')).toBeVisible({ timeout: 10_000 })
  const txt = await page.locator('#app-root').innerText()
  expect(CYR.test(txt), `екран експорту лишився українським:\n${txt.slice(0, 200)}`).toBe(false)
})
