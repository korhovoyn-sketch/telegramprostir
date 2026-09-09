import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, type HarnessUser } from './helpers/harness'
import { EN } from '../../src/lib/dict-en'

/**
 * НАСКРІЗНИЙ ВОРКФЛОУ — від входу до видалення акаунта, ОБОМА МОВАМИ.
 *
 * Чим це відрізняється від аудиту екранів і від `language.spec.ts`: ті питають,
 * ЯК ВИГЛЯДАЄ інтерфейс. Тут питання інше — чи ПРАЦЮЮТЬ самі флоу. Клас
 * дефектів, який видно лише так: рядок, що бере участь у ПОРІВНЯННІ або в
 * умові, перекладений — гілка мовчки йде не туди, а екран виглядає бездоганно.
 *
 * ОДИН ОБХІД НА ДВІ МОВИ, А НЕ ДВІ КОПІЇ. Копія розійшлася б за раунд, і
 * «українською все гаразд» перестало б означати те саме, що англійською — цей
 * проєкт уже платив за такий дрейф тричі (`ManageGuestsScreen`/`TeamScreen`,
 * `InviteSheet`, і сам обхід екранів). Тому кроки написані УКРАЇНСЬКИМИ
 * ключами, а `L()` бере переклад із ТОГО САМОГО словника, що й інтерфейс.
 *
 * Побічний і головний виграш: українська гілка — це ПОЗИТИВНИЙ КОНТРОЛЬ.
 * Перевірка «кирилиці немає» англійською нічого не варта, якщо той самий крок
 * не доводить, що українською кирилиця Є: інакше порожній чи зламаний екран
 * нерозрізненний від перекладеного (на цьому вже спалився інструмент живого
 * обходу — спінер кирилиці не має ЗА ПОБУДОВОЮ).
 */

type Lang = 'uk' | 'en'
const LANGS: Lang[] = ['uk', 'en']

/** Підпис цією мовою. Ключ — український рядок, як і в самому застосунку. */
const L = (lang: Lang, uk: string): string => (lang === 'uk' ? uk : (EN[uk] ?? uk))

const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

/**
 * Роздільник тисяч іде за ЛОКАЛЛЮ, і саме тут ловиться захардкоджена 'uk-UA'.
 * Перевіряються ОБИДВІ половини: правильна форма Є, чужа — відсутня. Інакше
 * «мова перемкнулась наполовину» лишалось би невидимим.
 */
const MONEY: Record<Lang, { ok: RegExp; alien: RegExp }> = {
  uk: { ok: /\$1[\s  ]230/, alien: /\$1,230/ },
  en: { ok: /\$1,230/, alien: /\$1[\s  ]230/ },
}

const userFor = (lang: Lang): HarnessUser => ({
  ...DEFAULT_USER,
  role: 'owner',
  // Імʼя ЛАТИНКОЮ навмисно: воно рендериться як ДАНІ (заголовок профілю,
  // ініціал аватара), тож із кириличним імʼям англійська гілка падала б на
  // самому користувачі, а не на неперекладеному інтерфейсі.
  first_name: 'Mykola',
  last_name: 'T',
  // Фікстура УЗГОДЖЕНА: `setupApp` віддає цього ж користувача як відповідь
  // логіну, а роут `users` — як рядок таблиці. Розбіжність між цими двома
  // джерелами колись тихо жила в `language.spec` і проявилась лише тоді, коли
  // за `language_code` нарешті пішов код.
  language_code: lang,
})

/** Дані фікстур НЕ перекладаються — це рядки в БД, а не інтерфейс. */
const DB = {
  id: 'db-1', name: 'Rubin BC', type: 'business_center', color: 'blue', icon: 'building',
  owner_id: DEFAULT_USER.id, created_at: '2026-01-01T00:00:00Z', share_token: 'dbtok',
  share_expires_at: null, landlord_name: null, description: null,
}
const PROP = {
  id: 'p-1', db_id: 'db-1', owner_id: DEFAULT_USER.id, name: 'Office 101', status: 'free',
  area_useful: 50, area_total: 60, area_basis: 'total', rent_type: 'per_m2', rent_rate: 18,
  utilities_rate: 2.5, floor: 3, sort_order: 100, created_at: '2026-01-01T00:00:00Z',
  tenant_name: null as string | null,
  lease_start_date: null as string | null,
  lease_end_date: null as string | null,
  sale_price: null, address: null, description: null, folder_id: null,
  share_token: 'ptok', parking_type: null, ev_charger: null, landlord_name: null,
}

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

async function seedWithData(page: Page, user: HarnessUser, prop = PROP) {
  await seedBackend(page, user)
  await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), user)
  await page.route('**/rest/v1/databases**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (r: Route) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? prop : [prop])
  })
}

/**
 * Мова екрана як ІНВАРІАНТ, а не як одностороння перевірка: англійською
 * кирилиці бути не повинно, українською вона МУСИТЬ бути.
 */
async function assertLang(page: Page, lang: Lang, where: string) {
  const txt = (await page.locator('#app-root').innerText()).trim()
  if (lang === 'en') {
    expect(CYR.test(txt), `${where}: екран лишився українським:\n${txt.slice(0, 300)}`).toBe(false)
  } else {
    expect(CYR.test(txt), `${where}: українською кирилиці НЕМА — екран порожній або зламаний`).toBe(true)
  }
}

for (const lang of LANGS) {
  test.describe(`воркфлоу — ${lang}`, () => {
    const USER = userFor(lang)
    const t = (uk: string) => L(lang, uk)

    test('онбординг НОВОГО користувача: мова з профілю, роль доїжджає на сервер', async ({ page }) => {
      // Ані `ps_lang`, ані кешу профілю — перший запуск у житті. Мова може
      // прийти ЛИШЕ з відповіді edge-функції, куди її кладе Telegram.
      await seedBackend(page, { ...USER, role: null })

      await page.goto('/')
      await expect(page.getByText(t('Хто ти?'))).toBeVisible({ timeout: 20_000 })
      await assertLang(page, lang, 'вибір ролі')

      // Картка ролі — не іменований клас, а `glass-s`/`glass-d` (обране/ні).
      await page.locator('.glass-s, .glass-d').filter({ hasText: t('Власник') }).first().click()
      const rolePatch = page.waitForRequest((r) => r.url().includes('/rest/v1/users') && r.method() === 'PATCH')
      await page.getByRole('button', { name: t('Продовжити →') }).click()
      const body = JSON.parse((await rolePatch).postData() ?? '{}')
      expect(body.role, 'роль не доїхала на сервер').toBe('owner')

      await expect(page.getByText(t('Контакти'), { exact: true })).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'контакти')
    })

    test('створення бази: POST несе введене, а тип лишається СЛУЖБОВИМ значенням', async ({ page }) => {
      await seedBackend(page, USER)
      await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), USER)

      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      // Порожній стан має ВЛАСНУ первинну дію, а плаваючий FAB там свідомо
      // схований (`fab-off`) — двох однакових дій на екрані бути не повинно.
      await page.getByRole('button', { name: t('Створити першу базу') }).click()
      await expect(page.getByText(t('Нова база'))).toBeVisible()

      await page.getByPlaceholder(t('БЦ Олімп')).fill('Rubin BC')
      await page.locator('.type-card', { hasText: t('Бізнес-центр') }).click()
      const post = page.waitForRequest((r) => r.url().includes('/rest/v1/databases') && r.method() === 'POST')
      await page.getByRole('button', { name: t('Створити базу') }).click()
      const sent = JSON.parse((await post).postData() ?? '{}')
      const row = Array.isArray(sent) ? sent[0] : sent
      expect(row.name).toBe('Rubin BC')
      // Перекладений ПІДПИС у колонці `type` зробив би базу нерозпізнаваною
      // для форми обʼєкта (паркінг-гілка) і для публічного превʼю.
      expect(row.type, 'у базу поїхав ПІДПИС замість значення').toBe('business_center')
    })

    test('обʼєкти: статуси, і гроші за ЛОКАЛЛЮ мови', async ({ page }) => {
      await seedWithData(page, USER)
      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByText('Rubin BC').first().click()

      await expect(page.getByText(`${t('Всі')} (1)`)).toBeVisible({ timeout: 10_000 })
      // «Вільно» англійською — Vacant, а не Free: `free` читається як
      // «безкоштовно», тобто статус став би обіцянкою ціни.
      await expect(page.getByText(`${t('Вільно')} (1)`)).toBeVisible()
      await expect(page.getByText(`${t('Зайнято')} (0)`)).toBeVisible()
      await expect(page.getByText(`${t('Продаж')} (0)`)).toBeVisible()

      // ГРОШІ: база розрахунку 'total' → 60 м² × 18 = 1080 оренда,
      // × 2.5 = 150 експлуатаційні, разом 1230.
      const txt = await page.locator('#app-root').innerText()
      expect(MONEY[lang].ok.test(txt), `суми ${lang}-формату немає:\n${txt.slice(0, 300)}`).toBe(true)
      expect(MONEY[lang].alien.test(txt), 'роздільник тисяч від ЧУЖОЇ локалі').toBe(false)
      await assertLang(page, lang, 'список обʼєктів')
    })

    test('оренда: PATCH несе орендаря і СЛУЖБОВИЙ статус', async ({ page }) => {
      await seedWithData(page, USER)
      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByText('Rubin BC').first().click()
      await page.getByText('Office 101').first().click()
      const cta = page.getByRole('button', { name: t('Здати в оренду') })
      await expect(cta).toBeVisible({ timeout: 10_000 })

      await cta.click()
      await expect(page.getByText(t('Орендар')).first()).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'форма оренди')

      await page.getByLabel(new RegExp(t('Орендар'), 'i')).first().fill('Acme Ltd')
      const patch = page.waitForRequest((r) => r.url().includes('/rest/v1/properties') && r.method() === 'PATCH')
      await page.getByRole('button', { name: new RegExp(`^(${t('Зберегти')}|${t('Здати в оренду')})$`) }).first().click()
      const sent = JSON.parse((await patch).postData() ?? '{}')
      expect(sent.tenant_name).toBe('Acme Ltd')
      // Перекладений статус зробив би обʼєкт невидимим для КОЖНОГО фільтра
      // і для публічного превʼю.
      expect(sent.status, 'у статус поїхав ПІДПИС замість значення').toBe('occupied')
    })

    test('платежі: сума МІСЯЧНА, а не сира ставка', async ({ page }) => {
      const OCCUPIED = { ...PROP, status: 'occupied', tenant_name: 'Acme Ltd',
                         lease_start_date: '2026-01-01', lease_end_date: '2027-01-01' }
      await seedWithData(page, USER, OCCUPIED)
      // Без розкладу календар порожній ЗА ПОБУДОВОЮ — і саме на цьому перша
      // редакція тесту проходила, нічого не перевіряючи.
      const SCHEDULE = {
        id: 'rp-1', property_id: 'p-1', owner_id: USER.id, due_day: 5,
        notify_days_before: 3, is_active: true,
        created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      }
      await page.route('**/rest/v1/rent_payments**', (r: Route) => {
        const obj = (r.request().headers()['accept'] ?? '').includes('object')
        return jsonRoute(r, obj ? SCHEDULE : [SCHEDULE])
      })

      // ЧАС МОРОЗИМО, і це не перестраховка: хук бере день місяця з розкладу,
      // тож сама дата прогону вирішує, в яку секцію (і чи взагалі) впаде
      // платіж. Без цього крок давав 2 проходи з 5 — нестабільний гард гірший
      // за відсутній. 2 червня при `due_day: 5` — платіж попереду й у ЦЬОМУ
      // ж місяці.
      await page.clock.setFixedTime(new Date('2026-06-02T10:00:00Z'))

      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByText('Rubin BC').first().click()
      await page.getByText('Office 101').first().click()
      await expect(page.getByText(t('Платежі')).first()).toBeVisible({ timeout: 10_000 })
      await page.getByText(t('Платежі')).first().click()

      await expect(page.getByText(new RegExp(`${t('Календар платежів')}|${t('Платежі')} —`)))
        .toBeVisible({ timeout: 10_000 })
      const txt = await page.locator('#app-root').innerText()
      await assertLang(page, lang, 'календар платежів')
      // АНТИВАКУУМ: без цього рядка перевірка нижче проходить і на ПОРОЖНЬОМУ
      // екрані — сирої ставки там немає за побудовою.
      expect(/1[\s  ,]?0?80/.test(txt),
        `місячної суми на екрані немає:\n${txt.slice(0, 300)}`).toBe(true)
      // Сира ставка ($18/м²) на екрані платежів була б брехнею про суму до
      // сплати — той самий клас, що вже коштував $2 160 замість $1 800.
      expect(/\$18\b(?![\s  ,]\d)/.test(txt),
        'на екрані платежів сира ставка замість місячної суми').toBe(false)
    })

    test('експорт відкривається з меню бази', async ({ page }) => {
      await seedWithData(page, USER)
      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByText('Rubin BC').first().click()
      await page.locator('.hdr-a').last().click()
      await page.waitForTimeout(420)
      const row = page.locator('.sheet-row').filter({ hasText: t('Експорт') })
      await expect(row.first()).toBeVisible({ timeout: 10_000 })
      await row.first().click()

      await expect(page.getByText(t('Завантажити PDF'))).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'експорт')
    })

    test('вихід з акаунту: підтвердження тією ж мовою', async ({ page }) => {
      await seedWithData(page, USER)
      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByLabel(t('Профіль')).click()
      await expect(page.getByText(t('Налаштування'))).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'профіль')

      await page.getByRole('button', { name: t('Вийти') }).click()
      // Нативного `showPopup` у харнесі немає за замовчуванням — це слабший
      // клієнт, і тоді підтвердження малює наш `ConfirmHost`.
      await expect(page.getByText(t('Вийти з акаунту?'))).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'діалог виходу')
    })

    test('видалення акаунта: слово підтвердження збігається з тим, що перевіряє код', async ({ page }) => {
      await seedWithData(page, USER)
      await page.goto('/')
      await expect(page.getByText(t('Мої бази'))).toBeVisible({ timeout: 20_000 })
      await page.getByLabel(t('Профіль')).click()
      await page.getByRole('button', { name: t('Видалити акаунт') }).click()
      await expect(page.getByText(t('Видалити акаунт?'), { exact: true })).toBeVisible({ timeout: 10_000 })
      await assertLang(page, lang, 'видалення акаунта')

      const del = page.getByRole('button', { name: t('Видалити акаунт'), exact: true }).last()
      await expect(del).toBeDisabled()

      // Слово ІНШОЇ мови НЕ сміє вмикати кнопку — інакше показане слово і те,
      // що перевіряється, розійшлись би, і користувач вписував би одне у поле,
      // яке чекає інше.
      const other = lang === 'uk' ? L('en', 'ВИДАЛИТИ') : 'ВИДАЛИТИ'
      await page.getByRole('textbox').first().fill(other)
      await expect(del, 'кнопку вмикає слово, якого на екрані немає').toBeDisabled()

      await page.getByRole('textbox').first().fill(t('ВИДАЛИТИ'))
      await expect(del, 'показане слово не вмикає кнопку — видалити акаунт НЕМОЖЛИВО').toBeEnabled()

      const rpc = page.waitForRequest((r) => r.url().includes('/rpc/delete_my_account'))
      await del.click()
      await rpc
    })
  })
}

/**
 * ВХІД АНГЛОМОВНОГО КОРИСТУВАЧА — не параметризується, бо це саме про
 * розбіжність між профілем і пристроєм, а не про мову як таку.
 */
test.describe('вхід англомовного користувача', () => {
  const EN_USER = userFor('en')

  test('профіль каже en — застосунок стартує англійською БЕЗ ручного перемикання', async ({ page }) => {
    await seedBackend(page, EN_USER)
    // Кешований профіль є (звичайний холодний старт), а `ps_lang` НЕМАЄ —
    // саме так виглядає перший запуск, новий пристрій або почищений вебвʼю.
    await page.addInitScript((u) => localStorage.setItem('ps_user', JSON.stringify(u)), EN_USER)

    await page.goto('/')
    await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
    await assertLang(page, 'en', 'старт із профілю')
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

    // Профіль каже 'en', тож сегмент «Eng» уже підсвічений. Тап по ньому
    // мусить ПОЛАГОДИТИ мову — інакше користувач у пастці: показано
    // англійську, намальовано українську, і кнопка, яка це лікує, мовчить.
    await page.getByRole('button', { name: 'Eng' }).click()
    await expect(page.getByText('Language')).toBeVisible({ timeout: 10_000 })
  })
})
