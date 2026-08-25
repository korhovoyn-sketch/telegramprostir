import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, objectAction } from './helpers/harness'

/**
 * ТИМЧАСОВИЙ аудит усіх модалок: відкриття, ЗАКРИТТЯ кожним шляхом і вигляд.
 * Файл під `_` — у звичайний прогін не входить (див. testIgnore). Запуск:
 *   PERF=1 npx playwright test _modal-audit --workers=1
 */

const SHOTS = process.env.SHOTS_DIR ?? '/tmp/modal-shots'
const NOW = '2025-09-01T09:00:00.000Z'
const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Ірина' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const DB2_ID = '10000000-0000-0000-0000-000000000002'
const FOLDER_ID = '50000000-0000-0000-0000-000000000001'
const COL_ID = '70000000-0000-0000-0000-000000000001'

const json = (r: Route, body: unknown) =>
  r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

const db = (id: string, name: string) => ({
  id, owner_id: OWNER.id, name, address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: `aabbccddeeff0011223344${id.slice(-2)}`,
  share_expires_at: null, created_at: NOW, updated_at: NOW,
})
const DBS = [db(DB_ID, 'БЦ Рубін'), db(DB2_ID, 'БЦ Сапфір')]

function prop(i: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${i}`, db_id: DB_ID, owner_id: OWNER.id,
    name: `Офіс ${100 + i}`, floor: String(i + 1), status: 'free', area_useful: 45,
    area_total: 52, area_basis: 'total', rent_type: 'per_m2', rent_rate: 20, utilities_rate: 2,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: 'Світлий офіс.', address: null,
    sale_price: null, tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: i, share_token: `bb0000000000000000000000${i}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over,
  }
}
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120, lease_start_date: '2025-01-01', lease_end_date: '2026-01-01', folder_id: FOLDER_ID }),
  prop(2, { status: 'free' }),
]
const SCHEDULE = [{
  id: '80000000-0000-0000-0000-000000000001', property_id: PROPERTIES[0].id,
  owner_id: OWNER.id, due_day: 5, notify_days_before: 3, is_active: true,
  created_at: NOW, updated_at: NOW,
}]

async function ownerRoutes(page: Page) {
  await page.route('**/rest/v1/databases**', (r) => {
    if ((r.request().headers()['accept'] ?? '').includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, DBS.find((d) => d.id === m?.[1]) ?? DBS[0])
    }
    return json(r, DBS)
  })
  await page.route('**/rest/v1/properties**', (r) => {
    if ((r.request().headers()['accept'] ?? '').includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find((p) => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  await page.route('**/rest/v1/property_folders**', (r) => json(r, [
    { id: FOLDER_ID, db_id: DB_ID, owner_id: OWNER.id, name: 'Орендарі', sort_order: 1, created_at: NOW, updated_at: NOW },
  ]))
  await page.route('**/rest/v1/rent_payments**', (r) => json(r, SCHEDULE))
  await page.route('**/rest/v1/guest_links**', (r) => {
    if (r.request().method() === 'POST') return json(r, { invite_token: 'ee00112233445566778899bb' })
    return json(r, [{
      id: '30000000-0000-0000-0000-000000000001', owner_id: OWNER.id, property_id: null,
      db_id: DB_ID, invite_token: 'cc00112233445566778899aa', label: 'Орендар А',
      guest_user_id: null, status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/db_members**', (r) => {
    if (r.request().method() === 'POST') return json(r, { invite_token: 'ff00112233445566778899cc' })
    if (r.request().url().includes('user_id=eq.')) return json(r, [])
    return json(r, [{
      id: '40000000-0000-0000-0000-000000000001', db_id: DB_ID, user_id: '00000000-0000-0000-0000-000000000077',
      role: 'editor', invite_token: 'dd00112233445566778899', label: 'Менеджер',
      member_name: 'Оля Петренко', status: 'active', claimed_at: NOW, created_at: NOW,
    }])
  })
  await page.route('**/rest/v1/rpc/manage_share', (r) =>
    json(r, [{ share_token: DBS[0].share_token, share_expires_at: null, error: null }]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? OWNER : [OWNER]))
  for (const t of ['rent_payment_records', 'property_views', 'property_files', 'property_photos', 'notifications', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Чекає, поки попередній шит ДОГРАЄ вихід, і геометрія стане стабільною. */
async function settled(page: Page) {
  await expect(page.locator('.modal.closing')).toHaveCount(0, { timeout: 6_000 })
  await page.waitForTimeout(450)
}

/**
 * Знімок + структурні інваріанти вигляду. Міряється ПІСЛЯ стабілізації, бо
 * геометрія посеред `modalSlideUp` — це кадр анімації, а не верстка.
 */
async function shoot(page: Page, name: string) {
  await settled(page)
  const sheet = page.locator('.modal').last()
  await expect(sheet).toBeVisible()

  // Знімаємо фокус із поля ПЕРЕД заміром, і це не косметика. Шити, що самі
  // фокусують поле (оренда, інвайт, пікери в режимі створення), запускають
  // `kbFallback`: у безголовому браузері клавіатури НЕМА, платформа нічого не
  // звітує, і через 550мс шит підіймається на 320px над порожнім місцем. Це
  // задокументована поведінка (е2e не вміє показати нативну клавіатуру), але
  // замір «шит притиснутий до низу» від неї стає ЛОТЕРЕЄЮ: інвайт-шит проходив
  // лише тому, що його автофокус (400мс) не встигав добігти до порогу.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.())
  // kbDropRef 180мс + transition padding-bottom .25s — міряти можна лише після.
  await page.waitForTimeout(600)
  await page.screenshot({ path: `${SHOTS}/${name}.png` })

  const vh = page.viewportSize()!.height
  const vw = page.viewportSize()!.width
  const m = await sheet.evaluate((el) => {
    const r = el.getBoundingClientRect()
    const head = el.querySelector('.modal-h')
    const body = el.querySelector('.modal-body') as HTMLElement | null
    const acts = [...el.querySelectorAll<HTMLButtonElement>('.modal-actions .modal-btn')]
    return {
      x: Math.round(r.x), width: Math.round(r.width),
      top: Math.round(r.top), bottom: Math.round(r.bottom),
      title: (head?.textContent ?? '').trim(),
      overflowX: body ? body.scrollWidth - body.clientWidth : 0,
      radius: getComputedStyle(el).borderTopLeftRadius,
      actions: acts.map((b) => ({
        label: (b.textContent ?? '').trim(),
        h: Math.round(b.getBoundingClientRect().height),
        below: Math.round(b.getBoundingClientRect().bottom - r.bottom),
        disabled: b.disabled,
        opacity: Number(getComputedStyle(b).opacity),
      })),
    }
  })

  // Обрізаний текст: для `ellipsis+nowrap+hidden` єдиний надійний критерій —
  // scrollWidth > clientWidth на самому носії тексту. Leaf-фільтри його гублять,
  // бо підпис — це іконка + текстовий вузол.
  const truncated = await sheet.evaluate((el) =>
    [...el.querySelectorAll<HTMLElement>('*')]
      .filter((n) => {
        const st = getComputedStyle(n)
        return st.overflowX !== 'visible' && st.textOverflow === 'ellipsis' && n.scrollWidth - n.clientWidth > 0
      })
      .map((n) => `«${(n.textContent ?? '').trim().slice(0, 34)}» (.${n.className.toString().split(/\s+/)[0]}) обрізано на ${n.scrollWidth - n.clientWidth}px`))
  expect(truncated, `${name}: обрізаний текст`).toEqual([])

  // Кнопки дій не мають `text-overflow: ellipsis`, тож попередня перевірка їх НЕ
  // бачить: довгий підпис у них не обрізається видимо, а розпирає/впритул тисне
  // кнопку. Міряємо реальну ширину тексту проти внутрішньої ширини кнопки.
  const tight = await sheet.evaluate((el) =>
    [...el.querySelectorAll<HTMLButtonElement>('.modal-actions .modal-btn')]
      .map((b) => {
        const cs = getComputedStyle(b)
        const inner = b.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)
        const rng = document.createRange()
        rng.selectNodeContents(b)
        const textW = rng.getBoundingClientRect().width
        return { label: (b.textContent ?? '').trim(), overflowBy: Math.round(textW - inner) }
      })
      .filter((r) => r.overflowBy > 0)
      .map((r) => `«${r.label}» шириться за кнопку на ${r.overflowBy}px`))
  expect(tight, `${name}: підпис кнопки не вміщується`).toEqual([])

  expect(m.title, `${name}: порожній заголовок`).not.toBe('')
  expect(m.x, `${name}: шит не притиснутий до лівого краю (x=${m.x})`).toBe(0)
  expect(m.width, `${name}: ширина ${m.width} ≠ ширині екрана ${vw}`).toBe(vw)
  expect(m.top, `${name}: верх шита ВИЩЕ екрана (${m.top}) — ознака подвійного ліфта`).toBeGreaterThanOrEqual(0)
  expect(Math.abs(m.bottom - vh), `${name}: шит не притиснутий до низу (низ ${m.bottom} при висоті ${vh})`).toBeLessThanOrEqual(1)
  expect(m.overflowX, `${name}: горизонтальне переповнення тіла`).toBeLessThanOrEqual(1)
  expect(m.radius, `${name}: втрачено скруглення верхніх кутів`).not.toBe('0px')
  for (const a of m.actions) {
    expect(a.h, `${name} → «${a.label}»: висота ${a.h}px < 44 (Apple HIG)`).toBeGreaterThanOrEqual(44)
    expect(a.below, `${name} → «${a.label}» вилазить на ${a.below}px за низ шита`).toBeLessThanOrEqual(0)
    if (a.disabled) {
      expect(a.opacity, `${name} → «${a.label}»: неактивна через прозорість`).toBeGreaterThanOrEqual(0.9)
    }
  }
  return m.title
}

/** Закриття тапом по бекдропу. */
async function closeByBackdrop(page: Page, name: string) {
  const before = await page.locator('.modal').count()
  await page.locator('.modal-overlay').last().click({ position: { x: 10, y: 10 } })
  await expect(page.locator('.modal'), `${name}: бекдроп-тап не закрив шит`)
    .toHaveCount(before - 1, { timeout: 6_000 })
}

/** Закриття клавішею Escape. */
async function closeByEscape(page: Page, name: string) {
  const before = await page.locator('.modal').count()
  await page.keyboard.press('Escape')
  await expect(page.locator('.modal'), `${name}: Escape не закрив шит`)
    .toHaveCount(before - 1, { timeout: 6_000 })
}

/** Закриття кнопкою «Скасувати»/«Закрити»/«Готово» в actions. */
async function closeByCancel(page: Page, name: string) {
  const before = await page.locator('.modal').count()
  const btn = page.locator('.modal').last()
    .locator('.modal-actions .modal-btn')
    .filter({ hasText: /Скасувати|Закрити|Готово/ })
  await expect(btn, `${name}: немає кнопки скасування в actions`).toHaveCount(1)
  await btn.click()
  await expect(page.locator('.modal'), `${name}: кнопка скасування не закрила шит`)
    .toHaveCount(before - 1, { timeout: 6_000 })
}

async function toObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (2)')).toBeVisible({ timeout: 15_000 })
}

async function menu(page: Page, item: string) {
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.getByText(item, { exact: true }).click()
}

// ─────────────────────────────────────────────────────────────────────────────

test('база: меню, папки, пікер папок, пікер баз', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // 1. Меню бази — закриваємо кнопкою «Скасувати» (вона тепер в actions).
  await toObjects(page)
  await page.getByLabel('Меню бази').click()
  expect(await shoot(page, '01-db-menu')).toBe('БЦ Рубін')
  await closeByCancel(page, '01-db-menu')

  // …і повторно, щоб перевірити ДРУГИЙ шлях закриття — Escape.
  await page.getByLabel('Меню бази').click()
  await settled(page)
  await closeByEscape(page, '01-db-menu (escape)')

  // 2. Папки — «Готово» + бекдроп.
  await menu(page, 'Папки')
  expect(await shoot(page, '02-folders')).toBe('Папки')
  await closeByCancel(page, '02-folders')
  await menu(page, 'Папки')
  await settled(page)
  await closeByBackdrop(page, '02-folders (backdrop)')

  // 3. Пікер папок (bulk) + 4. пікер баз.
  await menu(page, 'Виділити об\'єкти')
  await page.locator('.obj-card').first().click()
  await expect(page.locator('.batchbar')).toBeVisible()
  await page.locator('.batch-pill', { hasText: 'У папку' }).click()
  await shoot(page, '03-folder-picker')
  await closeByCancel(page, '03-folder-picker')

  await page.locator('.batch-pill').filter({ hasText: /базу|Перенести/ }).first().click()
  expect(await shoot(page, '04-db-picker')).toBe('Перенести в базу')
  await closeByEscape(page, '04-db-picker')
})

test('обʼєкт: оренда, пікер папки у формі', async ({ page }) => {
  // Розклад платежів і підтвердження платежу — тепер повноекранні маршрути
  // (фаза 2 переробки модалок), не шити: цей інструмент знімає лише
  // ActionSheet/Modal-інстанси, для екранів огляд не потрібен окремо.
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // 5. «Здати в оренду».
  await toObjects(page)
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: /Здати в оренду/ }).click()
  expect(await shoot(page, '05-rent')).toBe('Здати в оренду')
  await closeByCancel(page, '05-rent')

  // 8. Пікер папки у ФОРМІ обʼєкта (інший інстанс, ніж bulk).
  await toObjects(page)
  await objectAction(page, 'Редагувати')
  await expect(page.getByText('Редагування')).toBeVisible({ timeout: 15_000 })
  const folderRow = page.getByText(/Папка/).first()
  if (await folderRow.count()) {
    await folderRow.click()
    if (await page.locator('.modal').count()) {
      await shoot(page, '08-folder-picker-form')
      await closeByEscape(page, '08-folder-picker-form')
    }
  }
})

test('доступи: гості, команда, створене посилання, шаринг', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)

  // 9-12. Запросити гостя/команду + створене посилання — фаза 3 переробки
  // модалок (atomic-riding-clock.md) перевела InviteSheet/CreatedLinkSheet на
  // повноекранний CreateInviteScreen; обидва кроки оглядаються звичайним
  // скріном екрана, не цим модалка-специфічним інструментом.

  // 13. ShareSheet бази.
  await toObjects(page)
  await menu(page, 'Аналітика і поширення')
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await shoot(page, '13-share-sheet')

  // 14. Вкладене підтвердження ПОВЕРХ ShareSheet — і воно не має затемнювати вдруге.
  await page.locator('.modal .sheet-row', { hasText: 'Відкликати доступ' }).click()
  await expect(page.locator('.modal')).toHaveCount(2)
  await shoot(page, '14-nested-confirm')
  // Вкладений оверлей мусить затемнювати СЛАБШЕ за базовий, але НЕ зникати:
  // без нього підтвердження лягає на живий, нерозмитий шит під ним.
  const dim = await page.locator('.modal-overlay').evaluateAll((els) =>
    els.map((e) => {
      const s = getComputedStyle(e)
      const a = /rgba?\([^)]*?([\d.]+)\)$/.exec(s.backgroundColor)
      return { alpha: a ? Number(a[1]) : 1, blur: s.backdropFilter }
    }))
  expect(dim[1].alpha, 'вкладений оверлей перестав відділяти підтвердження від шита').toBeGreaterThan(0.1)
  expect(dim[1].alpha, 'вкладений оверлей затемнює як повноцінний — разом виходить майже чорне')
    .toBeLessThan(dim[0].alpha)
  expect(dim[1].blur, 'вкладений оверлей утратив розмиття нижнього шита').not.toBe('none')
  await closeByEscape(page, '14-nested-confirm')
  // Нижній шит мусить ВИЖИТИ — Escape закриває лише верхню модалку стеку.
  await expect(page.locator('.modal'), 'Escape зніс і нижній шит').toHaveCount(1)
  await closeByBackdrop(page, '13-share-sheet')
})

test('профіль: підтвердження виходу і видалення акаунта', async ({ page }) => {
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })

  // 15. Вихід — фолбек-модалка ConfirmHost (нативного попапа в цьому клієнті нема).
  await page.getByRole('button', { name: /Вийти з акаунту/ }).click()
  expect(await shoot(page, '15-logout-confirm')).toBe('Вийти з акаунту?')
  await closeByCancel(page, '15-logout-confirm')

  // 16. Видалення акаунта — власна модалка з типізованим підтвердженням.
  await page.getByRole('button', { name: /Видалити акаунт/ }).click()
  expect(await shoot(page, '16-delete-account')).toBe('Видалити акаунт?')
  const confirm = page.locator('.modal-btn').filter({ hasText: /Видалити/ }).last()
  await expect(confirm, 'кнопка активна ще до введення слова').toBeDisabled()
  await closeByBackdrop(page, '16-delete-account')
})

test('рієлтор: підбірка — додати обʼєкт і поширити', async ({ page }) => {
  test.setTimeout(180_000)
  await setupApp(page, { user: REALTOR })
  await ownerRoutes(page)
  await page.route('**/rest/v1/realtor_subscriptions**', (r) => json(r, [
    { id: '60000000-0000-0000-0000-000000000001', realtor_id: REALTOR.id, db_id: DB_ID, created_at: NOW, database: DBS[0] },
  ]))
  await page.route('**/rest/v1/collections**', (r) => json(r, [{
    id: COL_ID, realtor_id: REALTOR.id, name: 'Для клієнта А', client_name: 'Іван',
    share_token: 'cc00112233445566778899dd', share_expires_at: null, is_draft: false,
    // Непорожня СВІДОМО: `shareCollection()` правильно відмовляється ділитися
    // порожньою підбіркою («Підбірка порожня»), тож із нулем обʼєктів шит
    // шаринга не відкрився б узагалі — і це не дефект, а гілка продукту.
    created_at: NOW, updated_at: NOW, collection_properties: [{ count: 1 }],
  }]))
  await page.route('**/rest/v1/collection_properties**', (r) => json(r, [
    { id: '90000000-0000-0000-0000-000000000001', collection_id: COL_ID,
      property_id: PROPERTIES[0].id, created_at: NOW, property: PROPERTIES[0] },
  ]))

  await page.goto('/')
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await expect(page.getByText('Для клієнта А')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Для клієнта А').click()

  // 17. «Додати обʼєкт» у підбірку.
  const addBtn = page.getByRole('button', { name: /Додати об/ }).first()
  if (await addBtn.count()) {
    await addBtn.click()
    if (await page.locator('.modal').count()) {
      expect(await shoot(page, '17-collection-add')).toBe('Додати об\'єкт')
      await closeByCancel(page, '17-collection-add')
    }
  }

  // 18. ShareSheet підбірки — тригер має власний aria-label.
  const share = page.getByLabel('Поділитись підбіркою').first()
  await expect(share, 'кнопка поширення підбірки не знайдена').toHaveCount(1)
  await share.click()
  await shoot(page, '18-share-collection')
  await closeByBackdrop(page, '18-share-collection')
})

test('шаринг у стані «посилання ще не створено» — кнопка ретраю в межах QR-плитки', async ({ page }) => {
  // Легасі-рядок БЕЗ токена + збій фонового генерування: єдиний шлях побачити
  // `.qr-retry`. Жоден тест у цей стан не заходив, а підпис «Створити посилання»
  // живе в плитці 124×124 на БІЛОМУ тлі — тобто рискує вилізти за неї.
  test.setTimeout(120_000)
  await setupApp(page, { user: OWNER })
  await ownerRoutes(page)
  const noToken = { ...DBS[0], share_token: null, share_expires_at: null }
  await page.route('**/rest/v1/databases**', (r) => {
    if ((r.request().headers()['accept'] ?? '').includes('object')) return json(r, noToken)
    return json(r, [noToken, DBS[1]])
  })
  // Фонове першогенерування ПАДАЄ — інакше шит одразу отримав би токен.
  await page.route('**/rest/v1/rpc/manage_share', (r) =>
    r.fulfill({ status: 500, contentType: 'application/json', body: '{"message":"boom"}' }))

  await toObjects(page)
  await menu(page, 'Аналітика і поширення')
  await expect(page.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await page.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await shoot(page, '19-share-no-link')

  const retry = page.locator('.qr-retry')
  await expect(retry, 'кнопка ретраю не показалась — шит лишився з вічним спінером').toHaveCount(1)
  const fit = await retry.evaluate((b) => {
    const box = b.parentElement!.getBoundingClientRect()
    const r = b.getBoundingClientRect()
    return { overflowX: Math.round(r.width - box.width), overflowY: Math.round(r.height - box.height),
             label: (b.textContent ?? '').trim() }
  })
  expect(fit.overflowX, `«${fit.label}» шириться за QR-плитку на ${fit.overflowX}px`).toBeLessThanOrEqual(0)
  expect(fit.overflowY, `«${fit.label}» вилазить за QR-плитку по висоті на ${fit.overflowY}px`).toBeLessThanOrEqual(0)
  await closeByBackdrop(page, '19-share-no-link')
})
