import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession, skipCoachmarks } from './helpers/harness'

/**
 * Стани завантаження: стабільність лейауту і матриця станів на екран.
 *
 * **Чому тут не один CLS-гард, а три різні перевірки.** Layout Instability API
 * (`layout-shift`) рахує лише зсуви елементів, які ПЕРЕЖИЛИ кадр — тобто
 * існували до і після і змінили позицію. У нас перехід скелетон → контент
 * замінює піддерево цілком: заглушки видаляються, картки додаються, і жоден
 * запис у метрику не потрапляє. Заміряно: під час реального завантаження
 * `performance.getEntriesByType('layout-shift').length === 0`, тоді як
 * штучний зсув персистентного елемента (`marginTop:120px` на `.list`) дає
 * CLS 0.139. Тож CLS тут покриває РІВНО один клас — рух хрому, що лишається на
 * місці; решту треба міряти геометрією напряму, інакше гард порожній.
 *
 * Друга прогалина: **скелетони не згадувались у жодному тесті**, хоч
 * `SkeletonLoader` стоїть на 5 екранах, `SkeletonList` — на 7, а `RetryState`
 * — на 8. «Завантаження» перевірялось лише як тайминг, а не як стан, який
 * користувач бачить.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROPS = Array.from({ length: 6 }, (_, i) => ({
  id: `20000000-0000-0000-0000-00000000000${i + 1}`, db_id: DB_ID, owner_id: USER.id,
  name: `Офіс ${101 + i}`, floor: String(i + 1), status: i % 2 ? 'free' : 'occupied',
  area_useful: 100 + i, area_total: 120 + i, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 18, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null,
  utilities: null, description: null, address: null, sale_price: null,
  tenant_name: i % 2 ? null : `ТОВ ${i}`, lease_start_date: '2025-01-01',
  lease_end_date: '2026-01-01', sort_order: i,
  share_token: `bb000000000000000000${i + 10}`, share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 0,
}))

const json = (r: Route, body: unknown, status = 200) =>
  r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

/**
 * Лічильник стрибків лейауту. Ставиться init-скриптом ДО першого рендера і
 * `buffered: true` — інакше зсуви, що стались до підписки (а це саме перший
 * прийом даних), не порахуються взагалі.
 */
async function installCLS(page: Page) {
  await page.addInitScript(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).__cls = 0
    try {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          const s = entry as PerformanceEntry & { value: number; hadRecentInput: boolean }
          // Зсуви ПІСЛЯ дії користувача не рахуються — це очікувана реакція,
          // а не смикання під пальцем.
          if (!s.hadRecentInput) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ;(window as any).__cls += s.value
          }
        }
      }).observe({ type: 'layout-shift', buffered: true })
    } catch { /* браузер без layout-shift — метрика лишиться нулем */ }
  })
}

const readCLS = (page: Page) =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page.evaluate(() => Math.round(((window as any).__cls as number) * 1000) / 1000)

interface Opts {
  /** Затримка відповіді, щоб скелетон встиг проявитись. */
  delay?: number
  /** Порожні списки замість даних. */
  empty?: boolean
  /** 500 на properties + databases. */
  fail?: boolean
}

async function setup(page: Page, o: Opts = {}) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await skipCoachmarks(page)

  const reply = async (r: Route, body: unknown) => {
    if (o.delay) await new Promise((res) => setTimeout(res, o.delay))
    if (o.fail) return json(r, { message: 'boom' }, 500)
    return json(r, body)
  }
  await page.route('**/rest/v1/databases**', (r) =>
    reply(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : (o.empty ? [] : [DB])))
  await page.route('**/rest/v1/properties**', (r) =>
    reply(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROPS[0] : (o.empty ? [] : PROPS)))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
}

/** Екран не в ErrorBoundary. */
const alive = (page: Page, where: string) =>
  expect(page.getByText('Щось пішло не так'), `${where}: екран у ErrorBoundary`).toHaveCount(0)

// ── Стабільність лейауту ─────────────────────────────────────────────────────

/**
 * Позиції елементів, які МУСЯТЬ пережити прихід даних не зрушивши — зняті на
 * СТАБІЛЬНОМУ кадрі (три однакові кадри підряд).
 *
 * Чому не миттєвий замір: **старт застосунку осідає САМ, один раз, і це не має
 * стосунку до даних.** `#app-root` живе на `var(--tg-vh, 100svh)`, тобто до
 * того, як mount-ефект `page.tsx` запише реальну висоту від Telegram, лейаут
 * стоїть на висоті вікна. Коли саме приходить цей запис — залежить від
 * середовища: локально (dev) він встигає ДО першого скелетона, на CI
 * (прод-білд під `serve`) — ПІСЛЯ. Через це замір «до» ловив різні боки одного
 * й того ж осідання, і гард падав на ЧУЖОМУ зсуві (`.tabbar 593 → 512`)
 * замість зсуву від приходу даних. Очікування самої змінної `--tg-vh` це НЕ
 * лікує: локально вона вже виставлена на момент першого скелетона, тож
 * очікування — no-op, і різниця середовищ лишається.
 */
const anchors = (page: Page, stableFrames = 20, budgetFrames = 240) =>
  page.evaluate(({ need, budget }) =>
    new Promise<Record<string, number>>((resolve, reject) => {
      const read = () => {
        const out: Record<string, number> = {}
        for (const sel of ['.hdr', '.display', '.stat-g', '.seg', '.tabbar', '.fbtn']) {
          const el = document.querySelector(sel) as HTMLElement | null
          if (el) out[sel] = Math.round(el.getBoundingClientRect().top)
        }
        return out
      }
      let prev = ''
      let same = 0
      let frames = 0
      const tick = () => {
        const cur = read()
        const key = JSON.stringify(cur)
        if (key === prev) same++
        else { same = 0; prev = key }
        if (same >= need) return resolve(cur)
        if (++frames > budget) return reject(new Error(`хром не стабілізувався за ${budget} кадрів`))
        requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    }), { need: stableFrames, budget: budgetFrames })

test('прихід даних не зрушує хром екрана (заміряні позиції + CLS)', async ({ page }) => {
  // Анімація входу екрана рухає ВСЕ піддерево трансформом, тож без reduce
  // «до» міряється на півдорозі анімації і будь-яке порівняння безглузде.
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await installCLS(page)
  await setup(page, { delay: 1200 })

  // КРОК 1 — дати застосунку завантажитись ПОВНІСТЮ. Осідання старту («#app-root»
  // з фолбека `100svh` на реальну висоту від Telegram) — окрема одноразова
  // подія, і момент її приходу залежить від середовища: локально вона встигає до
  // першого скелетона, на CI (прод-білд під `serve`) — після нього. Поки замір
  // «до» робився на першому екрані, у порівняння потрапляв саме цей чужий зсув
  // (`.tabbar 593 → 512` у CI), а не зсув від даних. Ні очікування самої
  // змінної `--tg-vh`, ні очікування «стабільного кадру» цього не лікують:
  // перше локально є no-op, друге завершується ДО осідання, якщо те запізнюється.
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.skel')).toHaveCount(0)

  // КРОК 2 — тепер вхід у базу: хром уже осів, тож ЄДИНА змінна тут — прихід
  // списку об'єктів. Саме це гард і мусить перевіряти.
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.skel').first()).toBeVisible({ timeout: 15_000 })
  const before = await anchors(page)
  // Гард від ВАКУУМНОГО заміру: стабілізація мусить настати ще ДО приходу даних.
  // Якби `before` знімався вже з намальованого списку, він дорівнював би `after`
  // завжди — і тест «проходив» би, не перевіряючи нічого.
  await expect(page.locator('.skel').first(), 'замір «до» зроблено вже після приходу даних').toBeVisible()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.skel')).toHaveCount(0)
  const after = await anchors(page)

  for (const sel of Object.keys(before)) {
    expect(after[sel], `db-objects: ${sel} зрушив ${before[sel]} → ${after[sel]} після приходу даних`)
      .toBe(before[sel])
  }
  await page.waitForTimeout(600)
  const cls = await readCLS(page)
  expect(cls, `CLS ${cls} — персистентний елемент змінив позицію`).toBeLessThan(0.1)
})

test('заглушка має геометрію того, що її замінить', async ({ page }) => {
  // Прямий замір замість CLS: підміна піддерева метриці невидима (див. шапку),
  // а візуально це і є стрибок — заглушка 48px на місці картки 200px означає,
  // що прихід даних не «проявляє» екран, а перебудовує його.
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await setup(page, { delay: 1200 })

  const skelRow = () => page.evaluate(() =>
    Math.round((document.querySelector('.skel-row') as HTMLElement).getBoundingClientRect().height))
  const contentRow = (sel: string) => page.evaluate((s) => {
    const hs = [...document.querySelectorAll(s)].map((e) => e.getBoundingClientRect().height)
    return Math.round(hs.reduce((a, b) => a + b, 0) / hs.length)
  }, sel)

  /** ±30%: картки різної висоти (зайнята 228 / вільна 178) — точного числа не існує. */
  const close = (skel: number, real: number, where: string) =>
    expect(Math.abs(skel - real) / real, `${where}: заглушка ${skel}px проти контенту ${real}px`)
      .toBeLessThan(0.3)

  await page.goto('/')
  await expect(page.locator('.skel-row').first()).toBeVisible({ timeout: 15_000 })
  const dbSkel = await skelRow()
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  close(dbSkel, await contentRow('.row'), 'db-list')

  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.skel-row').first()).toBeVisible({ timeout: 15_000 })
  const cardSkel = await skelRow()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 20_000 })
  close(cardSkel, await contentRow('.obj-card'), 'db-objects/картки')

})

test('заглушка компактного вигляду — своя висота, не карткова', async ({ page }) => {
  // Вподобання «компактно» сідиться ДО першого входу: повторний вхід у ту саму
  // базу вже має теплий SWR-снапшот, тобто стану завантаження там просто немає —
  // саме на цьому крок падав під `CI=1`, де білд віддає дані швидше за dev.
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await setup(page, { delay: 1200 })
  await page.addInitScript(() => localStorage.setItem('ps:occCompact', '1'))

  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.skel-row').first()).toBeVisible({ timeout: 15_000 })
  const skel = await page.evaluate(() =>
    Math.round((document.querySelector('.skel-row') as HTMLElement).getBoundingClientRect().height))

  await expect(page.locator('.row').first()).toBeVisible({ timeout: 20_000 })
  const real = await page.evaluate(() => {
    const hs = [...document.querySelectorAll('.row')].map((e) => e.getBoundingClientRect().height)
    return Math.round(hs.reduce((a, b) => a + b, 0) / hs.length)
  })
  expect(Math.abs(skel - real) / real,
    `db-objects/компактно: заглушка ${skel}px проти рядка ${real}px`).toBeLessThan(0.3)
})

test('скелетон не дублює блок статистики екрана', async ({ page }) => {
  // Усі пʼять споживачів `SkeletonLoader` малюють свій `.stat-g` ПОЗА гілкою
  // loading. Три плиткові заглушки в самому лоадері давали або другий блок
  // статистики під справжнім, або фантомний блок там, де статистики нема.
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await setup(page, { delay: 1500 })
  await page.goto('/')
  await expect(page.locator('.skel').first()).toBeVisible({ timeout: 15_000 })
  expect(await page.locator('.stat-g').count(), 'db-list: два блоки статистики під час завантаження').toBe(1)

  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.skel').first()).toBeVisible({ timeout: 15_000 })
  expect(await page.locator('.stat-g').count(), 'db-objects: фантомний блок статистики').toBe(0)
})

// ── Матриця станів ───────────────────────────────────────────────────────────

test('стан ЗАВАНТАЖЕННЯ: скелетон, а не порожній екран', async ({ page }) => {
  await setup(page, { delay: 1500 })
  await page.goto('/')

  // Поки дані в дорозі — користувач мусить бачити скелетон, не білу пляму.
  await expect(page.locator('.skel').first()).toBeVisible({ timeout: 15_000 })
  await alive(page, 'db-list/loading')

  // І скелетон мусить ЗНИКНУТИ, коли дані прийшли (а не лишитись під контентом).
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.skel')).toHaveCount(0)
})

test('стан ПОРОЖНЬО: свій текст, а не скелетон назавжди', async ({ page }) => {
  await setup(page, { empty: true })
  await page.goto('/')
  await expect(page.getByText(/Створіть першу базу|Немає баз/).first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.skel'), 'скелетон не має лишатись у порожньому стані').toHaveCount(0)
  await alive(page, 'db-list/empty')
})

test('стан ПОМИЛКА: панель повтору з робочою кнопкою', async ({ page }) => {
  let failing = true
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    failing ? json(r, { message: 'boom' }, 500) : json(r, [DB]))
  await page.route('**/rest/v1/properties**', (r) => json(r, PROPS))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await page.goto('/')
  await expect(page.locator('.retry-wrap')).toBeVisible({ timeout: 20_000 })
  await alive(page, 'db-list/error')

  // Кнопка мусить справді перезапитувати, а не просто бути намальованою.
  failing = false
  await page.locator('.retry-btn').click()
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.locator('.retry-wrap')).toHaveCount(0)
})

test('стан ПОМИЛКА в об\'єктах бази: повтор повертає список', async ({ page }) => {
  let failing = true
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    failing ? json(r, { message: 'boom' }, 500) : json(r, PROPS))
  for (const t of ['property_folders', 'property_files', 'rent_payments', 'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.locator('.retry-wrap')).toBeVisible({ timeout: 20_000 })
  await alive(page, 'db-objects/error')

  failing = false
  await page.locator('.retry-btn').click()
  await expect(page.locator('.obj-card').first()).toBeVisible({ timeout: 20_000 })
})
