import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, seedSession } from './helpers/harness'
import { measureContrast, belowAA, smallTargets } from './helpers/contrast'
import { ALL_GROUPS, ownerFixtures, OWNER_SCREENS } from './helpers/screens'

/**
 * Читабельність і досяжність — ГАРД, а не замір.
 *
 * До цього обидві метрики жили в `_contrast.spec.ts`, який не входить у прогін:
 * друкував таблицю і нічого не блокував. Тобто відомий борг міг тихо рости —
 * девʼятого блока нижче AA ніхто б не помітив.
 *
 * Тому база ЗАМОРОЖЕНА: кожен наявний борг перелічений із причиною, а будь-який
 * НОВИЙ блок нижче AA або новий контрол під 44px валить прогін. Кількість на
 * екран теж зафіксована — щоб борг не розростався всередині вже дозволеного
 * класу.
 *
 * ── Обхід ─────────────────────────────────────────────────────────────────
 * Донедавна цей гард ходив ЧОТИРМА екранами (`db-list`, `db-objects`,
 * `property-detail`, `profile`) — тобто 24 екрани з 28 не міряв ніхто, і
 * закрити це скріншотами неможливо: кадр ловить ЗМІНУ проти бейслайна, а текст,
 * який був нижче порогу ЗАВЖДИ, бейслайн благословляє. Тепер маршрут спільний
 * (`helpers/screens.ts`) і покриває 21 екран у чотирьох ролях.
 *
 * Розширення знайшло борг на 13 нових екранах. За рішенням власника він
 * ЗАМОРОЖЕНИЙ, а не виправлений одним заходом: мета фази — зробити його видимим
 * і незростаючим. Два класи потребують окремого рішення і винесені в коментарі
 * до `CONTRAST_DEBT`.
 */

/**
 * Заморожений борг контрасту. Ключ — власний клас блока (або «батько>тег» для
 * безкласового вузла).
 *
 * Рішення власника проєкту: правити ДАНІ, підписи лишити.
 *
 * ⚠️ ДВА КЛАСИ ТУТ — НЕ ПІДПИСИ, і лишаються лише до окремого дизайн-рішення:
 *
 * 1. `mbtn` — ПЕРВИННА кнопка застосунку, нижче AA на пʼятьох екранах
 *    (найгірше 2.35:1 на «Завантажити PDF» в експорті). Це не капшен, це
 *    підпис головної дії. Причина системна: біле по напівпрозорій скляній
 *    пігулці, а градієнт екрана СВІТЛІШАЄ донизу — саме там, де кнопка й
 *    стоїть. Лікується не альфою тексту, а щільнішою заливкою пігулки, тобто
 *    зміною вигляду ВСІХ первинних кнопок і всіх бейслайнів разом із ними.
 * 2. `obj-t` / `obj-s` / `obj-mt>span` — назва обʼєкта і його метадані в списку
 *    рієлтора (4:1 і нижче). Ті самі класи в базі власника поріг проходять:
 *    різниця в тому, що екран рієлтора коротший і картки лягають нижче в
 *    градієнті. Той самий механізм, що вже задокументований для `.obj-tot-sub`.
 */
const CONTRAST_DEBT: ReadonlySet<string> = new Set([
  // ── підписи й капшени (рішення власника: лишаються) ──
  // Плитки дашборда бази: 11px капшен `--t4` над СВІТЛИМ тонованим блоком.
  'dash-sub',
  // Підпис плитки дашборда, 11px/600 — той самий світлий блок.
  'dash-l',
  // Неактивний сегмент (мова/валюта в Профілі, база площі й статус у формі):
  // приглушеність тут і є станом.
  'fr-seg-b',
  // Тонований бейдж «Зайнято»/«Продаж» — foreground на тлі власної заливки.
  'bdg',
  // Оверлайн секції: 11px/600 uppercase, безкласовий <span> у `.over`.
  'over>span',
  // Капшен «оренда + експлуатаційні» під сумою картки: темніший ґрунт прибрано
  // за проханням власника (виглядав як зайва плашка). 4.31–4.38 — на волосок
  // нижче AA, сама сума (`.obj-tot-v`) лишається над порогом.
  'obj-tot-sub',
  // Підпис «На місяць» над тією ж сумою — той самий блок, та сама причина.
  'obj-tot-l',
  // Підзаголовок типу бази в майстрі створення («Будинки, ділянки»), 12px/400.
  'type-s',
  // Капшен періоду в аналітиці («за 7 днів»).
  'over-a',
  // Текст порожнього стану аналітики — допоміжна підказка, не дані.
  'empty-s',
  // Монограма аватара, 22px/600 біле на тонованому колі. Формально потребує
  // 4.5 (шкала вважає «великим» лише ≥700), фактично це 22px гліф — межовий
  // випадок самої метрики, а не текст, який читають.
  'profile-av',
  // Другорядні текстові кнопки: «Пропустити →» в онбордингу, «Додати» в
  // сканері, «Налаштувати» в календарі. Приглушеність — навмисна ієрархія
  // поряд із первинною дією.
  'body>button', '?>button', 'glass-s>button',
  // ── класи, що чекають на дизайн-рішення (див. блок вище) ──
  'mbtn', 'obj-t', 'obj-s', 'obj-mt>span',
])

/**
 * Скільки блоків нижче AA дозволено на екран — щоб борг не ріс у своєму класі.
 * Числа зняті заміром, а не вгадані; `property-form-new` тримає 4 при
 * спостережених 3–4, бо «Зайнято» стоїть на 4.45 при порозі 4.5 і перетинає
 * його від найдрібнішого зсуву рендера.
 */
const FROZEN: Record<string, number> = {
  'db-list': 0,
  'db-objects': 6,
  'db-objects-compact': 0,
  'property-detail': 0,
  'property-form-new': 4,
  'create-db': 3,
  'sharing-analytics': 3,
  'payment-calendar': 3,
  'manage-guests': 0,
  team: 0,
  export: 2,
  notifications: 0,
  profile: 7,
  'realtor-dashboard': 1,
  'realtor-database': 6,
  'qr-scanner': 1,
  collections: 0,
  'guest-home': 0,
  'guest-property': 0,
  'role-select': 1,
  'profile-setup': 1,
}

async function auditScreen(page: Page, label: string) {
  const rows = await measureContrast(page)
  expect(rows.length, `${label}: текстових блоків не знайдено — вибірка застаріла`).toBeGreaterThan(5)
  const bad = belowAA(rows)

  const unexpected = bad
    .filter((b) => !CONTRAST_DEBT.has(b.key))
    .map((b) => `${b.ratio}:1 (треба ${b.need}) ${b.size}px/${b.weight} «${b.text}» .${b.cls} [${b.key}]`)
  expect([...new Set(unexpected)],
    `${label}: НОВИЙ текст нижче WCAG AA — або підніми контраст, або додай у CONTRAST_DEBT із причиною`)
    .toEqual([])

  expect(bad.length,
    `${label}: блоків нижче AA стало ${bad.length}, заморожено ${FROZEN[label]} — борг виріс усередині дозволеного класу`)
    .toBeLessThanOrEqual(FROZEN[label])
}

for (const group of ALL_GROUPS) {
  test(`контраст тексту: ${group.role}`, async ({ page }) => {
    test.setTimeout(300_000)
    page.setDefaultTimeout(20_000)
    await group.fixtures(page)

    const visited: string[] = []
    for (const s of group.screens) {
      // Кожен крок самодостатній від `/`: замір робить текст прозорим
      // НЕОБОРОТНО, тож наступний екран мусить малюватись із чистого старту.
      await s.go(page)
      await page.waitForTimeout(800)
      expect(FROZEN, `${s.label}: екран не має запису у FROZEN`).toHaveProperty(s.label)
      await auditScreen(page, s.label)
      visited.push(s.label)
    }
    // Антивакуумність: «нових знахідок нема» мусить означати «поміряли все», а
    // не «маршрут тихо обірвався на другому екрані».
    expect(visited, `${group.role}: обхід не дійшов до всіх екранів`)
      .toEqual(group.screens.map((s) => s.label))
  })
}

/**
 * Заморожений борг зони дотику.
 *
 * `.view-seg-b` — квадратні кнопки-іконки «Картки / Компактно» 38px впритул
 * одна до одної в спільній обгородці: розширення вкрало б тап у сусідню, тож це
 * рішення про геометрію пари, а не про сам контрол.
 *
 * `.obj-act-btn` — рядок дій картки. Природний бокс (~35px) СВІДОМО не
 * розширюють через `::after`: над кнопками тіло картки, яке відкриває обʼєкт, і
 * розширена зона вкрала б у нього тапи.
 *
 * Решта зʼявилась разом із розширенням обходу на 21 екран — і це інвентар, а не
 * рішення «так і треба»: степер кількості в формі (32×32), чіпи сортування
 * (32px), кнопки календаря платежів (29–36px), «Поділитись»/«Відкликати» в
 * гостях і команді (31px), «Написати власнику» (36px). Усі проходять поріг
 * `ui-audit` (32px, WCAG 2.5.8 AA — 24px) і не дотягують до Apple HIG 44.
 * Піднімати їх — окрема робота з переверсткою рядків, а не правка порогу.
 */
const TAP_DEBT: ReadonlySet<string> = new Set([
  'view-seg-b', 'obj-act-btn', 'sort-chip', 'owner-act', 'button',
])

test('фактична зона дотику — 44px (Apple HIG)', async ({ page }) => {
  test.setTimeout(300_000)
  page.setDefaultTimeout(20_000)
  await ownerFixtures(page)
  for (const s of OWNER_SCREENS) {
    await s.go(page)
    await page.waitForTimeout(500)
    const small = await smallTargets(page, 44)
    const unexpected = [...new Set(small
      .filter((t) => !TAP_DEBT.has(t.key))
      .map((t) => `.${t.cls} «${t.label}» ${t.w}×${t.h}`))]
    expect(unexpected,
      `${s.label}: контрол під 44px по ФАКТИЧНІЙ зоні дотику — розшир зону через ::after або додай у TAP_DEBT`)
      .toEqual([])
  }
})

// ── Далі — перевірки, що вимагають ОДНОГО екрана й власної геометрії ─────────

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2025-09-01T09:00:00.000Z'
const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW,
}
const PROP = {
  id: '20000000-0000-0000-0000-000000000001', db_id: DB_ID, owner_id: USER.id,
  name: 'Офіс 10 поверху ( мале крило )', floor: '10', status: 'occupied',
  area_useful: 175.8, area_total: 195.13, area_basis: 'total', rent_type: 'per_m2',
  rent_rate: 12.8, utilities_rate: 2.5, has_parking: false, parking_spaces: 0,
  parking_type: null, ev_charger: false, folder_id: null,
  utilities: ['electricity', 'water', 'heating', 'gas'], description: 'Світлий офіс.',
  address: 'Дегтярівська 27-Т', sale_price: null, tenant_name: 'Фоп Плотко',
  lease_start_date: '2025-08-15', lease_end_date: '2026-08-31',
  sort_order: 1, share_token: 'bb00000000000000000011', share_expires_at: null,
  created_at: NOW, updated_at: NOW, photos: [], _view_count: 3,
}

async function singleDbFixtures(page: Page) {
  await setupApp(page, { user: USER })
  await seedSession(page, USER as unknown as Record<string, unknown>)
  const json = (r: import('@playwright/test').Route, body: unknown) =>
    r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? PROP : [PROP]))
  await page.route('**/rest/v1/users**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? USER : [USER]))
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
                   'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('розширена зона дотику нікому не краде тапи', async ({ page }) => {
  test.setTimeout(120_000)
  await singleDbFixtures(page)
  // Невидимий `::after` на 44px — компроміс: вигляд рядка лишається, зона росте.
  // Ціна помилки — вкрадений тап у сусідній контрол, тож промацуємо центр і краї
  // розширеної зони і дивимось, у ЩО фактично влучає палець.
  const steps: [string, () => Promise<void>][] = [
    ['db-objects', async () => {
      await page.goto('/')
      await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
      await page.getByText('БЦ Рубін').first().click()
      await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
    }],
    ['profile', async () => {
      await page.goto('/')
      await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
      await page.locator('.tabbar [aria-label="Профіль"]').click()
      await expect(page.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
    }],
    ['notifications', async () => {
      await page.locator('.tabbar [aria-label="Сповіщення"]').click()
      await expect(page.getByText('Сповіщення').first()).toBeVisible({ timeout: 15_000 })
    }],
  ]
  for (const [label, go] of steps) {
    await go()
    await page.waitForTimeout(500)
    const stolen = await page.evaluate(() => {
      const bad: string[] = []
      const bar = document.querySelector('.tabbar') as HTMLElement | null
      const fold = bar ? bar.getBoundingClientRect().top : window.innerHeight
      const targets = [...document.querySelectorAll('.seg-b,.view-seg-b,.fr-seg-b,.notif-tab,.hdr-back')] as HTMLElement[]
      for (const t of targets) {
        const r = t.getBoundingClientRect()
        if (r.width < 4 || r.top < 0 || r.bottom > fold) continue
        for (const dy of [-20, 0, 20]) {
          const x = Math.round(r.left + r.width / 2)
          const y = Math.round(r.top + r.height / 2 + dy)
          if (y < 1 || y > fold - 1) continue
          const hit = document.elementFromPoint(x, y)
          if (!hit) continue
          const ownTarget = hit === t || t.contains(hit) || hit.contains(t)
          const other = (hit as HTMLElement).closest('button,[role="button"],a,.sheet-row,.obj-card,.row,.notif-row')
          if (!ownTarget && other && !t.contains(other)) {
            bad.push(`${(t.className || '').toString().slice(0, 18)} @${dy > 0 ? '+' : ''}${dy} → ${(other.className || other.tagName).toString().slice(0, 24)}`)
          }
        }
      }
      return bad
    })
    expect([...new Set(stolen)], `${label}: розширена зона краде тап у сусідній контрол`).toEqual([])
  }
})

test('дії останньої картки не ховаються під таббаром', async ({ page }) => {
  await singleDbFixtures(page)
  await page.goto('/')
  await expect(page.getByText('БЦ Рубін').first()).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (1)')).toBeVisible({ timeout: 15_000 })
  // Саме в самому низу дії останньої картки зустрічаються з таббаром.
  await page.evaluate(() => {
    const b = document.querySelector('.body') as HTMLElement
    b.scrollTop = b.scrollHeight
  })
  await page.waitForTimeout(600)

  const res = await page.evaluate(() => {
    const bar = document.querySelector('.tabbar') as HTMLElement
    const barTop = bar.getBoundingClientRect().top
    const acts = [...document.querySelectorAll('.obj-act-btn')] as HTMLElement[]
    const last = acts[acts.length - 1]
    const r = last?.getBoundingClientRect()
    const cx = r ? Math.round(r.left + r.width / 2) : 0
    const cy = r ? Math.round(r.top + r.height / 2) : 0
    const hit = r ? document.elementFromPoint(cx, cy) : null
    return {
      found: !!r,
      overlap: r ? Math.round(r.bottom - barTop) : -1,
      hitClass: hit ? (hit.className?.toString().slice(0, 30) || hit.tagName) : 'нічого',
      hitIsAction: !!hit?.closest('.obj-act-btn'),
    }
  })
  expect(res.found, 'дій картки не знайдено — селектор застарів').toBe(true)
  expect(res.overlap, `остання дія залазить під таббар на ${res.overlap}px`).toBeLessThanOrEqual(0)
  expect(res.hitIsAction, `тап у центр останньої дії влучає в ${res.hitClass}, а не в кнопку`).toBe(true)
})
