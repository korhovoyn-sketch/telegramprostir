import { test, expect, type Browser, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'
import { DEVICES, deviceContext } from './helpers/devices'

/**
 * КЛАВІАТУРА НА РІЗНИХ ПРИСТРОЯХ.
 *
 * Уся наявна клавіатурна перевірка (26 тестів у чотирьох спеках) ганяється на
 * ОДНІЙ геометрії — 375×667. `devices.spec.ts` ходить пʼятьма ширинами, але
 * слова «keyboard» у ньому немає жодного разу. Тобто на питання «як вона
 * поводиться на іншому екрані» відповіді не давало ніщо.
 *
 * Прогалина не абстрактна: код клавіатури ЯВНО залежить від геометрії —
 * `kbCacheKey()` у `page.tsx` ключує кеш висоти як `${innerWidth}x${innerHeight}`
 * саме тому, що на іншому екрані й у ландшафті клавіатура інша. Ця гілка не
 * виконувалась у тестах ніколи.
 *
 * Три інваріанти на кожен пристрій, і кожен колись був живим багом:
 *  1. ПЕРЕКРИТТЯ (iOS) — відступ додаємо ми;
 *  2. СТИСНЕННЯ (Android) — НЕ віднімаємо клавіатуру вдруге (подвійний ліфт);
 *  3. ПОВЕРНЕННЯ — оболонка вертає всю висоту (чорна смуга під екраном).
 * Плюс четвертий, предметний: поле, у яке друкують, не перекрите.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const NOW = new Date().toISOString()
const DB = {
  id: '10000000-0000-0000-0000-000000000001', owner_id: USER.id, name: 'БЦ Рубін',
  address: 'вул. Хрещатик, 1', type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  for (const t of ['properties', 'property_folders', 'property_files', 'property_views',
                   'db_members', 'notifications', 'rent_payments', 'rent_payment_records',
                   'collections', 'guest_links']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

const cssVar = (page: Page, name: string) => page.evaluate((n) =>
  parseFloat(getComputedStyle(document.documentElement).getPropertyValue(n)) || 0, name)

const stable = (page: Page, h: number) => page.evaluate((v) =>
  (window as unknown as { __tgViewportStable: (n: number) => void }).__tgViewportStable(v), h)
const tgKb = (page: Page, h: number) => page.evaluate((v) =>
  (window as unknown as { __tgKeyboard: (n: number) => void }).__tgKeyboard(v), h)

/** Клавіатура, що ПЕРЕКРИВАЄ: vv нижчий за вікно, лейаут не стиснуто. */
async function overlayKeyboard(page: Page, px: number) {
  await page.evaluate((h) => {
    const vv = window.visualViewport!
    Object.defineProperty(vv, 'height', { configurable: true, get: () => window.innerHeight - h })
    vv.dispatchEvent(new Event('resize'))
  }, px)
}
async function hideOverlayKeyboard(page: Page) {
  await page.evaluate(() => {
    const vv = window.visualViewport!
    Object.defineProperty(vv, 'height', { configurable: true, get: () => window.innerHeight })
    vv.dispatchEvent(new Event('resize'))
  })
}

async function atHome(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 25_000 })
}

for (const dev of DEVICES) {
  test(`${dev.name}: клавіатура відкривається, ховається і не забирає висоту двічі`, async ({ browser }: { browser: Browser }) => {
    test.setTimeout(180_000)
    const ctx = await browser.newContext(deviceContext(dev))
    const page = await ctx.newPage()
    page.setDefaultTimeout(25_000)
    const problems: string[] = []

    try {
      await fixtures(page)
      await atHome(page)

      const W = dev.width
      const FULL = dev.height
      /**
       * Висоту оболонки міряємо ВІДНОСНО себе самої, а не проти екрана.
       *
       * Перша версія вимагала `rootH === FULL` і завалила iPad mini на 930 при
       * 1133 — це виявився НЕ дефект: при ширині ≥680px застосунок навмисно
       * малюється телефонною рамкою 430×930 по центру десктопного фону
       * (`globals.css`, блок `@media (min-width:680px)`). Тобто хибним було
       * очікування, а не код — рівно той клас помилки заміру, від якого
       * застерігає шапка `devices.spec.ts`.
       *
       * Справжній інваріант «чорної смуги» геометрії не потребує: скільки б
       * оболонка не займала до клавіатури, стільки ж мусить займати після.
       */
      const rootBefore = await page.evaluate(() =>
        Math.round(document.getElementById('app-root')!.getBoundingClientRect().height))
      // Висота клавіатури пропорційна екрану: на планшеті вона фізично більша,
      // і фіксовані 280px там були б неправдою про пристрій.
      const KB = Math.round(FULL * 0.38)

      // ── 1. ПЕРЕКРИТТЯ ────────────────────────────────────────────────────
      await stable(page, FULL)
      await tgKb(page, KB)
      await page.waitForTimeout(250)
      const kb1 = await cssVar(page, '--keyboard-h')
      const vh1 = await cssVar(page, '--tg-vh')
      if (kb1 !== KB) problems.push(`перекриття: --keyboard-h ${kb1}, очікується ${KB}`)
      if (vh1 !== FULL) problems.push(`перекриття: --tg-vh ${vh1}, лейаут мав лишитись на всю висоту ${FULL}`)

      // ── 2. СТИСНЕННЯ ─────────────────────────────────────────────────────
      await tgKb(page, 0)
      await page.waitForTimeout(150)
      await stable(page, FULL)
      await page.setViewportSize({ width: W, height: FULL - KB })
      await tgKb(page, KB)
      await page.waitForTimeout(250)
      const kb2 = await cssVar(page, '--keyboard-h')
      const vh2 = await cssVar(page, '--tg-vh')
      // ПОДВІЙНИЙ ЛІФТ: лейаут уже без клавіатури, тож наш відступ = 0.
      if (kb2 !== 0) problems.push(`стиснення: --keyboard-h ${kb2} — клавіатуру віднято ВДРУГЕ`)
      if (vh2 !== FULL - KB) problems.push(`стиснення: --tg-vh ${vh2}, очікується ${FULL - KB}`)

      // ── 3. ПОВЕРНЕННЯ ────────────────────────────────────────────────────
      await tgKb(page, 0)
      await page.setViewportSize({ width: W, height: FULL })
      await page.waitForTimeout(350)
      const vh3 = await cssVar(page, '--tg-vh')
      const rootAfter = await page.evaluate(() =>
        Math.round(document.getElementById('app-root')!.getBoundingClientRect().height))
      if (vh3 !== FULL) problems.push(`повернення: --tg-vh ${vh3}, очікується ${FULL}`)
      if (rootAfter !== rootBefore) {
        problems.push(`повернення: оболонка ${rootAfter}px проти ${rootBefore}px до клавіатури — порожня смуга`)
      }

      // ── 4. ПОЛЕ, У ЯКЕ ДРУКУЮТЬ, НЕ ПЕРЕКРИТЕ ────────────────────────────
      await page.getByLabel('Створити базу').click()
      await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })
      await stable(page, FULL)
      await overlayKeyboard(page, KB)
      await page.waitForTimeout(400)
      await page.getByLabel('Назва бази').focus()
      await page.waitForTimeout(500)

      const geo = await page.evaluate(() => {
        const f = document.querySelector<HTMLElement>('[aria-label="Назва бази"]')!.getBoundingClientRect()
        const cta = document.querySelector<HTMLElement>('.mbtn')?.getBoundingClientRect()
        return {
          bottom: Math.round(f.bottom),
          ctaTop: cta ? Math.round(cta.top) : Number.POSITIVE_INFINITY,
        }
      })
      const kbTop = FULL - KB
      if (geo.bottom > kbTop) {
        problems.push(`поле «Назва бази» заходить під клавіатуру: низ ${geo.bottom} проти ${kbTop}`)
      }
      if (geo.bottom > geo.ctaTop) {
        problems.push(`поле «Назва бази» під кнопкою: низ ${geo.bottom} проти ${geo.ctaTop}`)
      }

      // АНТИВАКУУМ: без цього «проблем немає» означало б «екран не доїхав».
      expect(geo.bottom, 'поле не знайдено — фікстура чи маршрут зламані').toBeGreaterThan(0)
      await hideOverlayKeyboard(page)
    } finally {
      await ctx.close()
    }

    expect(problems, `${dev.name}: клавіатура`).toEqual([])
  })
}

/**
 * КЕШ ВИСОТИ КЛЮЧУЄТЬСЯ ГЕОМЕТРІЄЮ — і не тече між пристроями.
 *
 * `kbCacheKey()` = `${innerWidth}x${innerHeight}`, бо на іншому екрані й у
 * ландшафті клавіатура фізично інша. Передбачливий підйом бере висоту саме з
 * цього кешу, тож протікання означало б, що шит на телефоні підстрибує на
 * висоту планшетної клавіатури — і навпаки.
 *
 * Гілка не виконувалась у тестах ЖОДНОГО разу: усі клавіатурні спеки живуть на
 * одній геометрії, де ключ завжди той самий.
 */
test('кеш висоти не тече між геометріями', async ({ browser }: { browser: Browser }) => {
  test.setTimeout(180_000)
  const BIG = DEVICES[3]      // 430×932
  const SMALL = DEVICES[0]    // 360×740
  const ctx = await browser.newContext(deviceContext(BIG))
  const page = await ctx.newPage()
  page.setDefaultTimeout(25_000)

  try {
    await fixtures(page)
    await atHome(page)

    // Наповнюємо кеш на ВЕЛИКІЙ геометрії справжнім resize-ом: лише він пише
    // `writeKbCache` (поріг >100px відсікає рядок підказок).
    await stable(page, BIG.height)
    await overlayKeyboard(page, 400)
    await page.waitForTimeout(300)
    expect(await cssVar(page, '--keyboard-h'), 'кеш мав наповнитись справжньою висотою').toBe(400)
    await hideOverlayKeyboard(page)
    await page.waitForTimeout(300)

    const cached = await page.evaluate(() => localStorage.getItem('kb_h_v1'))
    expect(cached, 'запис у кеш не стався — далі перевіряти нічого').toContain('400')

    // Той самий пристрій: підйом на фокус МУСИТЬ спрацювати. Це антивакуумна
    // половина — без неї «чужа висота не взялась» проходило б і на коді, де
    // передбачливий підйом зламаний цілком.
    await page.getByLabel('Створити базу').click()
    await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })
    // ФОКУСУЄМО «Адресу», а не «Назву»: на назві стоїть `autoFocus`, тобто вона
    // вже сфокусована — повторний `.focus()` не породжує `focusin` узагалі, і
    // тест міряв би тишу. Підйом від самого автофокуса на цей момент уже знято
    // таймером 600мс (`confirmTimer`), бо справжнього resize не було.
    await page.getByLabel('Адреса бази').focus()
    await page.waitForTimeout(200)
    expect(await cssVar(page, '--keyboard-h'),
      'на СВОЇЙ геометрії кеш мусить підняти шит одразу').toBe(400)
    await page.getByLabel('Адреса бази').blur()
    await page.waitForTimeout(300)

    // Тепер міняємо геометрію — ключ інший, кешу для неї немає.
    await page.setViewportSize({ width: SMALL.width, height: SMALL.height })
    await page.waitForTimeout(300)
    await page.getByLabel('Адреса бази').focus()
    await page.waitForTimeout(200)
    expect(await cssVar(page, '--keyboard-h'),
      'на ІНШІЙ геометрії висота попереднього пристрою братись не сміє').toBe(0)
  } finally {
    await ctx.close()
  }
})

/**
 * ГІЛКИ ПОМИЛОК, яких не торкався жоден тест.
 *
 * Клавіатурний блок `page.tsx` має пʼять захисних гілок; дві покриті
 * (`confirmTimer`, «клієнт стискає лейаут» — у `modals.spec.ts`). Три нижче не
 * виконувались ніколи, а кожна відповідає на реальний стан пристрою.
 */
test('поле-БАРАБАН (date) не підіймає екран на висоту клавіатури', async ({ page }) => {
  // `opensKeyboard()` виключає date/time свідомо: вони відкривають барабан
  // іншої висоти, тож підйом на кешовану висоту КЛАВІАТУРИ був би просто
  // хибним. У формі обʼєкта дати договору стоять поруч із текстовими полями,
  // тобто переплутати їх — питання одного тапу.
  await fixtures(page)
  await atHome(page)
  const FULL = page.viewportSize()!.height

  await stable(page, FULL)
  await overlayKeyboard(page, 300)
  await page.waitForTimeout(300)
  expect(await cssVar(page, '--keyboard-h'), 'кеш наповнено').toBe(300)
  await hideOverlayKeyboard(page)
  await page.waitForTimeout(300)

  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })

  // Текстове поле — підйом Є (антивакуум: інакше нуль нижче нічого не доводить).
  // «Адреса», а не «Назва»: на назві `autoFocus`, і повторний фокус подію не шле.
  await page.getByLabel('Адреса бази').focus()
  await page.waitForTimeout(200)
  expect(await cssVar(page, '--keyboard-h'), 'текстове поле підіймає').toBe(300)
  await page.getByLabel('Адреса бази').blur()
  await page.waitForTimeout(300)

  // А тепер БАРАБАН: вставляємо date-поле в ту саму форму й фокусуємо.
  await page.evaluate(() => {
    const i = document.createElement('input')
    i.type = 'date'
    i.id = '__probe_date'
    document.querySelector('.body')!.appendChild(i)
  })
  await page.locator('#__probe_date').focus()
  await page.waitForTimeout(300)
  expect(await cssVar(page, '--keyboard-h'),
    'барабан дати не сміє підіймати екран на висоту КЛАВІАТУРИ').toBe(0)
})

/**
 * СПРОСТОВАНО: «провал висоти при переході між полями» ЗВІДСИ НЕ ПЕРЕВІРЯЄТЬСЯ.
 *
 * `onFocusOut` навмисно відкладає обнулення через тік (`blurTimer`), щоб
 * перехід focusout→focusin усередині форми не блимнув екраном униз і назад.
 * Гард на це я написав і ПРИБРАВ: фальсифікація (прибраний дебаунс) залишала
 * його зеленим — і з програмним `.focus()`, і з реальним тапом Playwright.
 * Причина не в зонді: між focusout і focusin браузер не малює кадру, тож
 * покадровий семплер не має де побачити нуль.
 *
 * Тобто інваріант, можливо, взагалі не про Chromium — на живому клієнті кадр
 * туди може потрапити, а тут ні. Лишати зелений тест, який не падає на
 * зламаному коді, гірше, ніж не мати його: він додає впевненості, не додаючи
 * перевірки (той самий висновок, що вже записаний для `.batchbar` у
 * `layering.spec.ts`). Дебаунс у коді лишається — його ціна нульова.
 */

test('приватний режим: недоступний localStorage не ламає клавіатуру', async ({ page }) => {
  // `readKbCache`/`writeKbCache` обгорнуті try/catch саме на цей випадок: без
  // них перший же фокус кинув би виняток просто в обробнику `focusin`.
  //
  // Сховище ламаємо ПІСЛЯ старту, а не з `addInitScript`, і це не спрощення:
  // сесію тестового користувача сідає сам харнес через `localStorage`, тож
  // зламане з завантаження воно валить ФІКСТУРУ, а не застосунок — перша
  // версія цього тесту так і зробила, і «застосунок не стартує» було
  // висновком про мій стаб, а не про код. Шлях старту в застосунку захищений
  // окремо (`lib/snapshot.ts`, `useAuth` — свої try/catch).
  await fixtures(page)
  await atHome(page)
  const FULL = page.viewportSize()!.height

  // Спершу наповнюємо кеш, щоб було ЩО втратити.
  await stable(page, FULL)
  await overlayKeyboard(page, 300)
  await page.waitForTimeout(300)
  await hideOverlayKeyboard(page)
  await page.waitForTimeout(300)

  await page.evaluate(() => {
    const boom = () => { throw new DOMException('denied', 'SecurityError') }
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      get: () => ({ getItem: boom, setItem: boom, removeItem: boom, clear: boom, key: boom, length: 0 }),
    })
  })

  await page.getByLabel('Створити базу').click()
  await expect(page.getByText('Нова база')).toBeVisible({ timeout: 15_000 })
  // Фокус не сміє кинути виняток; передбачливого підйому просто немає.
  await page.getByLabel('Адреса бази').focus()
  await page.waitForTimeout(250)
  expect(await cssVar(page, '--keyboard-h'),
    'без доступу до кешу передбачливий підйом не робиться — і це нормально').toBe(0)

  // А прямий сигнал платформи мусить працювати як завжди.
  await overlayKeyboard(page, 280)
  await page.waitForTimeout(300)
  expect(await cssVar(page, '--keyboard-h'),
    'клавіатура мусить працювати прямим сигналом навіть без сховища').toBe(280)
})
