import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * Сітка безпеки під рефакторинг модалок.
 *
 * `Modal.tsx` УЖЕ має повний набір діалогової механіки — фокус переходить у шит,
 * повертається на опенер (APG), Tab і Shift+Tab заперті всередині, прокрутка фону
 * блокується, свайп нижче порога вертає шит на місце. І на все це немає ЖОДНОГО
 * тесту: у `tests/` ніхто не натискає Tab і не читає `activeElement` для перевірки
 * фокуса. Тобто будь-який рефакторинг ламає цю механіку МОВЧКИ — вона не видна ні
 * на скріншоті, ні в жодному з наявних 202 тестів.
 *
 * Ці гарди мусять зʼявитись ПЕРЕД змінами, а не після.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
  properties: [{ status: 'occupied', rent_rate: 18, area_useful: 100, rent_type: 'per_m2' }],
}

function prop(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, area_basis: 'total',
    rent_type: 'per_m2', rent_rate: null, utilities_rate: null,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], _view_count: 0, ...over,
  }
}
// Достатньо обʼєктів, щоб список під шитом був ДОВШИМ за екран — інакше перевірка
// блокування прокрутки фону нічого не означає.
const PROPERTIES = [
  prop(1, { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', rent_rate: 18, area_useful: 100, area_total: 120 }),
  ...Array.from({ length: 8 }, (_, i) => prop(i + 2)),
]

const json = (route: Route, body: unknown) =>
  route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

async function fixtures(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) =>
    json(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const accept = r.request().headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = r.request().url().match(/id=eq\.([0-9a-f-]+)/)
      return json(r, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return json(r, PROPERTIES)
  })
  for (const t of ['property_folders', 'property_files', 'property_photos', 'rent_payments',
                   'rent_payment_records', 'property_views', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => json(r, []))
  }
  await page.addInitScript(() =>
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/**
 * Відкриває шит «Здати в оренду». Опенер — СПРАВЖНЯ кнопка (`.fbtn`), тож на ній
 * можна перевірити повернення фокуса; рядок меню бази для цього не годиться, бо
 * він `<div>` і фокуса не тримає взагалі.
 */
async function openRentSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })
  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  const opener = page.getByRole('button', { name: 'Здати в оренду' })
  await expect(opener).toBeVisible({ timeout: 15_000 })
  await opener.click()
  // Чекати на текст не можна: «Здати в оренду» — ще й підпис плаваючої кнопки під
  // шитом. Чекаємо на сам шит (див. CLAUDE.md про `.modal`, що перерішується).
  await expect(page.locator('.modal')).toBeVisible()
  await expect(page.locator('.modal').getByText('Здати в оренду', { exact: true })).toBeVisible()
}

/** Клас/тег елемента у фокусі — читабельніше за сирий HTML у повідомленні падіння. */
const activeDesc = (page: Page) => page.evaluate(() => {
  const a = document.activeElement as HTMLElement | null
  if (!a) return 'null'
  return `${a.tagName.toLowerCase()}.${(a.className || '').toString().trim().split(/\s+/)[0] || '-'}`
})

test('фокус іде в шит при відкритті і вертається на кнопку, що його відкрила', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // Фокус мусить бути ВСЕРЕДИНІ діалогу — інакше читалка лишається на екрані
  // під шитом і озвучує контент, якого користувач не бачить.
  const inside = await page.evaluate(() =>
    document.querySelector('.modal')?.contains(document.activeElement) ?? false)
  expect(inside, `фокус поза шитом: ${await activeDesc(page)}`).toBe(true)

  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // …і повернутись саме на опенер, а не на <body>: інакше після закриття Tab
  // починає обхід з початку екрана.
  const restored = await page.evaluate(() => {
    const a = document.activeElement as HTMLElement | null
    return !!a && a.classList.contains('fbtn')
  })
  expect(restored, `фокус не повернувся на опенер, зараз: ${await activeDesc(page)}`).toBe(true)
})

test('Tab і Shift+Tab не виводять фокус за межі шита', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  const focusableCount = await page.locator('.modal').evaluate((el) =>
    el.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])').length)
  // Гард від вакуумності: у шиті без фокусованих елементів пастка тримала б
  // фокус на контейнері, і тест проходив би, нічого не перевіряючи.
  expect(focusableCount, 'у шиті нема чого обходити — тест став би порожнім').toBeGreaterThan(2)

  // Обходимо ПОВНЕ коло плюс запас: якщо пастка не замикається, фокус вийде
  // на контент під шитом ще до кінця циклу.
  for (let i = 0; i < focusableCount + 3; i++) {
    await page.keyboard.press('Tab')
    const inside = await page.evaluate(() =>
      document.querySelector('.modal')?.contains(document.activeElement) ?? false)
    expect(inside, `Tab #${i + 1} вивів фокус за шит: ${await activeDesc(page)}`).toBe(true)
  }

  for (let i = 0; i < 4; i++) {
    await page.keyboard.press('Shift+Tab')
    const inside = await page.evaluate(() =>
      document.querySelector('.modal')?.contains(document.activeElement) ?? false)
    expect(inside, `Shift+Tab #${i + 1} вивів фокус за шит: ${await activeDesc(page)}`).toBe(true)
  }
})

test('прокрутка фону заблокована, поки шит відкритий, і відновлюється після', async ({ page }) => {
  await fixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (9)')).toBeVisible({ timeout: 15_000 })

  const before = await page.evaluate(() => document.body.style.overflow)

  await page.locator('.obj-card', { hasText: 'Офіс 102' }).locator('.obj-t').click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.locator('.modal')).toBeVisible()

  expect(await page.evaluate(() => document.body.style.overflow),
    'фон не заблокований, поки шит відкритий').toBe('hidden')

  await page.keyboard.press('Escape')
  await expect(page.locator('.modal')).toHaveCount(0)

  // Відновлення важливіше за саме блокування: протікле `overflow:hidden` лишає
  // застосунок незгортним назавжди, і жоден екран цього не покаже.
  expect(await page.evaluate(() => document.body.style.overflow),
    'блокування протекло після закриття шита').toBe(before)
})

/** Синтезує вертикальний drag на елементі; `end` — чи відпускаємо палець. */
async function drag(page: Page, selector: string, dy: number, end = true) {
  await page.locator(selector).evaluate((el, { dy, end }) => {
    const r = el.getBoundingClientRect()
    const x = r.x + r.width / 2
    const y0 = r.y + 8
    const fire = (type: string, cy: number, ended = false) => {
      const t = new Touch({ identifier: 1, target: el as Element, clientX: x, clientY: cy })
      el.dispatchEvent(new TouchEvent(type, {
        touches: ended ? [] : [t], changedTouches: [t], bubbles: true, cancelable: true,
      }))
    }
    fire('touchstart', y0)
    fire('touchmove', y0 + dy / 2)
    fire('touchmove', y0 + dy)
    if (end) fire('touchend', y0 + dy, true)
  }, { dy, end })
}

test('свайп НИЖЧЕ порога вертає шит і не лишає інлайнових стилів', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // 60px — свідомо менше за поріг 96px у Modal.tsx.
  await drag(page, '.modal-head', 60)
  await expect(page.locator('.modal'), 'свайп нижче порога закрив шит').toBeVisible()

  // Snap-back їде .24s; читаємо ПІСЛЯ переходу, інакше зловимо кадр анімації.
  await page.waitForTimeout(450)
  const left = await page.evaluate(() => {
    const m = document.querySelector('.modal') as HTMLElement
    const ov = document.querySelector('.modal-overlay') as HTMLElement
    return { transform: m.style.transform, opacity: ov.style.opacity }
  })
  // Інлайнові залишки — не косметика: вони переживають шит і перебивають CSS
  // при наступних анімаціях (transform лишався назавжди при тапі без руху).
  expect(left.transform, 'на шиті лишився інлайновий transform').toBe('')
  expect(left.opacity, 'на оверлеї лишилась інлайнова opacity').toBe('')
})

test('свайп, початий у ТІЛІ шита, не закриває його', async ({ page }) => {
  await fixtures(page)
  await openRentSheet(page)

  // Прокрутка вмісту не має конкурувати з жестом закриття: інакше кожна спроба
  // догорнути форму викидала б користувача з шита.
  await drag(page, '.modal-body', 160)
  await expect(page.locator('.modal'), 'свайп у тілі шита закрив його').toBeVisible()
})
