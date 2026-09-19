import { test, type Browser } from '@playwright/test'
import { ALL_GROUPS, OWNER_SCREENS } from './helpers/screens'
import { jsonRoute } from './helpers/harness'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс → поза прогоном; запуск із PERF=1).
 * Знімає справжні екрани продукту в 3× для маркетингових матеріалів:
 * бейслайни живуть у 1×/2× і на 1080px-полотні Instagram милять.
 *
 *   PERF=1 SHOTS=marketing/shots npx playwright test _marketing-shots
 */
const OUT = process.env.SHOTS || 'marketing/shots'
const FROZEN = new Date('2025-09-01T09:00:00.000Z')

// Кадри, що НЕСУТЬ маркетингове повідомлення. Решта 25 екранів — службові
// (пікери, підтвердження), у рекламі вони не працюють.
const WANT = new Set([
  'db-list', 'db-objects', 'property-detail', 'payment-calendar',
  'sharing-analytics', 'export', 'team', 'notifications',
  'realtor-dashboard', 'collections', 'guest-home', 'welcome',
  'property-form-new', 'db-objects-compact',
])

for (const group of ALL_GROUPS) {
  const steps = group.screens.filter((s) => WANT.has(s.label))
  if (!steps.length) continue

  test(`shots · ${group.role}`, async ({ browser }: { browser: Browser }) => {
    test.setTimeout(240_000)
    for (const step of steps) {
      // Власний контекст на КОЖЕН крок: кроки самодостатні (кожен робить
      // goto('/')), а спільний контекст ділив би між ними localStorage —
      // саме той дрейф, що вже ламав `db-objects-compact` в обході.
      const ctx = await browser.newContext({
        viewport: { width: 375, height: 812 },
        deviceScaleFactor: 3,
        isMobile: true,
        hasTouch: true,
      })
      const page = await ctx.newPage()
      page.setDefaultTimeout(25_000)
      try {
        await page.clock.setFixedTime(FROZEN)
        await page.emulateMedia({ reducedMotion: 'reduce' })
        await group.fixtures(page)
        await step.go(page)
        await page.waitForTimeout(700)
        await page.screenshot({ path: `${OUT}/${step.label}.png` })
        console.log(`✓ ${step.label}`)
      } catch (e) {
        console.log(`✗ ${step.label}: ${(e as Error).message.split('\n')[0]}`)
      } finally {
        await ctx.close()
      }
    }
  })
}


/**
 * КАЛЕНДАР ПЛАТЕЖІВ ІЗ ЖИВИМИ ДАНИМИ.
 *
 * Фікстури обходу тримають `rent_payments` ПОРОЖНІМ навмисно — крок
 * `payment-calendar` там міряє саме порожній стан. Для реклами це найгірший
 * можливий кадр: макет обіцяє «ви дізнаєтесь про прострочку останнім», а
 * доказ показує нулі й «немає розкладу», тобто не доводить нічого.
 *
 * Тому тут той самий екран, але з розкладом і записами: одне прострочено,
 * одне очікується, одне отримано. Час заморожено на 20-му числі — інакше
 * прострочення не настає в принципі (усі дати ще попереду).
 */
test('shots · календар із даними', async ({ browser }) => {
  test.setTimeout(120_000)
  const OWNER_ID = '00000000-0000-0000-0000-000000000001'
  const P = (n: number) => `20000000-0000-0000-0000-00000000000${n}`
  const SCHED = [
    { id: 's1', property_id: P(1), owner_id: OWNER_ID, due_day: 5,  notify_days_before: 3, is_active: true },
    { id: 's2', property_id: P(2), owner_id: OWNER_ID, due_day: 10, notify_days_before: 3, is_active: true },
    { id: 's3', property_id: P(3), owner_id: OWNER_ID, due_day: 25, notify_days_before: 3, is_active: true },
  ].map((r) => ({ ...r, created_at: '2025-09-01T09:00:00.000Z', updated_at: '2025-09-01T09:00:00.000Z' }))
  const RECORDS = [
    { id: 'r1', property_id: P(1), owner_id: OWNER_ID, due_date: '2025-09-05',
      paid_at: '2025-09-04T10:00:00.000Z', amount: 2725, status: 'paid', notes: null,
      created_at: '2025-09-04T10:00:00.000Z', updated_at: '2025-09-04T10:00:00.000Z' },
  ]

  const ctx = await browser.newContext({
    viewport: { width: 375, height: 812 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
  })
  const page = await ctx.newPage()
  page.setDefaultTimeout(25_000)
  try {
    await page.clock.setFixedTime(new Date('2025-09-20T09:00:00.000Z'))
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await ALL_GROUPS[0].fixtures(page)
    // ПІСЛЯ фікстур: Playwright бере обробник, зареєстрований останнім
    await page.route('**/rest/v1/rent_payments**', (r) => {
      const single = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, single ? SCHED[0] : SCHED)
    })
    await page.route('**/rest/v1/rent_payment_records**', (r) => jsonRoute(r, RECORDS))
    const step = OWNER_SCREENS.find((x) => x.label === 'payment-calendar')!
    await step.go(page)
    await page.waitForTimeout(900)
    await page.screenshot({ path: `${OUT}/payment-calendar-full.png` })
    console.log('✓ payment-calendar-full')
  } finally { await ctx.close() }
})


/**
 * АНАЛІТИКА ПЕРЕГЛЯДІВ ІЗ ЖИВИМИ ДАНИМИ — той самий клас, що календар вище.
 *
 * Фікстури обходу тримають `property_views` порожнім, тож кадр показував
 * «Немає переглядів» під маркетинговим підписом «Хто і коли відкрив
 * посилання» — тобто доказ СПРОСТОВУВАВ власне твердження. Для реклами це
 * гірше за відсутність кадру.
 *
 * Дати відлічуються від ЗАМОРОЖЕНОГО «сьогодні»: стовпчикова діаграма екрана
 * бере вікно 7 днів, тож фіксовані рядки за календарем випали б із нього
 * першого ж місяця, і кадр знову став би порожнім — мовчки.
 */
test('shots · аналітика з даними', async ({ browser }) => {
  test.setTimeout(120_000)
  const NOW = new Date('2025-09-20T09:00:00.000Z')
  const P = (n: number) => `20000000-0000-0000-0000-00000000000${n}`
  const ago = (h: number) => new Date(NOW.getTime() - h * 3600_000).toISOString()
  const VIEWS = [
    { viewer_name: 'Оля Петренко', property_id: P(1), h: 3 },
    { viewer_name: null, property_id: P(2), h: 9 },
    { viewer_name: 'Ігор Л.', property_id: P(1), h: 27 },
    { viewer_name: null, property_id: P(3), h: 33 },
    { viewer_name: 'Оля Петренко', property_id: P(3), h: 52 },
    { viewer_name: null, property_id: P(1), h: 74 },
    { viewer_name: 'Андрій К.', property_id: P(2), h: 98 },
    { viewer_name: null, property_id: P(1), h: 121 },
  ].map((v, i) => ({
    id: `v${i}`, property_id: v.property_id, viewer_id: v.viewer_name ? `u${i}` : null,
    viewer_name: v.viewer_name, action: 'view', created_at: ago(v.h),
  }))

  const ctx = await browser.newContext({
    viewport: { width: 375, height: 812 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
  })
  const page = await ctx.newPage()
  page.setDefaultTimeout(25_000)
  try {
    await page.clock.setFixedTime(NOW)
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await ALL_GROUPS[0].fixtures(page)
    // ПІСЛЯ фікстур — Playwright бере обробник, зареєстрований останнім.
    //
    // Екран питає `property_views` ДВІЧІ (обʼєкти бази через `property_id=in`
    // і відкриття самої бази через `db_id=eq`) і зливає відповіді. Роут, що
    // віддає той самий масив обом, подвоює КОЖЕН рядок у кадрі — «16 за 7
    // днів» при восьми посіяних. Тому відкриття бази тут порожні.
    await page.route('**/rest/v1/property_views**', (r) =>
      jsonRoute(r, r.request().url().includes('db_id=eq') ? [] : VIEWS))
    const step = OWNER_SCREENS.find((x) => x.label === 'sharing-analytics')!
    await step.go(page)
    await page.waitForTimeout(900)
    await page.screenshot({ path: `${OUT}/sharing-analytics-full.png` })
    console.log('✓ sharing-analytics-full')
  } finally { await ctx.close() }
})
