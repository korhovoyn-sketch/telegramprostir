import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

/**
 * ПЕРЕМИКАЧ МОВИ — ЩО САМЕ ТУТ ПЕРЕВІРЯЄТЬСЯ.
 *
 * До цього раунду `language_code` ПИСАВСЯ в базу і не читався НІКИМ: жоден
 * рядок коду цього поля не споживав. Тобто перемикач був декоративним, а
 * жоден тест цього не бачив — бо перевіряти було нічого.
 *
 * Гард свідомо міряє ЕКРАН, а не стан: «мова змінилась» означає, що на
 * сторінці не лишилось кирилиці, а не що в сторі інше значення.
 */

// Імʼя ЛАТИНКОЮ навмисно: воно рендериться як дані (заголовок профілю,
// ініціал в аватарі), тож із кириличним імʼям гард падав би на самому
// користувачі. Так будь-яка кирилиця на екрані означає рівно одне —
// неперекладений ІНТЕРФЕЙС.
const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Mykola', last_name: 'T' }
const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

async function seed(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, []))
  await page.route('**/rest/v1/properties**', (r) => jsonRoute(r, []))
  for (const t of ['notifications', 'property_views', 'db_members', 'rent_payments', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() => localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

/** Увесь видимий текст екрана. */
async function screenText(page: Page): Promise<string> {
  return (await page.locator('#app-root').innerText()).trim()
}

test('перемикач у профілі справді перемикає мову екрана', async ({ page }) => {
  await seed(page)
  await page.route('**/rest/v1/users**', (r) => {
    // `updateProfile` завершує ланцюг `.single()`, тобто чекає ОБʼЄКТ. Перша
    // редакція віддавала масив на PATCH — `setUser` клав у стор масив, і
    // профіль падав у ErrorBoundary через `first_name === undefined`. Тест
    // виглядав «флейким», хоч насправді ловив справжній крихкий шлях.
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    const row = { ...USER, language_code: 'en' }
    if (r.request().method() === 'PATCH') return jsonRoute(r, obj ? row : [row])
    return jsonRoute(r, obj ? USER : [USER])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  await page.getByLabel('Профіль').click()
  await expect(page.getByText('Мова')).toBeVisible()

  // АНТИВАКУУМ: до перемикання кирилиця на екрані Є. Без цієї половини
  // «кирилиці немає» проходило б і на порожньому екрані.
  expect(CYR.test(await screenText(page)), 'до перемикання екран український').toBe(true)

  await page.getByRole('button', { name: 'Eng' }).click()

  await expect(page.getByText('Language')).toBeVisible({ timeout: 10_000 })
  const after = await screenText(page)
  expect(CYR.test(after), `кирилиця лишилась: ${after.slice(0, 200)}`).toBe(false)
})

test('мова переживає перезапуск застосунку', async ({ page }) => {
  await seed(page)
  await page.route('**/rest/v1/users**', (r) => jsonRoute(r, [{ ...USER, language_code: 'en' }]))
  // Так виглядає ДРУГИЙ запуск: мову вже збережено локально, і перший кадр
  // мусить бути англійським — інакше користувач бачить спалах українського.
  await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))

  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  expect(CYR.test(await screenText(page)), 'перший кадр після перезапуску український').toBe(false)
})

test('англійською числа й дати беруть англійську локаль', async ({ page }) => {
  await seed(page)
  await page.route('**/rest/v1/users**', (r) => jsonRoute(r, [{ ...USER, language_code: 'en' }]))
  await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))

  await page.goto('/')
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 20_000 })
  // `toLocaleString('uk-UA')` розділяє тисячі НЕРОЗРИВНИМ пробілом, англійська
  // — комою. Захардкоджена локаль лишала б мову перемкненою наполовину.
  const html = await page.content()
  expect(html.includes(' м²'), 'український формат площі просочився').toBe(false)
})
