import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

/**
 * ІНСТРУМЕНТ (у прогін не входить): перемикає мову ЧЕРЕЗ ІНТЕРФЕЙС і обходить
 * екрани, знімаючи кожен. Гард `language.spec.ts` доводить, що перемикач діє
 * на профіль; тут перевіряється, що він діє на РЕШТУ — тобто що жоден екран
 * не застиг українською після перемикання (клас дефекту з кроку 3).
 */
const SHOTS = process.env.SHOTS_DIR || '/tmp/lang'
const CYR = /[а-яА-ЯіїєґІЇЄҐ]/
const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Mykola', last_name: 'T' }

const DBS = [{
  id: 'db-1', name: 'Rubin BC', type: 'business_center', color: 'blue', icon: 'building',
  owner_id: USER.id, created_at: '2026-01-01T00:00:00Z', share_token: 'tok', share_expires_at: null,
  landlord_name: null, description: null,
}]
const PROPS = [{
  id: 'p-1', db_id: 'db-1', owner_id: USER.id, name: 'Office 101', status: 'free',
  area_useful: 50, area_total: 60, area_basis: 'total', rent_type: 'per_m2', rent_rate: 18,
  utilities_rate: 2.5, floor: 3, sort_order: 100, created_at: '2026-01-01T00:00:00Z',
  tenant_name: null, lease_start_date: null, lease_end_date: null, sale_price: null,
  address: null, description: null, folder_id: null, share_token: 'pt', parking_type: null,
  ev_charger: null, landlord_name: null,
}]

async function seed(page: Page) {
  await setupApp(page, { user: USER })
  await page.route('**/rest/v1/users**', (r) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    const row = { ...USER, language_code: r.request().method() === 'PATCH' ? 'en' : 'uk' }
    return jsonRoute(r, obj ? row : [row])
  })
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, DBS))
  // `loadSingleProperty` завершує ланцюг `.single()`, тобто чекає ОБʼЄКТ.
  // Масив у відповідь давав екран деталі, що вічно крутить спінер — і саме на
  // ньому інструмент проходив вакуумно.
  await page.route('**/rest/v1/properties**', (r) => {
    const obj = (r.request().headers()['accept'] ?? '').includes('object')
    return jsonRoute(r, obj ? PROPS[0] : PROPS)
  })
  for (const t of ['notifications', 'property_views', 'db_members', 'rent_payments',
                   'rent_payment_records', 'collections', 'guest_links', 'property_photos',
                   'property_files', 'property_folders', 'realtor_subscriptions']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.addInitScript(() => localStorage.setItem('ob_v1',
    JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab'])))
}

test('перемикання через інтерфейс діє на всі екрани', async ({ page }) => {
  await seed(page)
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.screenshot({ path: `${SHOTS}/00-uk-db-list.png` })

  // Перемикаємо САМЕ так, як це робить користувач.
  await page.getByLabel('Профіль').click()
  await expect(page.getByText('Мова')).toBeVisible()
  await page.getByRole('button', { name: 'Eng' }).click()
  await expect(page.getByText('Language')).toBeVisible({ timeout: 10_000 })
  await page.screenshot({ path: `${SHOTS}/01-en-profile.png` })

  const bad: string[] = []
  const check = async (name: string) => {
    await page.waitForTimeout(400)
    const txt = (await page.locator('#app-root').innerText()).trim()
    await page.screenshot({ path: `${SHOTS}/${name}.png` })
    // АНТИВАКУУМ. Перша редакція цього інструмента «пройшла» крок деталі
    // обʼєкта, який насправді завис на спінері: у спінері кирилиці немає ЗА
    // ПОБУДОВОЮ, тож порожній екран нерозрізненний від перекладеного. Поріг
    // по кількості рядків — те саме, що `MIN_ROWS` у гарді контрасту.
    const rows = txt.split('\n').map((l) => l.trim()).filter(Boolean)
    if (rows.length < 6) bad.push(`${name}: екран не намалювався (${rows.length} рядків) — крок вакуумний`)
    const cyr = txt.split('\n').map((l) => l.trim()).filter((l) => CYR.test(l))
    if (cyr.length) bad.push(`${name}: ${cyr.join(' | ')}`)
    // Доступні назви теж — вони не в innerText.
    const labels = await page.locator('[aria-label]').evaluateAll(
      (ns) => ns.map((n) => n.getAttribute('aria-label') || ''))
    const cyrL = labels.filter((l) => /[а-яА-ЯіїєґІЇЄҐ]/.test(l))
    if (cyrL.length) bad.push(`${name} [aria]: ${[...new Set(cyrL)].join(' | ')}`)
  }

  await check('02-en-profile-full')
  await page.getByLabel(/Databases|Бази/).click()
  await expect(page.getByText('My databases')).toBeVisible({ timeout: 10_000 })
  await check('03-en-db-list')
  await page.getByText('Rubin BC').first().click()
  await page.waitForTimeout(900)
  await check('04-en-db-objects')
  await page.getByText('Office 101').first().click()
  await page.waitForTimeout(900)
  await check('05-en-property-detail')

  console.log(bad.length ? `КИРИЛИЦЯ:\n${bad.join('\n')}` : 'ЧИСТО: кирилиці немає на жодному кроці')
  expect(bad, bad.join('\n')).toEqual([])
})
