import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession, skipCoachmarks } from './helpers/harness'

/**
 * ТУПИКИ: екран, з якого стан не має виходу.
 *
 * Дві знахідки наскрізного аудиту, обидві про те, що екран СТВЕРДЖУЄ не те, що
 * сталось, і не дає ЧИМ вийти зі стану:
 *
 *  1. обрив звʼязку, поданий як «посилання недійсне» — впевнена неправда
 *     сторонній людині, якій рієлтор щойно надіслав лінк;
 *  2. «перевірте підключення» без жодної кнопки, якою можна повторити.
 *
 * Кожен має АНТИВАКУУМНУ пару: недійсний лінк мусить лишатись «не знайдено», а
 * непоправна гілка — БЕЗ кнопки повтору. Інакше «розподіл працює» довелось би
 * читати як «обидві гілки звели в одну».
 *
 * ТРЕТЯ ГІПОТЕЗА СПРОСТОВАНА, і записана, щоб її не «знаходили» знову: платіжні
 * екрани нібито крутили спінер вічно, коли рядка немає. Не крутять —
 * `loadSingleProperty` іде через `.single()`, а PostgREST на порожньому наборі
 * віддає 406/PGRST116, тобто ПОМИЛКУ, і гілка `RetryState` спрацьовувала. Тест
 * на це проходив би лише тому, що мок віддає `[]` там, де живий бекенд віддає
 * помилку — тобто доводив би поведінку, якої в проді не існує.
 */

const OWNER = { ...DEFAULT_USER, role: 'owner' as const }
const DB = {
  id: '10000000-0000-0000-0000-000000000001', owner_id: OWNER.id, name: 'БЦ Рубін',
  address: null, type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: '2025-09-01T09:00:00.000Z', updated_at: '2025-09-01T09:00:00.000Z',
}


test('обрив звʼязку на публічній підбірці — це НЕ «посилання недійсне»', async ({ page }) => {
  const COL_ID = '90000000-0000-0000-0000-000000000001'
  await setupApp(page, { user: OWNER, startParam: 'col_cc00112233445566778899dd' })
  await seedSession(page, OWNER as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/rpc/lookup_shared_collection', (r: Route) =>
    jsonRoute(r, [{ id: COL_ID, realtor_id: '00000000-0000-0000-0000-000000000099' }]))

  let fail = true
  let calls = 0
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (r: Route) => {
    calls++
    if (fail) return r.abort('failed')
    return jsonRoute(r, [{
      collection_id: COL_ID, collection_name: 'Топ офіси', share_expires_at: null,
      realtor_first_name: 'Олена', realtor_last_name: 'Р.', realtor_tg_username: null,
      realtor_phone: null, property_id: null, property_name: null, property_status: null,
      property_floor: null, property_area_useful: null, property_area_total: null,
      property_rent_type: null, property_rent_rate: null, property_sale_price: null,
      property_description: null, owner_currency: 'UAH',
      db_id: null, db_name: null, db_type: null, db_color: null, first_photo: null,
    }])
  })

  await page.goto('/')
  await expect(page.getByText('Не вдалося завантажити')).toBeVisible({ timeout: 25_000 })
  // Головне тут — чого НЕ має бути: збій мережі не сміє звинувачувати посилання.
  await expect(page.getByText('Підбірку не знайдено')).toHaveCount(0)

  // Повтор мусить справді ходити в мережу, а не лише перемальовувати текст.
  const before = calls
  fail = false
  await page.getByRole('button', { name: /Спробувати ще раз/ }).click()
  await expect(page.getByText('Топ офіси')).toBeVisible({ timeout: 20_000 })
  expect(calls, 'кнопка повтору не зробила нового запиту').toBeGreaterThan(before)
})

test('порожня відповідь на підбірку лишається «не знайдено» — розподіл не зламано', async ({ page }) => {
  // АНТИВАКУУМ до тесту вище: якби я звів ОБИДВІ гілки до мережевої, він так
  // само проходив би, а екран перестав би відрізняти недійсний лінк.
  const COL_ID = '90000000-0000-0000-0000-000000000001'
  await setupApp(page, { user: OWNER, startParam: 'col_cc00112233445566778899dd' })
  await seedSession(page, OWNER as unknown as Record<string, unknown>)
  await page.route('**/rest/v1/rpc/lookup_shared_collection', (r: Route) =>
    jsonRoute(r, [{ id: COL_ID, realtor_id: '00000000-0000-0000-0000-000000000099' }]))
  await page.route('**/rest/v1/rpc/get_public_collection_preview', (r: Route) => jsonRoute(r, []))

  await page.goto('/')
  await expect(page.getByText('Підбірку не знайдено')).toBeVisible({ timeout: 25_000 })
  await expect(page.getByText('Не вдалося завантажити')).toHaveCount(0)
})

test('гостьове запрошення: збій мережі дає ПОВТОР, а не лише «Закрити»', async ({ page }) => {
  // БЕЗ сесії — превʼю запрошення живе саме в цій гілці `SplashScreen`
  // (`parsed.kind === 'guest'` при відсутньому `getSession`). Сесія повела б
  // потік у `useDeepLink`, тобто в клейм, а не в превʼю.
  await setupApp(page, { startParam: 'guest_gg000000000000000000001' })
  await page.route('**/rest/v1/rpc/get_guest_property_preview', (r: Route) =>
    r.abort('failed'))

  await page.goto('/')
  await expect(page.getByText('Помилка завантаження')).toBeVisible({ timeout: 25_000 })
  // Було: єдина дія — «Закрити», тобто вийти із запрошення і шукати лінк назад
  // у чаті, хоч повідомлення просить «перевірте підключення».
  await expect(page.getByRole('button', { name: /Спробувати ще раз/ })).toBeVisible()
})

test('недійсне запрошення повтору НЕ пропонує — повторювати нема чого', async ({ page }) => {
  // Друга половина: кнопка мусить зʼявлятись лише на ВІДНОВЛЮВАНІЙ гілці.
  await setupApp(page, { startParam: 'guest_gg000000000000000000001' })
  // Порожня відповідь = запрошення не знайдено; це НЕ збій транспорту.
  await page.route('**/rest/v1/rpc/get_guest_property_preview', (r: Route) =>
    jsonRoute(r, null))

  await page.goto('/')
  await expect(page.getByText('Посилання недійсне')).toBeVisible({ timeout: 25_000 })
  await expect(page.getByRole('button', { name: /Спробувати ще раз/ })).toHaveCount(0)
})

/**
 * СПОВІЩЕННЯ: збій завантаження ≠ «сповіщень немає».
 *
 * Третій інстанс уже двічі виправленого класу (список доступів, аналітика
 * шарингу) — і вперше на ВКЛАДЦІ ТАББАРУ, тобто на щоденній поверхні. Екран мав
 * рівно дві гілки: скелетон і порожній стан. Тост про причину зникав за кілька
 * секунд, а «Немає сповіщень» лишалось на екрані як впевнена відповідь.
 *
 * Мій попередній скан цього НЕ побачив: він шукав екрани з прямим `supabase`, а
 * цей ходить через хук. Записано, бо помилка була в самому способі шукати.
 */
async function notifApp(page: Page, notifRoute: (r: Route) => unknown) {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/notifications**', (r: Route) => notifRoute(r))
  for (const t of ['databases', 'properties', 'property_folders', 'rent_payments',
                   'rent_payment_records', 'property_views', 'db_members', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Сповіщення"]').click()
}

test('сповіщення: збій завантаження дає повтор, а не «Немає сповіщень»', async ({ page }) => {
  test.setTimeout(90_000)
  let fail = true
  let calls = 0
  await notifApp(page, (r) => {
    calls++
    if (fail && r.request().method() === 'GET') return r.abort('failed')
    return jsonRoute(r, [])
  })

  // Чекаємо ЩЕДРО: supabase-js сам ретраїть обірваний запит, тож відмова
  // доходить до катча за 6-8с, а не миттєво. Замір на 4с показував скелетон і
  // виглядав як зламаний фікс — насправді був зроблений зарано.
  const retry = page.getByRole('button', { name: /Спробувати ще раз/ })
  await expect(retry).toBeVisible({ timeout: 30_000 })
  // Головне тут — ЧОГО немає: впевненого «Немає сповіщень» на місці збою.
  await expect(page.getByText('Немає сповіщень')).toHaveCount(0)

  const before = calls
  fail = false
  await retry.click()
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 30_000 })
  expect(calls, 'повтор не зробив нового запиту').toBeGreaterThan(before)
})

test('порожня відповідь лишається «Немає сповіщень» — розподіл не зламано', async ({ page }) => {
  // АНТИВАКУУМ: якби обидві гілки звели до помилки, тест вище так само проходив
  // би, а користувач бачив би панель повтору там, де просто немає подій.
  await notifApp(page, (r) => jsonRoute(r, []))
  await expect(page.getByText('Немає сповіщень')).toBeVisible({ timeout: 20_000 })
  await expect(page.getByRole('button', { name: /Спробувати ще раз/ })).toHaveCount(0)
})

/**
 * ПАПКИ: збій завантаження ≠ «папок немає».
 *
 * `unavailable` (42P01, міграція 043 не накочена) — стан ПОСТІЙНИЙ, і ховати
 * розділ там правильно. Обрив звʼязку тимчасовий, а наслідок доти був той
 * самий: порожній список. На екрані керування це найгірша з можливих неправд —
 * користувач створює папку, яка вже існує; у пікері обʼєкт їде в «Без папки»
 * тому, що список не доїхав.
 */
test('керування папками: збій завантаження дає повтор, а не «Ще немає папок»', async ({ page }) => {
  test.setTimeout(90_000)
  let fail = true
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/property_folders**', (r: Route) => {
    if (fail && r.request().method() === 'GET') return r.abort('failed')
    return jsonRoute(r, [])
  })
  await page.route('**/rest/v1/databases**', (r: Route) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  for (const t of ['properties', 'rent_payments', 'rent_payment_records', 'property_views',
                   'db_members', 'notifications', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()

  await expect(page.getByRole('button', { name: /Спробувати ще раз/ })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(/Ще немає папок/)).toHaveCount(0)
})

test('порожня база папок лишається «Ще немає папок» — розподіл не зламано', async ({ page }) => {
  // АНТИВАКУУМ: інакше «повтор показується» проходило б і на коді, що звів
  // обидва стани в помилку, і порожній розділ лякав би панеллю збою.
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r: Route) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  for (const t of ['property_folders', 'properties', 'rent_payments', 'rent_payment_records',
                   'property_views', 'db_members', 'notifications', 'collections']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()

  await expect(page.getByText(/Ще немає папок/)).toBeVisible({ timeout: 20_000 })
  await expect(page.getByRole('button', { name: /Спробувати ще раз/ })).toHaveCount(0)
})
