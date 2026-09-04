import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, seedSession } from './helpers/harness'

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
