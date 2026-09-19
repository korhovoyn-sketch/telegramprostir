import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

/**
 * ДІАГНОСТИКА ПІДКЛЮЧЕННЯ — єдина кнопка, якою власник зʼясовує, ЧОМУ вхід
 * мертвий. Уся її клієнтська половина не мала ЖОДНОГО тесту, і саме тому
 * повз рев'ю проїхало поглинання діагнозів: гілка `origin_match === false`
 * виходила раніше за список відсутніх змінних і ковтала його.
 *
 * Тут перевіряється те, чого джерельний гард не бачить у принципі —
 * ПРІОРИТЕТ гілок і те, що читає користувач.
 */

type Diag = Record<string, unknown>

async function openWelcome(page: Page, diag: Diag) {
  // Гілка сплеша дивиться на ХЕШ (`#fromLogout`), не на query — інакше
  // сесія відновлюється і нас веде на role-select.
  await setupApp(page, { user: { ...DEFAULT_USER, role: null }, noAutoLogin: true })
  // Саме GET на функцію: POST-шлях логіну спекою не зачіпається.
  await page.route('**/functions/v1/telegram-auth**', (r) => {
    if (r.request().method() !== 'GET') return r.fallback()
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(diag) })
  })
  await page.goto('/#fromLogout')
  const btn = page.getByRole('button', { name: /Діагностика підключення/ })
  await btn.waitFor({ timeout: 15_000 })
  // dispatchEvent, а НЕ click({ force }): force усе одно б'є по КООРДИНАТАХ, а
  // їх перекриває плаваюча «Увійти» — тобто тест виконував логін і їхав на
  // role-select, «не знайшовши» тоста. Перевіряється механізм, не геометрія
  // (її міряють devices/contrast); задокументована пастка цього репозиторію.
  await btn.dispatchEvent('click')
}

const ALL_SET = { allowed_origin: true, bot_token: true, supabase_url: true, service_key: true, anon_key: true, db: true }

test('розбіжність origin називає ОБИДВІ адреси', async ({ page }) => {
  await openWelcome(page, {
    ok: false,
    checks: { ...ALL_SET, origin_match: false, bot_token_valid: true },
    allowed_origin_value: 'https://typo.vercel.app',
  })
  await expect(page.getByText('ALLOWED_ORIGIN не збігається')).toBeVisible()
  await expect(page.getByText(/https:\/\/typo\.vercel\.app/)).toBeVisible()
})

test('НЕЗАДАНИЙ origin не ковтає решту діагнозів', async ({ page }) => {
  // `origin_match` тут теж false (null !== origin), але змінної НЕМАЄ — і
  // це інший діагноз: CORS при незаданій змінній відбиває Origin, тобто
  // НЕ блокує. Без гейта на `allowed_origin === true` користувач читав
  // неправдиве «Вхід блокує CORS» і не дізнавався про мертву БД узагалі.
  await openWelcome(page, {
    ok: false,
    checks: { ...ALL_SET, allowed_origin: false, db: false, origin_match: false },
    allowed_origin_value: null,
  })
  await expect(page.getByText('Проблема конфігурації')).toBeVisible()
  await expect(page.getByText(/ALLOWED_ORIGIN/)).toBeVisible()
  await expect(page.getByText(/зʼєднання з БД/)).toBeVisible()
  await expect(page.getByText('ALLOWED_ORIGIN не збігається')).toHaveCount(0)
})

test('ЗАДАНИЙ, але хибний токен не читається як «не налаштовано»', async ({ page }) => {
  await openWelcome(page, {
    ok: false,
    checks: { ...ALL_SET, origin_match: true, bot_token_valid: false },
    allowed_origin_value: 'https://app.vercel.app',
  })
  // Змінна ЗАДАНА, тож порада «додайте її» вела б у глухий кут.
  await expect(page.getByText(/Telegram його не приймає/)).toBeVisible()
  await expect(page.getByText(/Не налаштовано/)).toHaveCount(0)
})

test('усе зійшлось — успіх', async ({ page }) => {
  await openWelcome(page, {
    ok: true,
    checks: { ...ALL_SET, origin_match: true, bot_token_valid: true },
    allowed_origin_value: 'https://app.vercel.app',
  })
  await expect(page.getByText('Конфігурація OK')).toBeVisible()
})
