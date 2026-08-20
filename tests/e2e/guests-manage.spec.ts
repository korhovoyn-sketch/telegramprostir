import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * КЕРУВАННЯ ГОСТЯМИ — екран без жодного функціонального тесту.
 *
 * До цього спека `ManageGuestsScreen` відвідували лише візуальні обходи
 * (`screenshots`, `contrast`, `a11y-labels`) — тобто перевірялось, як він
 * ВИГЛЯДАЄ, і ніколи, що він РОБИТЬ. При цьому відкликання гостьового доступу
 * — безпекова дія: саме тут виявився мовчазний провал під RLS.
 */

const OWNER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: OWNER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function guest(n: number, over: Record<string, unknown> = {}) {
  return {
    id: `40000000-0000-0000-0000-00000000000${n}`, owner_id: OWNER.id,
    property_id: null, db_id: DB_ID, invite_token: `cafebabe000000000${n}`,
    label: `Орендар ${n}`, guest_user_id: null, status: 'pending',
    claimed_at: null, created_at: NOW, ...over,
  }
}

interface Opts {
  guests?: ReturnType<typeof guest>[]
  /** PATCH віддає 0 рядків — так виглядає відмова RLS на дроті. */
  patchBlocked?: boolean
  /** GET падає — мережа/політика лягли. */
  loadFails?: boolean
}

interface Wire { patches: number }

async function openGuests(page: Page, wire: Wire, opts: Opts = {}) {
  await setupApp(page, { user: OWNER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) =>
    r.request().method() === 'GET' ? jsonRoute(r, []) : r.fallback())
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records',
                   'property_views', 'property_folders', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.route('**/rest/v1/guest_links**', (r) => {
    if (r.request().method() === 'PATCH') {
      wire.patches++
      return jsonRoute(r, opts.patchBlocked ? [] : [{ id: 'x' }])
    }
    if (opts.loadFails) {
      return r.fulfill({ status: 500, contentType: 'application/json',
        body: JSON.stringify({ message: 'server exploded' }) })
    }
    return jsonRoute(r, opts.guests ?? [guest(1)])
  })

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Управління гостями', { exact: true }).click()
  await expect(page.getByText('Гості бази')).toBeVisible({ timeout: 15_000 })
}

async function confirmRevoke(page: Page) {
  await page.getByRole('button', { name: 'Відкликати' }).first().click()
  await expect(page.getByText('Відкликати доступ?')).toBeVisible()
  await page.locator('.modal-actions, [class*=modal]')
    .getByRole('button', { name: 'Відкликати' }).last().click()
}

test('відкликання гостя доходить до сервера і оновлює бейдж', async ({ page }) => {
  const wire: Wire = { patches: 0 }
  await openGuests(page, wire)
  await expect(page.getByText('Орендар 1')).toBeVisible()

  await confirmRevoke(page)

  await expect.poll(() => wire.patches, { timeout: 10_000 }).toBe(1)
  await expect(page.getByText('Відкликано')).toBeVisible()
})

/**
 * Дзеркало гарда з `team.spec.ts`: ті самі два екрани — копії один одного, і
 * саме тому дефект жив у ОБОХ. Фікс в одному без гарда на другий означав би,
 * що наступна правка знову розійдеться.
 */
test('заблокований RLS: гість НЕ позначається відкликаним', async ({ page }) => {
  const wire: Wire = { patches: 0 }
  await openGuests(page, wire, { patchBlocked: true })

  await confirmRevoke(page)

  await expect.poll(() => wire.patches, { timeout: 10_000 }).toBe(1)
  await expect(page.locator('.toast'), 'мовчазна відмова видається за успіх')
    .toContainText(/Не вдалося|доступ/i, { timeout: 10_000 })
  await expect(page.getByText('Відкликано')).toHaveCount(0)
  await expect(page.getByText('Очікує')).toBeVisible()
})

/**
 * Збій завантаження — це НЕ «гостей немає».
 *
 * Раніше `catch` показував тост і лишав `links` порожнім, тобто екран малював
 * «Немає запрошень». Тост зникає за секунди, порожній стан лишається — власник
 * бачив упевнену відповідь «доступів немає» на питання «які доступи я роздав».
 */
test('помилка завантаження показує повтор, а не «Немає запрошень»', async ({ page }) => {
  const wire: Wire = { patches: 0 }
  await openGuests(page, wire, { loadFails: true })

  await expect(page.getByText('Не вдалося завантажити')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Немає запрошень'), 'збій видається за порожній список')
    .toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Спробувати ще раз' })).toBeVisible()
})

/**
 * Мертвий лінк не можна ані копіювати, ані надсилати.
 *
 * `buildDeepLink` віддає '#', коли не задано юзернейм бота — і цей екран
 * лишався останнім місцем, яке спокійно давало надіслати таке «посилання».
 * Той самий клас уже давав прод-інцидент із `TELEGRAM_APP_NAME`.
 */
test('без юзернейма бота обидві дії з лінком неактивні', async ({ page }) => {
  const wire: Wire = { patches: 0 }
  await openGuests(page, wire)

  await expect(page.getByRole('button', { name: 'Копіювати' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Надіслати' })).toBeDisabled()
  // Відкликання від юзернейма бота не залежить і мусить лишатись доступним.
  await expect(page.getByRole('button', { name: 'Відкликати' })).toBeEnabled()
})
