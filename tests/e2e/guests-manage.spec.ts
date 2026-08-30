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
  /** SELECT з `guest_name` падає з 42703 — так виглядає бекенд БЕЗ міграції 048. */
  noNameColumn?: boolean
  /** PATCH віддає 0 рядків — так виглядає відмова RLS на дроті. */
  patchBlocked?: boolean
  /** GET падає — мережа/політика лягли. */
  loadFails?: boolean
  /** DELETE віддає 0 рядків — та сама мовчазна відмова RLS, але на видаленні. */
  deleteBlocked?: boolean
}

interface Wire { patches: number; deletes: number }

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
    if (r.request().method() === 'DELETE') {
      wire.deletes++
      return jsonRoute(r, opts.deleteBlocked ? [] : [{ id: 'x' }])
    }
    if (opts.loadFails) {
      return r.fulfill({ status: 500, contentType: 'application/json',
        body: JSON.stringify({ message: 'server exploded' }) })
    }
    const url = decodeURIComponent(r.request().url())
    if (opts.noNameColumn && url.includes('guest_name')) {
      return r.fulfill({ status: 400, contentType: 'application/json',
        body: JSON.stringify({ code: '42703', message: 'column guest_links.guest_name does not exist' }) })
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

test('відкликання гостя доходить до сервера і підтверджується', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire)
  await expect(page.getByText('Орендар 1')).toBeVisible()

  await confirmRevoke(page)

  await expect.poll(() => wire.patches, { timeout: 10_000 }).toBe(1)
  // Рядок їде у ЗГОРНУТУ секцію, тобто зникає з очей — тому підтвердженням
  // мусить бути тост. Без нього дія завершується мовчазним зникненням рядка,
  // що читається як збій, а не як успіх.
  await expect(page.locator('.toast')).toContainText('Доступ відкликано')
  await expect(page.getByRole('button', { name: /Відкликані \(1/ })).toBeVisible()
  await expect(page.getByText('Активних доступів немає')).toBeVisible()
})

/**
 * Дзеркало гарда з `team.spec.ts`: ті самі два екрани — копії один одного, і
 * саме тому дефект жив у ОБОХ. Фікс в одному без гарда на другий означав би,
 * що наступна правка знову розійдеться.
 */
test('заблокований RLS: гість НЕ позначається відкликаним', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
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
  const wire: Wire = { patches: 0, deletes: 0 }
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
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire)

  await expect(page.getByRole('button', { name: 'Копіювати' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Надіслати' })).toBeDisabled()
  // Відкликання від юзернейма бота не залежить і мусить лишатись доступним.
  await expect(page.getByRole('button', { name: 'Відкликати' })).toBeEnabled()
})


/**
 * ІМʼЯ ТОГО, ХТО ПРИЙНЯВ — а не лише підпис, який власник вигадав сам.
 *
 * `db_members` має `member_name` ще з 041, а `guest_links` до 048 не мав
 * нічого: список гостей відповідав на питання «як я назвав ці запрошення»,
 * але не на «хто цим користується». Для доступу до нерухомості важливе саме
 * друге. Підпис лишається ПОРЯД: він каже, за що доступ.
 */
test('прийнятий лінк показує імʼя гостя, а підпис лишається поряд', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, {
    guests: [guest(1, {
      status: 'active', claimed_at: NOW,
      guest_user_id: '90000000-0000-0000-0000-000000000009',
      guest_name: 'Олена Ковальчук',
    })],
  })

  await expect(page.getByText('Олена Ковальчук')).toBeVisible()
  await expect(page.getByText(/Орендар 1 ·/), 'підпис власника мусить лишитись').toBeVisible()
})

/**
 * ФРОНТ ДЕПЛОЇТЬСЯ НЕЗАЛЕЖНО ВІД МІГРАЦІЇ.
 *
 * `select` невідомої колонки — це 400 від PostgREST, тобто ВЕСЬ екран у стані
 * помилки, а не просто відсутні імена. Той самий патерн ретраю, що
 * `useProperties` тримає для `folder_id`.
 */
test('без міграції 048 екран працює — просто без імен', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, { noNameColumn: true })

  await expect(page.getByText('Орендар 1')).toBeVisible()
  await expect(page.getByText('Не вдалося завантажити'), 'відсутня колонка поклала екран')
    .toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Відкликати' })).toBeEnabled()
})

/**
 * ВІДКЛИКАНІ НЕ ВИШТОВХУЮТЬ ЖИВІ ДОСТУПИ.
 *
 * Видалення рядків немає, тож за рік активного користування база накопичує
 * десятки мертвих доступів — і саме тоді, коли їх найбільше, живі опиняються
 * за фолдом. Згорнута секція лишає їх доступними, не роблячи списком за
 * замовчуванням.
 */
test('відкликані згорнуті, живі — зверху', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, {
    guests: [
      guest(1, { status: 'revoked', label: 'Старий орендар' }),
      guest(2, { status: 'active', claimed_at: NOW, label: 'Чинний орендар' }),
    ],
  })

  await expect(page.getByText('Чинний орендар')).toBeVisible()
  await expect(page.getByText('Старий орендар'), 'відкликаний показаний одразу').toHaveCount(0)

  await page.getByRole('button', { name: /Відкликані \(1/ }).click()
  await expect(page.getByText('Старий орендар')).toBeVisible()
})

/**
 * Коли ВСІ доступи відкликані, екран не має виглядати як «нічого не
 * завантажилось»: активна секція порожня, але список НЕ порожній.
 */
test('усі відкликані: сказано прямо, а не порожній екран', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, { guests: [guest(1, { status: 'revoked' })] })

  await expect(page.getByText('Активних доступів немає')).toBeVisible()
  await expect(page.getByText('Немає запрошень'), 'це не порожній список').toHaveCount(0)
  await expect(page.getByRole('button', { name: /Відкликані \(1/ })).toBeVisible()
})


/**
 * Відкликані рядки накопичувались НАЗАВЖДИ: відкликання лише міняє статус, а
 * видалення не було взагалі. Згорнута секція ховає їх з очей, але не з даних —
 * за рік користування база збирає десятки мертвих доступів.
 */
test('відкликаний запис можна прибрати, і це доходить до сервера', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, { guests: [guest(1, { status: 'revoked', label: 'Старий орендар' })] })

  await page.getByRole('button', { name: /Відкликані \(1/ }).click()
  await expect(page.getByText('Старий орендар')).toBeVisible()

  await page.getByRole('button', { name: 'Прибрати' }).first().click()
  await expect(page.getByText('Прибрати запис?')).toBeVisible()
  await page.locator('.modal-actions, [class*=modal]')
    .getByRole('button', { name: 'Прибрати' }).last().click()

  await expect.poll(() => wire.deletes, { timeout: 10_000 }).toBe(1)
  // Саме `.acc-name`, а не `getByText`: текст імені є ще й у тілі шита
  // підтвердження, який виїжджає ~320мс — інакше замір ловить його, а не рядок.
  await expect(page.locator('.acc-name', { hasText: 'Старий орендар' })).toHaveCount(0)
})

/**
 * Дзеркало гарда відкликання, і воно потрібне саме тут: під RLS заблокований
 * DELETE віддає ПОРОЖНІЙ набір і NULL у `error` — тобто «прибрав» і «не мав
 * права» на дроті нерозрізненні. Без `assertAffected` рядок зникав би з екрана,
 * а в базі лишався: наступне відкриття показало б його знову, і це читалось би
 * як «застосунок не памʼятає дій».
 */
test('заблокований RLS: запис НЕ зникає зі списку', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, {
    guests: [guest(1, { status: 'revoked', label: 'Старий орендар' })],
    deleteBlocked: true,
  })

  await page.getByRole('button', { name: /Відкликані \(1/ }).click()
  await page.getByRole('button', { name: 'Прибрати' }).first().click()
  await expect(page.getByText('Прибрати запис?')).toBeVisible()
  await page.locator('.modal-actions, [class*=modal]')
    .getByRole('button', { name: 'Прибрати' }).last().click()

  await expect.poll(() => wire.deletes, { timeout: 10_000 }).toBe(1)
  await expect(page.getByText('Помилка')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('.acc-name', { hasText: 'Старий орендар' }),
    'рядок мусить лишитись — сервер його не видалив').toBeVisible()
})

/**
 * Живий доступ прибрати НЕ можна: інакше кнопка стала б другим шляхом
 * позбавлення доступу — без підтвердження про наслідки для людини.
 */
test('у живого доступу кнопки «Прибрати» немає', async ({ page }) => {
  const wire: Wire = { patches: 0, deletes: 0 }
  await openGuests(page, wire, { guests: [guest(1, { status: 'active', claimed_at: NOW })] })

  await expect(page.getByRole('button', { name: 'Відкликати' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Прибрати' })).toHaveCount(0)
})
