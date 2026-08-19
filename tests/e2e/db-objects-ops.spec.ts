import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Операції над обʼєктами всередині бази: порядок, пакетні дії, видалення.
//
// Два гарди тут стоять на реальних дефектах:
//  • «Змінити порядок» не скидало СОРТУВАННЯ, тож список малювався в одному
//    порядку, а стрілки міняли сусідів у зовсім іншому — переставлялась не та пара;
//  • пакетне «Вільно» лишало орендаря й дати договору на «вільному» обʼєкті,
//    і ця суміш їхала в експорт та в публічну /v.

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

/** Поверх і порядок навмисно РОЗІЙШЛИСЬ: за sort_order 1,2,3 — за поверхом 3,1,2. */
function prop(n: number, floor: string, sort: number, over: Record<string, unknown> = {}) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс ${100 + n}`, floor, status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: sort, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

interface Wire {
  patches: { url: string; body: Record<string, unknown> }[]
  deletes: string[]
  storageRemoves: number
}

interface Opts {
  props?: ReturnType<typeof prop>[]
  /** DELETE обʼєктів віддає 0 рядків — так виглядає блокування RLS. */
  deleteBlocked?: boolean
  /** PATCH віддає 0 рядків — те саме блокування, але на оновленні. */
  patchBlocked?: boolean
}

async function setup(page: Page, wire: Wire, opts: Opts = {}) {
  const props = opts.props ?? [
    prop(1, '5', 100), // поверх 5, порядок 1
    prop(2, '1', 200), // поверх 1, порядок 2
    prop(3, '3', 300), // поверх 3, порядок 3
  ]
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))

  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    const url = decodeURIComponent(rq.url())
    if (rq.method() === 'PATCH') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      wire.patches.push({ url, body })
      const ids = url.match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      const single = url.match(/id=eq\.([0-9a-f-]+)/)?.[1]
      const touched = ids.length > 0 ? ids : (single ? [single] : [])
      return jsonRoute(r, opts.patchBlocked ? [] : touched.map((id) => ({ id })))
    }
    if (rq.method() === 'DELETE') {
      wire.deletes.push(url)
      const ids = url.match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      return jsonRoute(r, opts.deleteBlocked ? [] : ids.map((id) => ({ id })))
    }
    if ((rq.headers()['accept'] ?? '').includes('object')) {
      const m = url.match(/id=eq\.([0-9a-f-]+)/)
      return jsonRoute(r, props.find((p) => p.id === m?.[1]) ?? props[0])
    }
    return jsonRoute(r, props)
  })

  await page.route('**/rest/v1/property_photos**', (r) =>
    jsonRoute(r, [{ storage_path: `${props[0]?.id}/1.jpg` }]))
  await page.route('**/rest/v1/property_files**', (r) => jsonRoute(r, []))
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records',
                   'property_views', 'property_folders', 'guest_links', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
  await page.route('**/storage/v1/object/**', (r) => {
    if (['POST', 'DELETE'].includes(r.request().method())) wire.storageRemoves++
    return jsonRoute(r, [])
  })
}

function freshWire(): Wire {
  return { patches: [], deletes: [], storageRemoves: 0 }
}

async function openDb(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

async function openMenu(page: Page) {
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
}

test('зміна порядку скидає сортування — інакше стрілки міняють НЕ ту пару', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openDb(page)

  // Сортуємо за поверхом: показаний порядок стає 1 → 3 → 5 поверх,
  // тобто Офіс 102 (пов.1), Офіс 103 (пов.3), Офіс 101 (пов.5).
  await page.getByRole('button', { name: 'За поверхом' }).click()
  await page.waitForTimeout(300)

  await openMenu(page)
  await page.getByText('Змінити порядок', { exact: true }).click()
  await page.waitForTimeout(400)

  // Після входу в режим порядку список МУСИТЬ повернутись до sort_order,
  // тобто до 101 → 102 → 103. Якщо сортування лишилось, перший рядок — 102.
  const firstRow = await page.locator('.obj-card, .row').first().innerText()
  expect(firstRow, 'у режимі порядку список іде за sort_order, а не за поверхом').toContain('Офіс 101')
})

/**
 * Заблокований RLS реордер мусить СКАЗАТИ про себе, а не вдавати успіх.
 *
 * `reorderProperty` була ЄДИНОЮ мутацією `useProperties` без `.select('id')` +
 * `assertAffected` — усі сусідні (статус, папка, перенос, видалення) його вже
 * мали. Під RLS заблокований UPDATE повертає порожній набір і NULL у `error`,
 * тобто редактор, чий доступ відкликали посеред роботи, бачив переставлений
 * список, який мовчки повертався на місце при наступному завантаженні.
 */
test('зміна порядку: заблокований RLS UPDATE не вдає успіх', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { patchBlocked: true })
  await openDb(page)

  await openMenu(page)
  await page.getByText('Змінити порядок', { exact: true }).click()
  await page.waitForTimeout(400)

  // Другий рядок угору — пара, яку точно можна поміняти місцями.
  await page.getByLabel('Вгору').nth(1).click()

  await expect(page.getByText(/Не вдалося зберегти порядок/), 'мовчазний провал видається за успіх')
    .toBeVisible({ timeout: 10_000 })
  // Оптимістичну перестановку мусить бути відкочено — інакше користувач лишиться
  // з порядком, якого на сервері немає.
  const firstRow = await page.locator('.obj-card, .row').first().innerText()
  expect(firstRow, 'оптимістичний своп не відкотився').toContain('Офіс 101')
})

test('пакетне «Вільно» знімає орендаря і дати договору', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, {
    props: [
      prop(1, '5', 100, {
        status: 'occupied', tenant_name: 'ТОВ «Ромашка»',
        lease_start_date: '2025-01-01', lease_end_date: '2026-01-01',
      }),
      prop(2, '1', 200),
    ],
  })
  await openDb(page)
  await openMenu(page)
  await page.getByText('Виділити об\'єкти', { exact: true }).click()
  await page.waitForTimeout(400)

  await page.locator('.obj-card, .row').first().click()
  await page.getByRole('button', { name: /Вільно/ }).last().click()
  await page.waitForTimeout(900)

  const patch = wire.patches.find((p) => p.body.status === 'free')
  expect(patch, 'PATCH статусу мусить полетіти').toBeTruthy()
  expect(patch!.body.tenant_name, 'вільний обʼєкт не має орендаря').toBeNull()
  expect(patch!.body.lease_start_date).toBeNull()
  expect(patch!.body.lease_end_date).toBeNull()
})

test('пакетне видалення: заблокований RLS DELETE не стирає фото і не бреше', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { deleteBlocked: true })
  await openDb(page)
  await openMenu(page)
  await page.getByText('Виділити об\'єкти', { exact: true }).click()
  await page.waitForTimeout(400)

  await page.locator('.obj-card, .row').first().click()
  await page.locator('.batch-pill.err').click()

  // Підпис пакетного підтвердження несе лічильник: «Видалити (N)».
  const confirm = page.locator('.modal').last()
  await confirm.getByRole('button', { name: /^Видалити \(\d+\)$/ }).click()
  await page.waitForTimeout(1200)

  expect(wire.storageRemoves, 'фото не можна знищити, коли рядки не видалились').toBe(0)
  await expect(page.locator('.toast')).toContainText(/Помилка|доступ/i)
  // Картки лишились на місці — оптимістика не «з'їла» їх назавжди.
  await expect(page.getByText('Офіс 101').first()).toBeVisible()
})
