import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Папки на рівні ЗАПИТІВ.
//
// `folders.spec.ts` покриває створення, відмову на дубль, bulk-перенос і
// селектор у формі. Перейменування, видалення й зміна порядку не мали жодного
// асерту на дроті — перевірялась лише поведінка UI. Тут закривається саме це:
// що летить у мережу і що відбувається, коли воно НЕ долітає (відкат оптимістики).

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const F1 = '50000000-0000-0000-0000-000000000001'
const F2 = '50000000-0000-0000-0000-000000000002'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

function folder(id: string, name: string, sort: number) {
  return { id, db_id: DB_ID, owner_id: USER.id, name, sort_order: sort, created_at: NOW, updated_at: NOW }
}

function prop(n: number, folderId: string | null) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс ${100 + n}`, floor: String(n), status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: folderId, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  }
}

interface Wire {
  patches: { url: string; body: Record<string, unknown> }[]
  deletes: string[]
  posts: Record<string, unknown>[]
}

interface Opts {
  /** Мутації папок відмовляють (RLS) — перевіряємо ВІДКАТ оптимістики. */
  fail?: boolean
  folders?: ReturnType<typeof folder>[]
  props?: ReturnType<typeof prop>[]
}

async function setup(page: Page, wire: Wire, opts: Opts = {}) {
  const folders = opts.folders ?? [folder(F1, 'Орендарі', 100), folder(F2, 'Вільні', 200)]
  const props = opts.props ?? [prop(1, F1), prop(2, null)]

  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const url = decodeURIComponent(rq.url())
      wire.patches.push({ url, body: JSON.parse(rq.postData() ?? '{}') })
      const ids = url.match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      return jsonRoute(r, ids.map((id) => ({ id })))
    }
    return jsonRoute(r, props)
  })

  await page.route('**/rest/v1/property_folders**', (r) => {
    const rq = r.request()
    const url = decodeURIComponent(rq.url())
    if (rq.method() === 'PATCH') {
      wire.patches.push({ url, body: JSON.parse(rq.postData() ?? '{}') })
      if (opts.fail) return jsonRoute(r, [])
      const id = url.match(/id=eq\.([0-9a-f-]+)/)?.[1]
      return jsonRoute(r, id ? [{ id }] : [])
    }
    if (rq.method() === 'DELETE') {
      wire.deletes.push(url)
      if (opts.fail) return jsonRoute(r, [])
      const id = url.match(/id=eq\.([0-9a-f-]+)/)?.[1]
      return jsonRoute(r, id ? [{ id }] : [])
    }
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      wire.posts.push(body)
      return jsonRoute(r, { ...folder('50000000-0000-0000-0000-0000000000ff', String(body.name), 300), ...body })
    }
    return jsonRoute(r, folders)
  })

  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'guest_links', 'notifications', 'property_photos', 'property_files']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

function freshWire(): Wire { return { patches: [], deletes: [], posts: [] } }

async function openFolderManager(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
  await page.getByLabel('Меню бази').click()
  await expect(page.locator('.modal')).toBeVisible()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()
  // Керування папками — ПОВНОЕКРАННИЙ маршрут (фаза 4), а не шит: чекаємо на
  // заголовок екрана, а не на появу `.modal`.
  await expect(page.getByText('Групуйте обʼєкти всередині бази')).toBeVisible({ timeout: 15_000 })
}

test('перейменування летить PATCH-ом із новою назвою', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openFolderManager(page)

  await page.getByLabel('Перейменувати').first().click()
  // Скоуп на РЯДОК папки: на екрані є ще поле «Нова», тож голий локатор інпута
  // дав би два збіги і правка не комітилась би взагалі.
  const input = page.locator('.fold-mng-row .fold-mng-input')
  await input.fill('Орендарі 2026')
  await page.getByLabel('Зберегти').first().click()
  await page.waitForTimeout(900)

  const patch = wire.patches.find((p) => p.url.includes('property_folders'))
  expect(patch, 'PATCH папки мусить полетіти').toBeTruthy()
  expect(patch!.body.name).toBe('Орендарі 2026')
  expect(patch!.body.updated_at, 'мітка часу оновлюється').toBeTruthy()
})

test('невдале перейменування ВІДКОЧУЄ оптимістику', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { fail: true })
  await openFolderManager(page)

  await page.getByLabel('Перейменувати').first().click()
  await page.locator('.fold-mng-row .fold-mng-input').fill('Назва, якої не буде')
  await page.getByLabel('Зберегти').first().click()
  await page.waitForTimeout(1200)

  await expect(page.locator('.toast')).toBeVisible()
  // Оптимістика знята: у списку знову стара назва, а не та, що не збереглась.
  // Список тепер на ЕКРАНІ (`.fold-mng`), а не в шиті — `.modal` тут лишився б
  // лише від підтвердження, тобто асерт мовчки перевіряв би не той вузол.
  await expect(page.locator('.fold-mng')).toContainText('Орендарі')
  await expect(page.locator('.fold-mng')).not.toContainText('Назва, якої не буде')
})

test('видалення непорожньої папки попереджає про долю обʼєктів', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openFolderManager(page)

  await page.getByLabel('Видалити').first().click()
  // Скоуп саме на діалог підтвердження: рядки папок теж мають кнопки з
  // aria-label «Видалити», тож пошук по всьому шиту дає strict-mode violation.
  const confirm = page.locator('.modal', { hasText: 'Видалити папку' })
  await expect(confirm).toContainText(/залишаться в базі/)
  await confirm.getByRole('button', { name: /^Видалити$/ }).click()
  await page.waitForTimeout(900)

  expect(wire.deletes.length, 'DELETE папки мусить полетіти').toBe(1)
  expect(wire.deletes[0]).toContain(`id=eq.${F1}`)
})

test('невдале видалення повертає папку у список', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { fail: true })
  await openFolderManager(page)

  await page.getByLabel('Видалити').first().click()
  await page.locator('.modal', { hasText: 'Видалити папку' })
    .getByRole('button', { name: /^Видалити$/ }).click()
  await page.waitForTimeout(1200)

  await expect(page.locator('.toast')).toBeVisible()
  await expect(page.locator('.fold-mng'), 'папка повернулась після відкату').toContainText('Орендарі')
})

test('зміна порядку шле два PATCH зі свопнутими sort_order', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await openFolderManager(page)

  await page.getByLabel('Вниз').first().click()
  await page.waitForTimeout(900)

  const folderPatches = wire.patches.filter((p) => p.url.includes('property_folders'))
  expect(folderPatches.length, 'своп — це рівно два оновлення').toBe(2)
  const orders = folderPatches.map((p) => p.body.sort_order).sort()
  expect(orders, 'обидва рядки отримують позиції одне одного').toEqual([100, 200])
})
