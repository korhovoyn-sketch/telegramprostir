import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * ПАПКИ: створення й видалення — порушення, знайдені читанням і підтверджені
 * виконанням. `folders.spec`/`folders-wire` міряють ЩАСЛИВІ шляхи (створив,
 * перейменував, видалив); тут — те, що відбувається поза ними.
 *
 *  1. екран керування папками не мав `offlineGuard` взагалі — офлайн дав би
 *     звичайний збій запиту замість «Немає інтернету»;
 *  2. створення до завантаження списку не бачило дублікатів (список порожній);
 *  3. «Створити й перемістити» після збою переміщення лишала папку створеною,
 *     а повторний тап впирався у «Така папка вже є» — тупик;
 *  4. чернетка/копія з уже ВИДАЛЕНОЮ папкою: поле показувало «Без папки», а
 *     збереження слало мертвий uuid → порушення зовнішнього ключа.
 */

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const F1 = '50000000-0000-0000-0000-000000000001'
const DEAD = '50000000-0000-0000-0000-0000000000de'
const NEW_ID = '50000000-0000-0000-0000-0000000000ff'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

const folder = (id: string, name: string, sort: number) =>
  ({ id, db_id: DB_ID, owner_id: USER.id, name, sort_order: sort, created_at: NOW, updated_at: NOW })

function prop(n: number, folderId: string | null) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`, db_id: DB_ID, owner_id: USER.id,
    name: `Офіс ${100 + n}`, floor: String(n), status: 'free', area_useful: 45, area_total: 52,
    area_basis: 'total', rent_type: 'per_m2', rent_rate: 18, utilities_rate: 2.5,
    has_parking: false, parking_spaces: 0, parking_type: null, ev_charger: false,
    folder_id: folderId, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, landlord_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n * 100, share_token: `bb0000000000000000000${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [],
  }
}

interface Wire {
  folderPosts: Record<string, unknown>[]
  propPatches: { url: string; body: Record<string, unknown> }[]
  propPosts: Record<string, unknown>[]
}
const freshWire = (): Wire => ({ folderPosts: [], propPatches: [], propPosts: [] })

interface Opts {
  /** Затримка відповіді на GET папок, мс — «список ще не доїхав». */
  foldersDelay?: number
  /** Перші N PATCH-ів `properties` відмовляють (порожній набір = відмова RLS). */
  failPropPatches?: number
  /** Папки, які бачить сервер. */
  folders?: ReturnType<typeof folder>[]
}

async function setup(page: Page, wire: Wire, opts: Opts = {}) {
  const folders = opts.folders ?? [folder(F1, 'Орендарі', 100)]
  let failLeft = opts.failPropPatches ?? 0
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)

  await page.route('**/rest/v1/databases**', (r) =>
    jsonRoute(r, (r.request().headers()['accept'] ?? '').includes('object') ? DB : [DB]))
  await page.route('**/rest/v1/properties**', (r) => {
    const rq = r.request()
    if (rq.method() === 'PATCH') {
      const url = decodeURIComponent(rq.url())
      wire.propPatches.push({ url, body: JSON.parse(rq.postData() ?? '{}') })
      if (failLeft > 0) { failLeft--; return jsonRoute(r, []) }
      const ids = url.match(/id=in\.\(([^)]+)\)/)?.[1]?.split(',') ?? []
      return jsonRoute(r, ids.map((id) => ({ id })))
    }
    if (rq.method() === 'POST') {
      wire.propPosts.push(JSON.parse(rq.postData() ?? '{}'))
      return jsonRoute(r, [{ ...prop(9, null), ...JSON.parse(rq.postData() ?? '{}') }], 201)
    }
    return jsonRoute(r, [prop(1, null), prop(2, null)])
  })
  await page.route('**/rest/v1/property_folders**', async (r) => {
    const rq = r.request()
    if (rq.method() === 'POST') {
      const body = JSON.parse(rq.postData() ?? '{}') as Record<string, unknown>
      wire.folderPosts.push(body)
      return jsonRoute(r, { ...folder(NEW_ID, String(body.name), 300), ...body })
    }
    if (rq.method() !== 'GET') return jsonRoute(r, [])
    if (opts.foldersDelay) await new Promise((res) => setTimeout(res, opts.foldersDelay))
    return jsonRoute(r, folders)
  })
  for (const t of ['db_members', 'rent_payments', 'rent_payment_records', 'property_views',
                   'guest_links', 'notifications', 'property_photos', 'property_files', 'property_tenancies']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }
}

async function openObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText(/Всі \(/)).toBeVisible({ timeout: 15_000 })
}

async function openFolderManager(page: Page) {
  await openObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText(/Групуйте об.єкти бази/)).toBeVisible({ timeout: 15_000 })
}

test('офлайн: створення, перейменування, зміна порядку й видалення папки кажуть «Немає інтернету» і не шлють запит', async ({ page }) => {
  const wire = freshWire()
  const mutations: string[] = []
  await setup(page, wire, { folders: [folder(F1, 'Орендарі', 100), folder('50000000-0000-0000-0000-000000000002', 'Вільні', 200)] })
  page.on('request', (r) => {
    if (r.url().includes('/rest/v1/property_folders') && r.method() !== 'GET') mutations.push(`${r.method()} ${r.url()}`)
  })
  await openFolderManager(page)
  await expect(page.getByText('Орендарі')).toBeVisible()
  await page.evaluate(() => window.dispatchEvent(new Event('offline')))

  const noInternet = page.getByText('Немає інтернету')

  await page.getByLabel('Назва нової папки').fill('Підвал')
  await page.getByRole('button', { name: 'Додати папку', exact: true }).click()
  await expect(noInternet.first(), 'створення офлайн').toBeVisible({ timeout: 5_000 })

  await page.getByLabel('Перейменувати').first().click()
  await page.locator('.fold-mng-row .fold-mng-input').fill('Орендарі 2026')
  await page.getByLabel('Зберегти').first().click()
  await page.waitForTimeout(500)

  await page.getByLabel('Вниз').first().click()
  await page.waitForTimeout(500)

  await page.getByLabel('Видалити').first().click()
  // Підтвердження нативного попапа в харнесі вимкнене — тож це DOM-фолбек.
  await page.getByRole('button', { name: 'Видалити', exact: true }).last().click()
  await page.waitForTimeout(700)

  expect(mutations, 'офлайн жодна мутація папок не мусить летіти в мережу').toEqual([])
})

test('створення до завантаження списку: дублікат НЕ проходить (список ще порожній)', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { foldersDelay: 1500 })
  await openObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText(/Групуйте об.єкти бази/)).toBeVisible({ timeout: 15_000 })

  // Список папок ще в дорозі (1.5с) — створюємо ту, що вже існує на сервері.
  await page.getByLabel('Назва нової папки').fill('Орендарі')
  await page.getByRole('button', { name: 'Додати папку', exact: true }).click()
  await page.waitForTimeout(2200)

  expect(wire.folderPosts, 'дубль не мусить летіти на сервер, поки список невідомий').toEqual([])
})

test('«Створити й перемістити»: після збою переміщення повторний тап ПЕРЕМІЩАЄ в уже створену папку, а не впирається у дубль', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire, { failPropPatches: 1 })
  await openObjects(page)
  await page.getByLabel('Меню бази').click()
  await page.waitForTimeout(420)
  await page.getByText('Виділити обʼєкти', { exact: true }).click()
  await page.locator('.obj-card').first().click()
  await page.getByRole('button', { name: /У папку/ }).click()
  await expect(page.getByText(/Оберіть папку або створіть нову/)).toBeVisible({ timeout: 10_000 })

  await page.getByLabel('Назва нової папки').fill('Підвал')
  const create = page.getByRole('button', { name: 'Створити й перемістити' })
  await create.click()
  await expect.poll(() => wire.propPatches.length, { timeout: 8_000 }).toBe(1) // збій переміщення
  await expect(page.getByText('Не вдалося перемістити')).toBeVisible()

  await create.click()
  await expect.poll(() => wire.propPatches.length, { timeout: 8_000 }).toBe(2)
  expect(wire.folderPosts, 'друга папка з тією ж назвою не створюється').toHaveLength(1)
  expect(wire.propPatches[1].body.folder_id, 'повтор переміщає в ТУ САМУ створену папку').toBe(NEW_ID)
  await expect(page.getByText('Така папка вже є')).toHaveCount(0)
})

test('чернетка з уже видаленою папкою: поле каже «Без папки» і збереження НЕ шле мертвий folder_id', async ({ page }) => {
  const wire = freshWire()
  await setup(page, wire)
  await page.addInitScript(([uid, dbId, dead]) => {
    localStorage.setItem(`draft_v1:${uid}:prop-new:${dbId}`, JSON.stringify({
      name: 'Чернетка', floor: '3', status: 'free', areaUseful: '40', areaTotal: '', areaBasis: 'total',
      rentType: 'per_m2', rentRate: '18', utilitiesRate: '', hasParking: false, parkingSpaces: '1',
      parkingType: '', evCharger: false, description: '', salePrice: '', tenantName: '',
      landlordName: '', leaseStartDate: '', leaseEndDate: '', address: '', utilities: [], folderId: dead,
    }))
  }, [USER.id, DB_ID, DEAD])

  await openObjects(page)
  await page.getByLabel('Додати обʼєкт').click()
  await expect(page.getByText('Новий обʼєкт')).toBeVisible()
  await expect(page.getByPlaceholder('Офіс 101')).toHaveValue('Чернетка', { timeout: 10_000 })
  // Папки завантажились (рядок вибору є), а мертвої серед них немає — поле
  // мусить показувати «Без папки» і НЕ нести мертвий uuid далі.
  await expect(page.locator('.fr-tap', { hasText: 'Папка' }).getByText('Без папки')).toBeVisible()

  await page.getByRole('button', { name: 'Створити', exact: true }).click()
  await expect.poll(() => wire.propPosts.length, { timeout: 8_000 }).toBeGreaterThan(0)
  const sent = wire.propPosts[0]
  expect(sent.folder_id ?? null, 'мертва папка не мусить їхати в INSERT').not.toBe(DEAD)
})
