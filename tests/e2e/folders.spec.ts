import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute } from './helpers/harness'

// ─── Folders: accordion grouping, management modal, bulk move, form selector ──

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const FOLDER_A = '40000000-0000-0000-0000-0000000000a1'
const FOLDER_B = '40000000-0000-0000-0000-0000000000b2'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

function prop(n: number, over: Record<string, unknown>) {
  return {
    id: `20000000-0000-0000-0000-00000000000${n}`,
    db_id: DB_ID, owner_id: USER.id, name: `Офіс ${100 + n}`, floor: String(n + 1),
    status: 'free', area_useful: 45, area_total: 52, area_basis: 'total', rent_type: 'per_m2',
    rent_rate: null, utilities_rate: null, has_parking: false, parking_spaces: 0,
    folder_id: null, utilities: null, description: null, address: null, sale_price: null,
    tenant_name: null, lease_start_date: null, lease_end_date: null,
    sort_order: n, share_token: `bb00000000000000000000${n}${n}`, share_expires_at: null,
    created_at: NOW, updated_at: NOW, photos: [], ...over,
  }
}

const PROPERTIES = [
  prop(1, { folder_id: FOLDER_A }),
  prop(2, { folder_id: FOLDER_A }),
  prop(3, {}), // unfoldered
]

const FOLDERS = [
  { id: FOLDER_A, db_id: DB_ID, owner_id: USER.id, name: 'Перший поверх', sort_order: 100, created_at: NOW, updated_at: NOW },
  { id: FOLDER_B, db_id: DB_ID, owner_id: USER.id, name: 'Другий поверх', sort_order: 200, created_at: NOW, updated_at: NOW },
]

async function setupFixtures(page: Page) {
  await setupApp(page, { user: USER })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return jsonRoute(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    if (req.method() === 'PATCH') return jsonRoute(route, [], 200)
    const accept = req.headers()['accept'] ?? ''
    if (accept.includes('object')) {
      const m = req.url().match(/id=eq\.([0-9a-f-]+)/)
      return jsonRoute(route, PROPERTIES.find(p => p.id === m?.[1]) ?? PROPERTIES[0])
    }
    return jsonRoute(route, PROPERTIES)
  })
  await page.route('**/rest/v1/property_folders**', (route) => {
    const req = route.request()
    if (req.method() === 'POST') {
      const body = JSON.parse(req.postData() ?? '{}')
      return jsonRoute(route, [{ id: '40000000-0000-0000-0000-0000000000c3', db_id: DB_ID, owner_id: USER.id, sort_order: 300, created_at: NOW, updated_at: NOW, ...body }], 201)
    }
    return jsonRoute(route, FOLDERS)
  })

  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openObjects(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (3)')).toBeVisible()
}

test('folders: accordion sections group objects and collapse', async ({ page }) => {
  await setupFixtures(page)
  await openObjects(page)

  // Both folder headers + the "Без папки" section render.
  await expect(page.locator('.fold-hd-name', { hasText: 'Перший поверх' })).toBeVisible()
  await expect(page.locator('.fold-hd-name', { hasText: 'Другий поверх' })).toBeVisible()
  await expect(page.locator('.fold-hd-name', { hasText: 'Без папки' })).toBeVisible()

  // Folder A holds its two objects; expanded by default.
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toBeVisible()
  await expect(page.locator('.obj-card', { hasText: 'Офіс 102' })).toBeVisible()

  // Collapsing folder A hides its objects (kept mounted for the animation, but
  // visibility:hidden once collapsed).
  await page.locator('.fold-hd', { hasText: 'Перший поверх' }).click()
  await expect(page.locator('.obj-card', { hasText: 'Офіс 101' })).toBeHidden()
  // The unfoldered object stays visible (different section).
  await expect(page.locator('.obj-card', { hasText: 'Офіс 103' })).toBeVisible()
})

test('folders: manage screen creates a folder', async ({ page }) => {
  await setupFixtures(page)
  await openObjects(page)

  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  await expect(page.getByText('Групуйте об\'єкти всередині бази')).toBeVisible()

  const postReq = page.waitForRequest(r => r.url().includes('/rest/v1/property_folders') && r.method() === 'POST')
  await page.getByLabel('Назва нової папки').fill('Підвал')
  await page.getByRole('button', { name: 'Додати папку', exact: true }).click()
  const req = await postReq
  expect(JSON.parse(req.postData() ?? '{}').name).toBe('Підвал')
})

test('folders: duplicate name is rejected without a POST', async ({ page }) => {
  await setupFixtures(page)
  let posted = false
  await page.route('**/rest/v1/property_folders**', (route) => {
    if (route.request().method() === 'POST') { posted = true; return jsonRoute(route, [], 201) }
    return route.fallback()
  })
  await openObjects(page)

  await page.getByLabel('Меню бази').click()
  await page.getByText('Папки', { exact: true }).click()
  // "Перший поверх" already exists in the fixture folders.
  await page.getByLabel('Назва нової папки').fill('Перший поверх')
  await page.getByRole('button', { name: 'Додати папку', exact: true }).click()
  await expect(page.getByText('Така папка вже є')).toBeVisible()
  expect(posted).toBe(false)
})

test('folders: bulk move sends a folder_id PATCH', async ({ page }) => {
  await setupFixtures(page)
  let patchBody: Record<string, unknown> | null = null
  await page.route('**/rest/v1/properties**', (route) => {
    const req = route.request()
    if (req.method() === 'PATCH') {
      patchBody = JSON.parse(req.postData() ?? '{}')
      return jsonRoute(route, [], 200)
    }
    return route.fallback()
  })

  await openObjects(page)

  await page.getByLabel('Меню бази').click()
  await page.getByText("Виділити об'єкти").click()
  await page.locator('.obj-card', { hasText: 'Офіс 103' }).click()
  await expect(page.getByText('1 обрано')).toBeVisible()

  await page.getByRole('button', { name: /У папку/ }).click()
  await page.locator('.sheet-row', { hasText: 'Перший поверх' }).click()

  await expect.poll(() => patchBody, { timeout: 10_000 }).not.toBeNull()
  expect(patchBody!.folder_id).toBe(FOLDER_A)
})

test('folders: form folder selector picks a folder', async ({ page }) => {
  await setupFixtures(page)
  await openObjects(page)

  await page.getByLabel("Додати об'єкт").click()
  await expect(page.getByText("Новий об'єкт")).toBeVisible()

  // Вибір папки у формі — ІНЛАЙНОВИЙ (фаза 4): рядок розгортає список прямо
  // тут, бо перехід на окремий екран розмонтував би незбережену форму.
  await page.locator('.fr-tap', { hasText: 'Папка' }).click()
  const sub = page.locator('.fr-sub')
  await expect(sub.filter({ hasText: 'Без папки' })).toBeVisible()
  await sub.filter({ hasText: 'Другий поверх' }).click()
  // Список згорнувся, а рядок показує обрану папку.
  await expect(page.locator('.fr-sub')).toHaveCount(0)
  await expect(page.locator('.fr-tap', { hasText: 'Папка' }).getByText('Другий поверх')).toBeVisible()
})
