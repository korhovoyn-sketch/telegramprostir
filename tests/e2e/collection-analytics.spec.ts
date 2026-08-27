import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * АНАЛІТИКА ПІДБІРКИ: дані писались, але їх не читав ЖОДЕН екран.
 *
 * `record_public_view(p_kind='col')` пише рядок із `collection_id` (міграція
 * 040), і рієлтор має на нього SELECT-політику `views_col_realtor_select`. Але
 * `sharing-analytics` відкривався лише з `propertyId` або `dbId` — тобто на
 * питання «чи відкрив клієнт те, що я надіслав» відповідь лежала в базі й була
 * недосяжна.
 *
 * Гард стереже ОБИДВІ половини: що екран фільтрує саме по `collection_id` (а не
 * приносить чужі перегляди), і що порожній стан не видає збій за «ніхто не
 * відкривав».
 */

const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }
const COL_ID = '70000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const COLLECTION = {
  id: COL_ID, realtor_id: REALTOR.id, name: 'Для клієнта А', is_draft: false,
  share_token: 'ff00112233445566778899aa', share_expires_at: null,
  created_at: NOW, updated_at: NOW,
}

/** Перегляди підбірки; `property_id` у них NULL — саме тому їх не бачив
 *  запит по `property_id`, яким ходили обидві наявні гілки екрана. */
const COL_VIEWS = [
  { id: 'v1', property_id: null, viewer_id: null, viewer_name: 'Веб-перегляд підбірки', action: 'view', created_at: NOW },
  { id: 'v2', property_id: null, viewer_id: null, viewer_name: 'Веб-перегляд підбірки', action: 'view', created_at: NOW },
]

async function realtorApp(page: Page, views: unknown[]) {
  const viewQueries: string[] = []
  await setupApp(page, { user: REALTOR })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/collections**', (r: Route) => jsonRoute(r, [COLLECTION]))
  await page.route('**/rest/v1/collection_properties**', (r: Route) => jsonRoute(r, []))
  await page.route('**/rest/v1/property_views**', (r: Route) => {
    viewQueries.push(new URL(r.request().url()).search)
    return jsonRoute(r, views)
  })
  for (const t of ['realtor_subscriptions', 'databases', 'properties', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }
  return viewQueries
}

async function openCollectionAnalytics(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await page.getByText('Для клієнта А').first().click()
  await page.getByText('Аналітика підбірки').click()
}

test('рієлтор бачить, скільки разів відкривали ЙОГО підбірку', async ({ page }) => {
  const viewQueries = await realtorApp(page, COL_VIEWS)
  await openCollectionAnalytics(page)

  await expect(page.locator('.hdr-t')).toHaveText('Аналітика підбірки')
  // Обидва перегляди дійшли до лічильника «за 7 днів».
  await expect(page.locator('.stat-n').first()).toHaveText('2')

  // ГОЛОВНЕ: фільтр саме по `collection_id`. Без цього екран показав би
  // ЧУЖІ перегляди — мок віддає той самий масив на будь-який запит, тож
  // «двійка на екрані» сама по собі нічого не доводить.
  await expect
    .poll(() => viewQueries.some((q) => q.includes(`collection_id=eq.${COL_ID}`)))
    .toBe(true)
})

test('порожня аналітика підбірки не видає збій за «ніхто не відкривав»', async ({ page }) => {
  await realtorApp(page, [])
  await openCollectionAnalytics(page)

  await expect(page.getByText('Немає переглядів')).toBeVisible({ timeout: 15_000 })
  // Підпис мусить бути ПРО ПІДБІРКУ: спільний текст із бази («щоб рієлтори
  // побачили обʼєкти») тут читається як чужа порада — підбірку надсилають
  // КЛІЄНТУ, а не рієлторам.
  await expect(page.getByText(/Надішли підбірку клієнту/)).toBeVisible()
})
