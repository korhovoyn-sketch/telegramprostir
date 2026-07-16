import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'

// ─── ShareSheet functional drive-through ──────────────────────────────────────
// Exercises copy, expiry presets, rotate and revoke — asserting each fires the
// manage_share RPC with the right arguments (the migration-036 backend).

const USER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = new Date().toISOString()

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink',
  share_token: 'aabbccddeeff001122334455', share_expires_at: null,
  created_at: NOW, updated_at: NOW, properties: [],
}

// records every manage_share call so the test can assert the arguments
const manageCalls: Array<Record<string, unknown>> = []

async function setup(page: Page) {
  await setupApp(page, { user: USER })
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route('**/rest/v1/databases**', (route) => {
    const accept = route.request().headers()['accept'] ?? ''
    return json(route, accept.includes('object') ? DB : [DB])
  })
  await page.route('**/rest/v1/properties**', (route) => json(route, []))
  await page.route('**/rest/v1/property_views**', (route) => json(route, []))

  await page.route('**/rest/v1/rpc/manage_share', (route) => {
    const body = JSON.parse(route.request().postData() ?? '{}')
    manageCalls.push(body)
    // Echo a plausible response: rotate → new token; set_expiry → +N days; revoke → past
    const days = body.p_days as number | null
    let expires: string | null = DB.share_expires_at
    if (body.p_action === 'set_expiry' && days) expires = new Date(Date.now() + days * 86400000).toISOString()
    if (body.p_action === 'clear_expiry') expires = null
    if (body.p_action === 'revoke') expires = new Date(Date.now() - 1000).toISOString()
    const token = body.p_action === 'rotate' ? 'ffee0011223344556677aabb' : DB.share_token
    return json(route, [{ share_token: token, share_expires_at: expires, error: null }])
  })

  await page.addInitScript(() => {
    localStorage.setItem('ob_v1', JSON.stringify(['owner-fab', 'obj-fab', 'realtor-qr', 'col-fab']))
  })
}

async function openShareSheet(page: Page) {
  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await page.getByText('БЦ Рубін').first().click()
  await expect(page.getByText('Всі (0)')).toBeVisible()
  await page.getByLabel('Меню бази').click()
  await page.getByText('Аналітика і поширення').click()
  await expect(page.getByText('Аналітика бази')).toBeVisible()
  await page.getByRole('button', { name: 'Поділитися' }).click()
  await expect(page.getByText('Термін дії')).toBeVisible()
}

test.beforeEach(() => { manageCalls.length = 0 })

test('share: QR + link render, copy reports success', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await setup(page)
  await openShareSheet(page)

  // QR encodes the /v URL with the real token
  await expect(page.locator('.qr-wrap svg')).toBeVisible()
  await expect(page.locator('.qr-link')).toContainText('/v/?db=aabbccddeeff001122334455')

  await page.getByRole('button', { name: 'Скопіювати' }).click()
  await expect(page.getByText('Посилання скопійовано')).toBeVisible()
})

test('share: expiry presets call manage_share', async ({ page }) => {
  await setup(page)
  await openShareSheet(page)
  await expect(page.getByText('безстрокове')).toBeVisible()

  await page.locator('.fr-seg-b', { hasText: '7 днів' }).click()
  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_kind: 'db', p_id: DB_ID, p_action: 'set_expiry', p_days: 7 })
  // UI reflects the new expiry (no longer "безстрокове")
  await expect(page.getByText('безстрокове')).toHaveCount(0)

  await page.locator('.fr-seg-b', { hasText: '30 днів' }).click()
  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'set_expiry', p_days: 30 })

  await page.locator('.fr-seg-b', { hasText: 'Без обмежень' }).click()
  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'clear_expiry' })
})

test('share: rotate link requires confirm then calls manage_share rotate', async ({ page }) => {
  await setup(page)
  await openShareSheet(page)

  await page.getByText('Оновити посилання').click()
  await expect(page.getByText('Оновити посилання?')).toBeVisible() // confirm dialog
  await page.getByRole('button', { name: 'Оновити', exact: true }).click()

  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'rotate' })
  await expect(page.getByText('Посилання оновлено')).toBeVisible()
  // QR/link now reflect the rotated token
  await expect(page.locator('.qr-link')).toContainText('ffee0011223344556677aabb')
})

test('share: revoke requires confirm then calls manage_share revoke', async ({ page }) => {
  await setup(page)
  await openShareSheet(page)

  await page.getByText('Відкликати доступ').click()
  await expect(page.getByText('Відкликати доступ?')).toBeVisible()
  await page.getByRole('button', { name: 'Відкликати', exact: true }).click()

  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'revoke' })
  await expect(page.getByText('Доступ відкликано')).toBeVisible()
  await expect(page.getByText('закінчився')).toBeVisible()
})

test('share: revoked link — dead QR is dimmed, copy/telegram disabled, hint shown', async ({ page }) => {
  await setup(page)
  await openShareSheet(page)

  await page.getByText('Відкликати доступ').click()
  await page.getByRole('button', { name: 'Відкликати', exact: true }).click()

  // Мертвий QR не має виглядати живим: бан-оверлей + підказка + disabled-кнопки
  await expect(page.getByText('Посилання неактивне')).toBeVisible()
  await expect(page.locator('.qr-dead-ov')).toBeVisible()
  await expect(page.getByText('Натисніть «Оновити посилання», щоб створити нове')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Скопіювати' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'У Telegram' })).toBeDisabled()

  // Пресет терміну на мертвому лінку НЕ оживляє його мовчки — спершу підтвердження
  const callsBefore = manageCalls.length
  await page.locator('.fr-seg-b', { hasText: 'Без обмежень' }).click()
  await expect(page.getByText('Активувати старе посилання?')).toBeVisible()
  await page.getByRole('button', { name: 'Скасувати', exact: true }).click()
  expect(manageCalls.length).toBe(callsBefore) // RPC не викликався

  // Свідома реактивація через підтвердження — працює
  await page.locator('.fr-seg-b', { hasText: 'Без обмежень' }).click()
  await page.getByRole('button', { name: 'Активувати старе' }).click()
  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'clear_expiry' })
  await expect(page.getByRole('button', { name: 'Скопіювати' })).toBeEnabled()
  await expect(page.locator('.qr-dead-ov')).toHaveCount(0)

  // «Оновити посилання» (ротація) також доступне
  await page.getByText('Оновити посилання', { exact: true }).click()
  await page.getByRole('button', { name: 'Оновити', exact: true }).click()
  await expect.poll(() => manageCalls.at(-1)).toMatchObject({ p_action: 'rotate' })
})
