import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER, type HarnessUser } from './helpers/harness'

/**
 * Реєстрація мусить СПРАВДІ зберігати вибране, а не лише «гортати екрани».
 *
 * `onboarding-owner.spec.ts` перевіряє навігацію й видимість нативної «Назад» —
 * але жодного разу не дивиться, ЩО полетіло в БД. Якби `updateProfile` тихо
 * викидав `role` (а він і справді викидає її для всіх, у кого роль уже є —
 * захист від самопідвищення), онбординг «проходив» би з роллю NULL: користувач
 * бачить свій домашній екран, а наступний холодний старт знову кидає його на
 * role-select. Тут фіксуємо саме payload-и.
 *
 * Плюс шлях РІЕЛТОРА, якого не було взагалі: у нього інший кінцевий екран
 * (realtor-dashboard, не empty-state), і рахується він з `user.role`, який на
 * той момент мусить бути вже оновленим кроком 1.
 */

/** Перехоплює PATCH-и на users, лишаючи merge-поведінку харнеса. */
async function setupCapture(page: Page, user: HarnessUser) {
  const patches: Record<string, unknown>[] = []
  await setupApp(page, { user })
  let current: Record<string, unknown> = { ...user }
  // Реєструємо ПІСЛЯ setupApp: у Playwright виграє останній збіг.
  await page.route('**/rest/v1/users**', (route) => {
    if (route.request().method() === 'PATCH') {
      try {
        const body = JSON.parse(route.request().postData() ?? '{}')
        patches.push(body)
        current = { ...current, ...body }
      } catch { /* ignore */ }
    }
    const accept = route.request().headers()['accept'] ?? ''
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(accept.includes('object') ? current : [current]),
    })
  })
  return patches
}

const NEW_USER: HarnessUser = { ...DEFAULT_USER, role: null }

test('реєстрація власника: роль і контакти долітають у БД, а не лише гортають екрани', async ({ page }) => {
  const patches = await setupCapture(page, NEW_USER)
  await page.goto('/')

  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()

  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  // Крок 1 мусить закомітити САМЕ роль — інакше наступний холодний старт
  // знову приведе на role-select.
  expect(patches.filter(p => p.role === 'owner'), 'PATCH з role=owner').toHaveLength(1)

  await page.getByLabel('Email').fill('vlasnyk@example.com')
  await page.getByLabel('Телефон').fill('+380671112233')
  await page.getByRole('button', { name: /Почати роботу/i }).click()

  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible()
  const contact = patches.find(p => 'email' in p || 'phone' in p)
  expect(contact, 'контактний PATCH надіслано').toBeTruthy()
  expect(contact).toMatchObject({ email: 'vlasnyk@example.com', phone: '+380671112233' })
  // Роль не має «переїхати» другим PATCH-ем — її вже закомічено, і будь-яка
  // повторна спроба означала б обхід захисту від самопідвищення.
  expect(contact).not.toHaveProperty('role')
})

test('реєстрація рієлтора: інша роль веде на СВІЙ домашній екран', async ({ page }) => {
  const patches = await setupCapture(page, NEW_USER)
  await page.goto('/')

  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await page.getByText('Ріелтор', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()

  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  expect(patches.filter(p => p.role === 'realtor'), 'PATCH з role=realtor').toHaveLength(1)

  // Кінцевий екран рахується з user.role — тобто крок 1 мусив ОНОВИТИ стор,
  // а не лише надіслати запит. Власника тут привело б на empty-state.
  await page.getByRole('button', { name: /Почати роботу/i }).click()
  await expect(page.getByText(/Робочі бази|Немає підписок/).first()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText(/Немає жодної бази/i)).toHaveCount(0)
})

test('реєстрація: невалідний email не зберігається і не пускає далі', async ({ page }) => {
  const patches = await setupCapture(page, NEW_USER)
  await page.goto('/')

  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()

  const before = patches.length
  await page.getByLabel('Email').fill('не-email')
  await page.getByRole('button', { name: /Почати роботу/i }).click()

  await expect(page.getByText(/Невірний email/i)).toBeVisible()
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()
  expect(patches.length, 'жодного PATCH з битим email').toBe(before)
})

test('реєстрація: «Пропустити» веде далі, нічого не зберігаючи', async ({ page }) => {
  const patches = await setupCapture(page, NEW_USER)
  await page.goto('/')

  await expect(page.getByText(/Хто ти\?/i)).toBeVisible({ timeout: 20_000 })
  await page.getByText('Власник', { exact: true }).first().click()
  await page.getByRole('button', { name: /Продовжити/i }).click()
  await expect(page.getByText('Контакти', { exact: true })).toBeVisible()

  const before = patches.length
  await page.getByLabel('Email').fill('nezberezhetsya@example.com')
  await page.getByRole('button', { name: /Пропустити/i }).click()

  await expect(page.getByText(/Немає жодної бази/i)).toBeVisible()
  expect(patches.length, '«Пропустити» не шле контактів').toBe(before)
})
