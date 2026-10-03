import { test, expect, type Page } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb } from './helpers/ownerFixtures'

/**
 * СВАЙП УНИЗ НЕ ГУБИТЬ НАБРАНЕ.
 *
 * Telegram закриває Mini App свайпом униз або хрестиком МИТТЄВО — разом із
 * тим, що людина встигла ввести. `enableClosingConfirmation` змушує його
 * спершу спитати. Виклик стояв у трьох формах із семи: оренда, розклад і
 * підтвердження платежу та запрошення губили введене мовчки.
 *
 * Гард читає стан, який харнес ЗАПАМʼЯТОВУЄ (`__tgClosingConfirm`), і
 * перевіряє обидва боки: на формі Telegram питає, а після виходу — ні.
 * Друга половина не формальність: підтвердження, що лишилось після форми,
 * питало б «закрити?» на кожному екрані списку.
 */

const closing = (page: Page) =>
  page.evaluate(() => (window as unknown as Record<string, unknown>).__tgClosingConfirm === true)

async function expectAsks(page: Page, where: string) {
  await expect.poll(() => closing(page), `${where}: Telegram мусить спитати перед закриттям`).toBe(true)
}
async function expectReleased(page: Page, where: string) {
  await expect.poll(() => closing(page), `${where}: підтвердження лишилось після виходу з форми`).toBe(false)
}

test('оренда: форма питає, обʼєкт — ні', async ({ page }) => {
  await setup(page, null)
  await openDb(page)
  // Антивакуум: на списку підтвердження немає — інакше «питає» нічого не доводить.
  expect(await closing(page)).toBe(false)
  await page.locator('.obj-t', { hasText: 'Офіс 102' }).click()
  await page.getByRole('button', { name: 'Здати в оренду' }).click()
  await expect(page.getByLabel('Орендар')).toBeVisible()
  await expectAsks(page, 'Здати в оренду')
  await page.getByRole('button', { name: 'Назад' }).first().click()
  await expect(page.getByLabel('Орендар')).toHaveCount(0)
  await expectReleased(page, 'Здати в оренду')
})

test('розклад платежів', async ({ page }) => {
  await setup(page, null)
  await openDb(page)
  await page.getByLabel('Меню бази').click()
  await page.getByText('Календар платежів').click()
  await page.getByRole('button', { name: /Налаштувати/ }).first().click()
  await expect(page.getByLabel('День місяця')).toBeVisible()
  await expectAsks(page, 'Розклад платежів')
  await page.getByRole('button', { name: 'Назад' }).first().click()
  await expect(page.getByLabel('День місяця')).toHaveCount(0)
  await expectReleased(page, 'Розклад платежів')
})

test('запрошення: питає на формі, а на показі готового лінка — ні', async ({ page }) => {
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/db_members**', (r) =>
      r.request().method() === 'POST'
        ? jsonRoute(r, { invite_token: 'inv0011223344556677' })
        : jsonRoute(r, []))
  })
  await openDb(page)
  await page.getByRole('button', { name: 'Меню бази' }).click()
  await page.getByText('Команда', { exact: true }).click()
  await page.getByRole('button', { name: 'Запросити в команду' }).click()
  await expectAsks(page, 'Запрошення')
  await page.getByPlaceholder('напр. Менеджер Оля').fill('Менеджер Оля')
  await page.getByRole('button', { name: 'Створити' }).click()
  await expect(page.getByText('Запрошення створено!')).toBeVisible()
  // Лінк уже збережено на сервері — втрачати нічого, тож і питати нема про що.
  await expectReleased(page, 'Запрошення (готовий лінк)')
})

test('форма обʼєкта (наявний виклик, переведений на спільний хук)', async ({ page }) => {
  await setup(page, null)
  await openDb(page)
  await page.getByRole('button', { name: /Додати обʼєкт|Новий обʼєкт/ }).first().click()
  await expect(page.getByPlaceholder('Офіс 101')).toBeVisible()
  await expectAsks(page, 'Новий обʼєкт')
})
