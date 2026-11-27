import { test, expect } from '@playwright/test'
import { guestFixtures, ownerFixtures } from './helpers/screens'
import { atDbObjects } from './helpers/screens'

/**
 * Гість не бачить розділу документів (078).
 *
 * Політики сховища гостьової гілки не мають, тож раніше розділ малювався —
 * з назвами файлів, які віддавали рядки таблиці, — а кожен тап по файлу давав
 * «Не вдалося відкрити файл». Тобто вміст недоступний, а назви витікали.
 *
 * Антивакуум: той самий екран у власника розділ МАЄ — інакше «у гостя немає»
 * проходило б і на екрані, де розділу не буває нікому.
 */
test('гість не бачить розділу «Файли» на картці обʼєкта', async ({ page }) => {
  await guestFixtures(page)
  await page.goto('/')
  await expect(page.getByText('Мої обʼєкти')).toBeVisible({ timeout: 20_000 })
  await page.getByText('Офіс 101').first().click()
  await expect(page.getByText('Корисна площа')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Файли', { exact: true })).toHaveCount(0)
  await expect(page.getByText('Файли ще не додані')).toHaveCount(0)
})

test('власник розділ «Файли» бачить (антивакуум)', async ({ page }) => {
  await ownerFixtures(page)
  await atDbObjects(page)
  await page.locator('.obj-card').first().locator('.obj-t').click()
  await expect(page.getByText('Корисна площа')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Файли', { exact: true }).first()).toBeVisible()
})
