import { test, expect } from '@playwright/test'
import { jsonRoute } from './helpers/harness'
import { setup, openDb, OCCUPIED, FREE } from './helpers/ownerFixtures'

/**
 * «ЗА ОРЕНДОЮ» ПОРІВНЮЄ МІСЯЧНІ СУМИ, А НЕ СИРІ СТАВКИ.
 *
 * Сортування брало `calcRent`, а той для `per_day` віддає ДОБОВУ ставку — тобто
 * місце за $80/добу ($2 400/міс) стояло НИЖЧЕ за офіс на $2 160/міс, бо 80 < 2160.
 * Той самий клас, що вже коштував раунду в експорті: сира ставка різних одиниць
 * у порівнянні, яке читається як грошове.
 */
test('добова ставка сортується за місячним еквівалентом', async ({ page }) => {
  // OCCUPIED: 18 $/м² × 120 м² (база «розрахункова») = 2 160 на місяць.
  const daily = { ...FREE, name: 'Місце 7', rent_type: 'per_day', rent_rate: 80 }
  await setup(page, null, async (p) => {
    await p.route('**/rest/v1/properties**', (r) => {
      const wantsObject = (r.request().headers()['accept'] ?? '').includes('object')
      return jsonRoute(r, wantsObject ? OCCUPIED : [OCCUPIED, daily])
    })
  })
  await openDb(page)
  await page.getByText('За орендою').click()
  await expect(page.locator('.obj-t').first()).toHaveText('Місце 7')
  // Антивакуум: без сортування першим стоїть OCCUPIED (sort_order 100 < 200),
  // тобто зелений результат вище — заслуга сортування, а не порядку фікстури.
  await page.getByText('За порядком').click()
  await expect(page.locator('.obj-t').first()).toHaveText(OCCUPIED.name)
})
