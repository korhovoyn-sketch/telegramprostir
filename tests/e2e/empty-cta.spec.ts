import { test, expect, type Page, type Route } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

/**
 * ПОРОЖНІЙ СТАН НЕ ДУБЛЮЄ ПЕРВИННУ ДІЮ.
 *
 * `CollectionsScreen` малював у порожньому стані `.mbtn` «Створити підбірку» і
 * ЗАРАЗ ЖЕ плаваючу `.fbtn` із ТИМ САМИМ підписом — дві однакові кнопки на
 * екрані, де прокручувати нема чого, тобто плаваюча не додає нічого, крім
 * сумніву «а це та сама дія?». На `db-list` те саме.
 *
 * ВИМОГА — РІВНО ОДНА дія, а не «немає однакових підписів». Слабше правило на
 * `db-list` проходило б і зі зламаним кодом: там підписи й так різні
 * («Створити першу базу» проти «Створити базу»), тобто гард був би зелений на
 * тому самому дефекті.
 */

const OWNER = { ...DEFAULT_USER, role: 'owner' as const, first_name: 'Микола' }
const REALTOR = { ...DEFAULT_USER, role: 'realtor' as const, first_name: 'Олена' }

async function emptyBackend(page: Page, user: typeof OWNER | typeof REALTOR) {
  await setupApp(page, { user })
  await skipCoachmarks(page)
  for (const t of ['databases', 'properties', 'collections', 'realtor_subscriptions',
                   'db_members', 'notifications', 'property_photos', 'property_views']) {
    await page.route(`**/rest/v1/${t}**`, (r: Route) => jsonRoute(r, []))
  }
}

/**
 * Підписи первинних дій, які РЕАЛЬНО на екрані.
 *
 * `opacity`/`pointer-events` перевіряються не заради повноти: FAB ховається
 * класом `fab-off`, тобто лишається в DOM із ненульовою висотою й
 * `visibility:visible` — перша версія зонда через це рахувала схований FAB як
 * видимий і завалила власний же фікс.
 */
async function ctaLabels(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>('.mbtn, .fbtn')]
      .filter((b) => {
        const cs = getComputedStyle(b)
        return b.getBoundingClientRect().height > 0 && cs.visibility !== 'hidden'
          && Number(cs.opacity) > 0.01 && cs.pointerEvents !== 'none'
      })
      .map((b) => (b.textContent ?? '').trim().replace(/^\+\s*/, '').toLowerCase()))
}

test('порожні бази: рівно одна первинна дія', async ({ page }) => {
  await emptyBackend(page, OWNER)
  await page.goto('/')
  await expect(page.getByText('Немає баз')).toBeVisible({ timeout: 20_000 })
  await page.waitForTimeout(600)

  const labels = await ctaLabels(page)
  expect(labels, `на порожньому екрані має бути РІВНО одна первинна дія: ${labels.join(' | ')}`)
    .toHaveLength(1)
})

test('порожні підбірки: рівно одна первинна дія', async ({ page }) => {
  await emptyBackend(page, REALTOR)
  await page.goto('/')
  await expect(page.getByText('Робочі бази')).toBeVisible({ timeout: 20_000 })
  await page.locator('.tabbar [aria-label="Підбірки"]').click()
  await expect(page.getByText('Немає підбірок')).toBeVisible({ timeout: 15_000 })
  await page.waitForTimeout(600)

  const labels = await ctaLabels(page)
  expect(labels, `на порожньому екрані має бути РІВНО одна первинна дія: ${labels.join(' | ')}`)
    .toHaveLength(1)
})
