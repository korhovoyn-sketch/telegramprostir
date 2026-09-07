import { test, expect, type Page } from '@playwright/test'
import { ALL_GROUPS, ownerFixtures, realtorFixtures } from './helpers/screens'
import { enPage, FIXTURE_DATA } from './helpers/en'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс — у прогін не входить):
 *   PERF=1 npx playwright test _i18n-audit --workers=1
 *
 * Обходить УСІ екрани всіх чотирьох ролей в АНГЛІЙСЬКОМУ режимі і друкує
 * кожен кириличний текстовий вузол. Розділити «дані» і «неперекладений
 * інтерфейс» автоматично неможливо — фікстури теж українські, — тому звіт
 * читається ОЧИМА. Саме так знайшлись дефекти, яких не бачить жоден асерт.
 *
 * Шити відкриваються окремим проходом: у `screens.ts` вони не кроки, а
 * `modal-sweep` ганяється лише українською.
 */

const DATA = FIXTURE_DATA
const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

async function cyrillicNodes(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const root = document.querySelector('#app-root') ?? document.body
    const out: string[] = []
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const s = (n.textContent ?? '').trim()
      if (!s) continue
      const el = n.parentElement
      if (!el || !el.offsetParent) continue          // прихований вузол
      if (/[а-яА-ЯіїєґІЇЄҐ]/.test(s)) out.push(s)
    }
    // aria-label теж читає користувач — читалкою.
    for (const el of Array.from(root.querySelectorAll('[aria-label]'))) {
      const a = el.getAttribute('aria-label') ?? ''
      if (/[а-яА-ЯіїєґІЇЄҐ]/.test(a)) out.push(`[aria-label] ${a}`)
    }
    return out
  })
}

const suspicious = (list: string[]) =>
  [...new Set(list)].filter((s) => !DATA.some((d) => s.includes(d)))

test.describe('АУДИТ: кожен екран англійською', () => {
  for (const g of ALL_GROUPS) {
    for (const step of g.screens) {
      test(`${g.role} · ${step.label}`, async ({ page }) => {
        await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
        await g.fixtures(page)
        const ep = enPage(page)
        await step.go(ep)
        await page.waitForTimeout(500)
        const bad = suspicious(await cyrillicNodes(page))
        if (bad.length) console.log(`\n### ${g.role} · ${step.label}\n` + bad.map((s) => '   • ' + s).join('\n'))
        expect(true).toBe(true)
      })
    }
  }
})

/**
 * ШИТИ. Обхід екранів їх не відкриває, а `modal-sweep` ганяється лише
 * українською — тобто англійською їх не бачив НІХТО.
 *
 * Межа приладу, названа прямо: крок `collection-analytics` у
 * `helpers/screens.ts` асертить український заголовок через
 * `expect(locator).toHaveText(...)`, а це API `expect`, до якого проксі не
 * дотягується. Екран при цьому правильний — «Collection analytics» видно
 * прямо в тексті падіння.
 */
async function dumpSheet(page: Page, name: string) {
  await page.waitForTimeout(450)
  const inSheet = await page.evaluate(() => {
    const m = document.querySelector('.modal')
    if (!m) return null
    const out: string[] = []
    const w = document.createTreeWalker(m, NodeFilter.SHOW_TEXT)
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const s = (n.textContent ?? '').trim()
      if (s && /[а-яА-ЯіїєґІЇЄҐ]/.test(s)) out.push(s)
    }
    for (const el of Array.from(m.querySelectorAll('[aria-label]'))) {
      const a = el.getAttribute('aria-label') ?? ''
      if (/[а-яА-ЯіїєґІЇЄҐ]/.test(a)) out.push(`[aria-label] ${a}`)
    }
    return out
  })
  if (inSheet === null) { console.log(`\n### ШИТ ${name}: НЕ ВІДКРИВСЯ`); return }
  const bad = suspicious(inSheet)
  console.log(`\n### ШИТ ${name}` + (bad.length ? '\n' + bad.map((x) => '   • ' + x).join('\n') : '  ✓ чисто'))
}

test.describe('АУДИТ: шити англійською', () => {
  test('меню бази · дії обʼєкта · підтвердження · поширення', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
    await ownerFixtures(page)
    const ep = enPage(page)
    await ep.goto('/')
    await expect(ep.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await ep.getByText('БЦ Рубін').first().click()
    await expect(ep.getByText('Всі (3)').first()).toBeVisible({ timeout: 15_000 })

    await ep.getByLabel('Меню бази').click()
    await dumpSheet(page, 'меню бази')
    await page.keyboard.press('Escape')
    await page.waitForTimeout(400)

    // Мітка несе НАЗВУ обʼєкта («Дії з обʼєктом «Офіс 103»»), тож точного
    // збігу не буде — беремо кнопку за класом, він від мови не залежить.
    await page.locator('.obj-more, [aria-label^="Actions for"]').first().click()
    await dumpSheet(page, 'дії обʼєкта')
    await page.keyboard.press('Escape')
    await page.waitForTimeout(400)

    // ConfirmHost — фолбек підтвердження, спільний для 14 місць.
    await ep.getByLabel('Меню бази').click()
    await page.waitForTimeout(450)
    await ep.getByText('Видалити базу', { exact: true }).click()
    await dumpSheet(page, 'підтвердження (ConfirmHost)')
  })

  test('поширення бази', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
    await ownerFixtures(page)
    const ep = enPage(page)
    await ep.goto('/')
    await expect(ep.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
    await ep.getByText('БЦ Рубін').first().click()
    await expect(ep.getByText('Всі (3)').first()).toBeVisible({ timeout: 15_000 })
    await ep.getByLabel('Меню бази').click()
    await page.waitForTimeout(450)
    await ep.getByText('Аналітика і поширення', { exact: true }).click()
    await ep.getByRole('button', { name: 'Поділитися' }).click()
    await dumpSheet(page, 'ShareSheet')
  })

  test('рієлтор: додати обʼєкт у підбірку', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
    await realtorFixtures(page)
    // Базова фікстура рієлтора віддає ПОРОЖНІ підбірки — сідаємо свою, як це
    // робить крок аналітики. Роут реєструється ПІСЛЯ фікстур: Playwright бере
    // обробник, зареєстрований останнім.
    await page.route('**/rest/v1/collections**', (r) => r.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify([{
        id: 'c0000000-0000-0000-0000-000000000001', realtor_id: '00000000-0000-0000-0000-000000000001',
        name: 'Для клієнта А', is_draft: false, share_token: 'ff00112233445566778899aa',
        share_expires_at: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      }]),
    }))
    const ep = enPage(page)
    await ep.goto('/')
    await ep.locator('.tabbar [aria-label="Підбірки"]').click()
    await page.waitForTimeout(600)
    await ep.getByText('Для клієнта А').first().click()
    await page.waitForTimeout(600)
    await ep.getByLabel('Додати обʼєкт').click()
    await dumpSheet(page, 'додати обʼєкт у підбірку')
  })
})
