import { test, expect, type Page } from '@playwright/test'
import { ownerFixtures, OWNER_SCREENS } from './helpers/screens'
import { PHOTO_PNG as PNG } from './helpers/harness'

/**
 * ФОТО ОБʼЄКТА: ЯК ВОНО ЗʼЯВЛЯЄТЬСЯ І ЩО ВИДНО, КОЛИ ЙОГО НЕМАЄ.
 *
 * Прогалина була СТРУКТУРНОЮ, а не поодинокою: харнес НЕ обслуговував URL фото
 * (`:9999/storage/v1/object/public/photos/…` не роутився нікуди), тож кроки
 * обходу «обʼєкт із фото» і «галерея» весь час міряли й знімали СТАН БИТОГО
 * ЗОБРАЖЕННЯ — і жоден гард цього не помічав, бо ні контраст, ні геометрія
 * не питають, чи в `<img>` є пікселі. Тепер `mockBackend` віддає справжній
 * знімок, а цей спек перекриває його повільною мережею й 404.
 *
 * Тут три питання, кожне про те, що бачить користувач на реальній мережі:
 *   1. ПОВІЛЬНА мережа: знімок не мусить зʼявлятись ривком поверх героя, а
 *      анімація появи — програвати на порожньому елементі (фейд при монтуванні
 *      добігав раніше, ніж приїжджали байти);
 *   2. БИТИЙ файл (рядок є, файлу немає — осиротілий шлях, збій сховища):
 *      не показувати гліф битої картинки з alt-текстом поверх скриму;
 *   3. доступна назва фото в галереї — мовою інтерфейсу.
 */

const PHOTO_URL = '**/storage/v1/object/public/photos/**'

async function openDetail(page: Page) {
  const step = OWNER_SCREENS.find((s) => s.label === 'property-detail-photo')!
  await step.go(page)
}

/** Чи видно в DOM ГЛІФ битої картинки: `<img>`, що завантажився без пікселів. */
async function brokenImages(page: Page, scope: string) {
  return page.evaluate((sel) => {
    const out: string[] = []
    document.querySelectorAll<HTMLImageElement>(`${sel} img`).forEach((img) => {
      const cs = getComputedStyle(img)
      const visible = cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity) > 0.05
      if (visible && img.complete && img.naturalWidth === 0) out.push(img.getAttribute('alt') || img.src.slice(-30))
    })
    return out
  }, scope)
}

test('повільна мережа: знімок героя проявляється ПІСЛЯ завантаження, а не ривком', async ({ page }) => {
  await ownerFixtures(page)
  let release: () => void = () => {}
  const held = new Promise<void>((r) => { release = r })
  let served = 0
  await page.route(PHOTO_URL, async (r) => {
    await held
    served++
    await r.fulfill({ status: 200, contentType: 'image/png', body: PNG })
  })
  await openDetail(page)
  const hero = page.locator('.obj-hero img').first()
  await expect(hero).toHaveCount(1)

  // Поки байти в дорозі — знімок невидимий, а місце героя тримає свій ґрунт.
  await page.waitForTimeout(400)
  const before = await hero.evaluate((el) => ({
    opacity: Number(getComputedStyle(el).opacity),
    complete: (el as HTMLImageElement).complete && (el as HTMLImageElement).naturalWidth > 0,
  }))
  expect(before.complete, 'антивакуум: фото мусило ще НЕ завантажитись').toBe(false)
  expect(before.opacity, 'незавантажене фото вже видиме — отже воно зʼявиться ривком').toBeLessThan(0.05)

  release()
  await expect.poll(() => served, { timeout: 5_000 }).toBeGreaterThan(0)
  // Після завантаження — проявляється, і саме ПЕРЕХОДОМ, а не стрибком.
  await expect.poll(() => hero.evaluate((el) => Number(getComputedStyle(el).opacity)), { timeout: 5_000 })
    .toBeGreaterThan(0.95)
  const tp = await hero.evaluate((el) => getComputedStyle(el).transitionProperty)
  expect(tp, 'поява фото без переходу — стрибок').toMatch(/opacity|all/)
})

test('битий файл: ні гліфа битої картинки, ні alt-тексту поверх героя, смужки й галереї', async ({ page }) => {
  await ownerFixtures(page)
  await page.route(PHOTO_URL, (r) => r.fulfill({ status: 404, body: 'not found' }))
  await openDetail(page)
  // Дати браузеру встигнути отримати 404 на всі три знімки.
  await page.waitForTimeout(600)

  expect(await brokenImages(page, '.obj-hero'), 'герой показує биту картинку').toEqual([])
  expect(await brokenImages(page, '.photos-strip'), 'смужка показує биті картинки').toEqual([])
  // Герой лишається героєм: той самий бокс, а не схлопнутий блок.
  const h = await page.locator('.obj-hero').evaluate((el) => el.getBoundingClientRect().height)
  expect(h).toBeGreaterThan(120)

  await page.locator('.obj-hero').click()
  await expect(page.getByRole('button', { name: 'Поділитись фото' })).toBeVisible({ timeout: 10_000 })
  await page.waitForTimeout(500)
  expect(await brokenImages(page, 'body'), 'галерея показує биту картинку').toEqual([])
  // Порожня чорна сцена без слова читається як «зависло» — мусить бути пояснення.
  await expect(page.getByText('Не вдалося завантажити фото')).toBeVisible()
})

test('галерея: доступна назва фото — мовою інтерфейсу, а не «Photo 1»', async ({ page }) => {
  await ownerFixtures(page)
  await page.route(PHOTO_URL, (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG }))
  await openDetail(page)
  await page.locator('.obj-hero').click()
  await expect(page.getByRole('button', { name: 'Поділитись фото' })).toBeVisible({ timeout: 10_000 })
  const alts = await page.locator('img').evaluateAll((els) => els.map((e) => e.getAttribute('alt') ?? ''))
  expect(alts.filter((a) => /^Photo\b/.test(a)), 'англійський alt в українському інтерфейсі').toEqual([])
  expect(alts.some((a) => /Фото 1 з 3/.test(a)), 'антивакуум: фото галереї мусить мати назву').toBe(true)
})
