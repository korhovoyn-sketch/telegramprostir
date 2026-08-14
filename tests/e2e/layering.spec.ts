import { test, expect } from '@playwright/test'
import { setupApp, DEFAULT_USER, jsonRoute, skipCoachmarks } from './helpers/harness'

// Шкала шарів у РАНТАЙМІ.
//
// Джерельний гард (`design-tokens.test.ts`) читає текст: він доводить, що сирих
// чисел не лишилось і що шкала оголошена зростаючою. Чого він не бачить —
// одруківки в НАЗВІ: `var(--z-tabbr)` виглядає як звичайний токен, але
// властивість стає невалідною, тобто `z-index:auto`, і елемент тихо провалюється
// на свій рівень у потоці. Це перевіряється лише резолвом у браузері.
//
// ── Чого тут свідомо НЕМА, і чому ────────────────────────────────────────────
// Спершу тут стояв другий тест: панель обраних (`.batchbar`, z-index був 100) не
// має малюватись поверх шита (`.modal-overlay`, 50), відкритого з неї ж самої.
// Числа читаються як очевидний дефект. Гіпотезу СПРОСТОВАНО фальсифікацією:
// тест проходив і зі старим числом, і навіть коли я примусово підняв панель до
// `position:fixed; z-index:100`, і коли переніс портал шита в `#app-root`.
// Причина — `#app-root` має `position:fixed`, а фіксований елемент у Chromium
// СТВОРЮЄ контекст накладання. Тобто будь-який z-index усередині оболонки
// структурно не здатен накрити портал у `<body>`: 100 діє лише серед своїх.
//
// Тому такий тест не можна зламати нічим, крім двох одночасних вигаданих змін —
// а гард, який не падає на зламаному коді, гірший за відсутній: він читається як
// покриття. Архітектурний інваріант лишився коментарем, у CI поїхало те, що
// справді може зламатись.

const USER = { ...DEFAULT_USER, role: 'owner' as const }
const DB_ID = '10000000-0000-0000-0000-000000000001'
const NOW = '2026-01-15T10:00:00.000Z'

const DB = {
  id: DB_ID, owner_id: USER.id, name: 'БЦ Рубін', address: 'вул. Хрещатик, 1',
  type: 'business_center', color: 'pink', share_token: 'aabbccddeeff001122334455',
  share_expires_at: null, created_at: NOW, updated_at: NOW, properties: [],
}

test('шкала шарів резолвиться в рантаймі, а не лише в тексті', async ({ page }) => {
  await setupApp(page, { user: USER })
  await skipCoachmarks(page)
  await page.route('**/rest/v1/databases**', (r) => jsonRoute(r, [DB]))
  for (const t of ['properties', 'property_folders', 'db_members', 'notifications']) {
    await page.route(`**/rest/v1/${t}**`, (r) => jsonRoute(r, []))
  }

  await page.goto('/')
  await expect(page.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })

  const scale = await page.evaluate(() => {
    const cs = getComputedStyle(document.documentElement)
    const names = ['--z-under', '--z-base', '--z-raised', '--z-content', '--z-above',
                   '--z-header', '--z-tabbar', '--z-scrim', '--z-float', '--z-batchbar',
                   '--z-confetti', '--z-overlay', '--z-viewer', '--z-toast', '--z-banner',
                   '--z-coach']
    return names.map((n) => [n, Number(cs.getPropertyValue(n).trim())] as const)
  })
  const missing = scale.filter(([, v]) => !Number.isFinite(v)).map(([n]) => n)
  expect(missing, 'токен шару не оголошений — усе, що ним користується, впаде в z-index:auto').toEqual([])
  const values = scale.map(([, v]) => v)
  expect(values, 'шкала мусить зростати').toEqual([...values].sort((a, b) => a - b))

  // Реальні елементи мусять РЕЗОЛВИТИ свій шар, а не отримати `auto` через
  // одруківку. Порівнюємо лише те, що справді лежить в одному контексті
  // накладання — усередині `#app-root` (див. коментар угорі про те, чому
  // зіставляти таббар із `--z-overlay` було б хибним читанням).
  const layers = await page.evaluate(() =>
    ['.tabbar', '.fbtn', '.hdr', '.body'].map((s) => {
      const el = document.querySelector(s)
      return [s, el ? getComputedStyle(el).zIndex : 'absent'] as const
    }))
  const auto = layers.filter(([, z]) => z === 'auto' || z === 'absent')
  expect(auto, 'елемент хрому лишився без шару').toEqual([])

  const byName = Object.fromEntries(layers.map(([s, z]) => [s, Number(z)]))
  expect(byName['.fbtn'], 'плаваюча CTA над таббаром').toBeGreaterThan(byName['.tabbar'])
  expect(byName['.hdr'], 'хедер над тілом екрана').toBeGreaterThan(byName['.body'])
})
