import { test } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { ALL_GROUPS } from './helpers/screens'

/**
 * ІНСТРУМЕНТ, не гард (`_`-префікс → у прогін не входить).
 *
 * Знімає всі досяжні екрани у вказану теку, щоб можна було порівняти ДВІ версії
 * коду В ОДНОМУ Й ТОМУ САМОМУ браузері. Це єдиний спосіб побачити з пісочниці,
 * що саме зробила зміна з кадрами: справжні бейслайни належать раннеру, а
 * `-diff.png` з його артефакту сюди не завантажується (редирект на blob-сховище
 * поза allowlist проксі — 403).
 *
 * Порівняння версій, а не бейслайнів, знімає головну ваду локального заміру:
 * різниця збірок Chromium (141 тут проти 148 на CI) в обидва знімки входить
 * ОДНАКОВО і в різниці зникає.
 *
 * Вживання:
 *   SHOTS_DIR=/tmp/before CI=1 npx playwright test _ab-shots
 *   (перемкнути гілку, перезібрати)
 *   SHOTS_DIR=/tmp/after  CI=1 npx playwright test _ab-shots
 *   python3 scripts/compare-shots.py /tmp/before /tmp/after
 */
const DIR = process.env.SHOTS_DIR
test.skip(!DIR, 'вкажи SHOTS_DIR')

for (const group of ALL_GROUPS) {
  test(`A/B кадри: ${group.role}`, async ({ page }) => {
    test.setTimeout(300_000)
    page.setDefaultTimeout(20_000)
    mkdirSync(DIR!, { recursive: true })
    await group.fixtures(page)
    for (const s of group.screens) {
      await s.go(page)
      // Той самий спокій, що й у бейслайнів: анімації входу мають осісти.
      await page.waitForTimeout(900)
      await page.screenshot({ path: `${DIR}/${s.label}.png` })
    }
  })
}
