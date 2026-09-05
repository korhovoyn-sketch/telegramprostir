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
 * ЧАС ЗАМОРОЖЕНИЙ, і без цього інструмент бреше. Дві теки знімаються з
 * інтервалом у десятки хвилин, тож будь-який текст, похідний від годинника,
 * відрізняється САМ ПО СОБІ. Наступано: прогін «до» о 11:0x і «після» о 12:0x
 * дав різницю на ТРЬОХ екранах (db-list, guest-home, realtor-dashboard) в
 * однаковій зоні заголовка — це `greeting()` перемкнувся з «Доброго ранку» на
 * «Добрий день» (`hour < 12` в utils). Виглядало як регресія від зміни, якої я
 * не робив. Значення те саме, що в бейслайнах (`screenshots.spec.ts`), щоб
 * кадри двох інструментів були зіставні.
 *
 * ШИРИНА ЗАДАЄТЬСЯ, бо десктоп інакше не оглянути. Проєкт один (`iphone-se`,
 * 375×667), а десктопний блок починається з 680px — тобто без `SHOT_W`
 * інструмент фізично не міг показати те, заради чого його кличуть при
 * десктопній роботі. Раніше під це завівся другий, майже такий самий спек;
 * друга копія розійшлася б за два раунди (той самий урок, що вже оплачений
 * `helpers/devices.ts`), тож ширина — параметр, а не новий файл.
 *
 * Вживання:
 *   SHOTS_DIR=/tmp/before CI=1 npx playwright test _ab-shots
 *   (перемкнути гілку, перезібрати)
 *   SHOTS_DIR=/tmp/after  CI=1 npx playwright test _ab-shots
 *   python3 scripts/compare-shots.py /tmp/before /tmp/after
 *
 *   SHOT_W=1440 SHOT_H=900 SHOTS_DIR=/tmp/wide CI=1 npx playwright test _ab-shots
 */
const FROZEN = new Date('2025-09-15T09:00:00.000Z')
const DIR = process.env.SHOTS_DIR
const W = Number(process.env.SHOT_W ?? 0)
const H = Number(process.env.SHOT_H ?? 0)
test.skip(!DIR, 'вкажи SHOTS_DIR')

for (const group of ALL_GROUPS) {
  test(`A/B кадри: ${group.role}`, async ({ page }) => {
    test.setTimeout(300_000)
    page.setDefaultTimeout(20_000)
    mkdirSync(DIR!, { recursive: true })
    if (W && H) await page.setViewportSize({ width: W, height: H })
    await page.clock.setFixedTime(FROZEN)
    await group.fixtures(page)
    for (const s of group.screens) {
      await s.go(page)
      // Той самий спокій, що й у бейслайнів: анімації входу мають осісти.
      await page.waitForTimeout(900)
      await page.screenshot({ path: `${DIR}/${s.label}.png` })
    }
  })
}
