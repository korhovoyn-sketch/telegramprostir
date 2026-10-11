/**
 * Сторіборд рілза — кадри з ТОГО САМОГО reel.html у ключові моменти таймлайну.
 *
 *   node marketing/render-board.mjs
 *
 * Сенс саме в спільному джерелі: намальований окремо сторіборд розходиться з
 * відео на першій же правці сценарію, і команда знімає не те, що затверджувала.
 */
import { chromium } from '@playwright/test'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const PAGE = 'file://' + resolve(HERE, 'reel.html')
const EXEC = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'

// Секунди мусять збігатися з підписами в секції 09 index.html
const MARKS = [0.8, 2.2, 4.8, 8.4, 13.4]

const browser = await chromium.launch({ executablePath: EXEC })
const page = await (await browser.newContext({
  viewport: { width: 1080, height: 1920 }, deviceScaleFactor: 1,
})).newPage()

await page.goto(PAGE)
await page.waitForFunction(() => document.fonts.status === 'loaded')
await page.waitForFunction(() =>
  [...document.images].every((i) => i.complete && i.naturalWidth > 0), null, { timeout: 30_000 })

for (const [i, sec] of MARKS.entries()) {
  await page.evaluate((ms) => {
    for (const a of document.getAnimations()) { a.pause(); a.currentTime = ms }
  }, sec * 1000)
  await page.screenshot({
    path: resolve(HERE, 'creatives', `board-${i + 1}.jpg`), type: 'jpeg', quality: 88,
  })
  console.log(`✓ board-${i + 1}.jpg  ${sec}s`)
}

await browser.close()
