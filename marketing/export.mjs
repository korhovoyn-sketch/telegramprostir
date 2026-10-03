/**
 * Експорт креативів у PNG, готові до публікації.
 *
 *   node marketing/export.mjs            # усі [data-export] → marketing/creatives/
 *   node marketing/export.mjs --preview  # + повносторінкове превʼю деку
 *
 * Знімає ЕЛЕМЕНТ, а не вʼюпорт, і робить це в режимі `?export=1`, де знято
 * масштаб показу: скріншот трансформованого елемента дав би розмитий кадр
 * замість піксель-у-піксель.
 */
import { chromium } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = resolve(HERE, 'creatives')
const PAGE = 'file://' + resolve(HERE, 'index.html')

// Пісочниця має ПОВНИЙ Chromium 1194, але не headless-shell, якого чекає
// поточна версія Playwright; `playwright install` тут заборонений.
const EXEC = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
const browser = await chromium.launch({ executablePath: EXEC })
const ctx = await browser.newContext({
  viewport: { width: 1400, height: 1000 },
  deviceScaleFactor: 1,
  reducedMotion: 'reduce',
})
const page = await ctx.newPage()
await mkdir(OUT, { recursive: true })

await page.goto(PAGE + '?export=1')
await page.waitForFunction(() => document.fonts.status === 'loaded')
// Кадри продукту — найважчі в деку; без цього частина плиток експортується
// з порожньою рамкою телефона.
await page.waitForFunction(() =>
  [...document.images].every((i) => i.complete && i.naturalWidth > 0), null, { timeout: 60_000 })
await page.waitForTimeout(600)

const ids = await page.$$eval('[data-export]', (els) =>
  els.map((e) => e.getAttribute('data-export')).filter((id) => !id.endsWith('-mini')))

let ok = 0
for (const id of ids) {
  const el = page.locator(`[data-export="${id}"]`).first()
  const box = await el.boundingBox()
  await el.screenshot({ path: `${OUT}/${id}.png` })
  console.log(`✓ ${id}  ${Math.round(box.width)}×${Math.round(box.height)}`)
  ok++
}

if (process.argv.includes('--preview')) {
  const p2 = await ctx.newPage()
  await p2.setViewportSize({ width: 1400, height: 1000 })
  await p2.goto(PAGE)
  await p2.waitForFunction(() => document.fonts.status === 'loaded')
  await p2.waitForFunction(() =>
    [...document.images].every((i) => i.complete && i.naturalWidth > 0), null, { timeout: 60_000 })
  await p2.waitForTimeout(800)
  await p2.screenshot({ path: `${OUT}/_deck-preview.png`, fullPage: true })
  console.log('✓ _deck-preview.png')
}

await browser.close()
console.log(`\n${ok} креативів у marketing/creatives/`)
