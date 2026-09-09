import { test, type Browser } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'
import { IPAD } from './helpers/devices'

/** ІНСТРУМЕНТ (у прогін не входить): кадри на планшетних геометріях. */
const SHOTS = process.env.SHOTS_DIR || '/tmp/tablet'
const GEOM = [
  { n: 'ipad-mini-portrait', w: 744, h: 1133 },
  { n: 'ipad-mini-land', w: 1133, h: 744 },
  { n: 'ipad-air-portrait', w: 820, h: 1180 },
  { n: 'ipad-pro-land', w: 1194, h: 834 },
]

for (const g of GEOM) {
  test(`кадри ${g.n}`, async ({ browser }: { browser: Browser }) => {
    const ctx = await browser.newContext({
      viewport: { width: g.w, height: g.h },
      deviceScaleFactor: 1, isMobile: true, hasTouch: true, userAgent: IPAD,
    })
    const page = await ctx.newPage()
    await page.clock.setFixedTime(new Date('2026-02-10T12:00:00Z'))
    const owner = ALL_GROUPS.find((x) => x.role === 'owner')!
    await owner.fixtures(page, 'ios')
    for (const step of owner.screens.slice(0, 6)) {
      try {
        await step.go(page)
        await page.waitForTimeout(500)
        await page.screenshot({ path: `${SHOTS}/${g.n}--${step.label}.png` })
      } catch { /* крок міг не доїхати — кадр просто не зніметься */ }
    }
    await ctx.close()
  })
}
