import { test, expect } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'
test.skip(!process.env.PERF, 'PERF=1')
test('row geom', async ({ page }) => {
  test.setTimeout(300_000)
  const g = ALL_GROUPS.find(x => x.role === 'owner')!
  await g.fixtures(page)
  await g.screens.find(s => s.label === 'property-form-new')!.go(page)
  await page.waitForTimeout(600)
  console.log(JSON.stringify(await page.evaluate(() => {
    const b = [...document.querySelectorAll<HTMLElement>('.fr-seg-b')].find(e => e.textContent?.includes('Розрахунков'))!
    const seg = b.parentElement as HTMLElement
    const row = seg.parentElement as HTMLElement
    const lbl = row.querySelector('.fr-l') as HTMLElement
    const cs = getComputedStyle(b)
    const rg = document.createRange(); rg.selectNodeContents(b)
    return {
      rowW: Math.round(row.getBoundingClientRect().width),
      rowCS: { pl: getComputedStyle(row).paddingLeft, pr: getComputedStyle(row).paddingRight, gap: getComputedStyle(row).gap, jc: getComputedStyle(row).justifyContent },
      lblW: Math.round(lbl.getBoundingClientRect().width),
      segW: Math.round(seg.getBoundingClientRect().width),
      btnW: Math.round(b.getBoundingClientRect().width), btnClient: b.clientWidth,
      pad: cs.padding, fs: cs.fontSize,
      need: Math.round(rg.getBoundingClientRect().width),
    }
  }), null, 1))
  expect(true).toBe(true)
})
