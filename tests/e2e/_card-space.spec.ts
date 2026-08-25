import { test, expect } from '@playwright/test'
import { OWNER_SCREENS, ownerFixtures } from './helpers/screens'

// Інструмент, не гард: друкує, скільки місця на картці обʼєкта займає рядок
// дій проти самого контенту. `PERF=1 npx playwright test _card-space`.
test('скільки місця їсть рядок дій картки', async ({ page }) => {
  await ownerFixtures(page)
  const step = OWNER_SCREENS.find((s) => s.label === 'db-objects')!
  await step.go(page)
  await page.locator('.obj-card').first().waitFor()

  const data = await page.evaluate(() => {
    const cards = Array.from(document.querySelectorAll('.obj-card'))
    return cards.slice(0, 4).map((c) => {
      const act = c.querySelector('.obj-act') as HTMLElement | null
      const btns = Array.from(c.querySelectorAll('.obj-act-btn')) as HTMLElement[]
      const cb = c.getBoundingClientRect()
      const ab = act?.getBoundingClientRect()
      return {
        name: (c.querySelector('.obj-t') as HTMLElement)?.innerText ?? '?',
        card: Math.round(cb.height),
        row: ab ? Math.round(ab.height) : 0,
        pct: ab ? Math.round((ab.height / cb.height) * 100) : 0,
        btns: btns.length,
        btnH: btns[0] ? Math.round(btns[0].getBoundingClientRect().height) : 0,
        widths: btns.map((b) => Math.round(b.getBoundingClientRect().width)),
      }
    })
  })
  for (const d of data) {
    console.log(`${d.name.padEnd(22)} картка ${String(d.card).padStart(4)}px | рядок ${String(d.row).padStart(3)}px (${d.pct}%) | кнопок ${d.btns} × ${d.btnH}px | ширини ${d.widths.join(', ')}`)
  }
  const vh = page.viewportSize()!.height
  console.log(`\nвиджет 375×${vh}; сумарно рядки дій зʼїдають ${data.reduce((a, d) => a + d.row, 0)}px по чотирьох картках`)
  expect(data.length).toBeGreaterThan(0)
})
