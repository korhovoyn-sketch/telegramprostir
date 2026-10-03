/* Антивакуум НА ВИХОДІ: чи в зібраному файлі кожне зображення справді
   намалювалось. Перевірка джерела («підрядка shots/ немає») доводить лише те,
   що шляхи замінені — не те, що заміна валідна. */
import { chromium } from '@playwright/test'
const EXEC = '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
const FILE = process.argv[2]
const b = await chromium.launch({ executablePath: EXEC })
const p = await (await b.newContext({ viewport: { width: 1440, height: 1000 } })).newPage()
const errs = []
p.on('pageerror', (e) => errs.push('JS: ' + e.message))
p.on('requestfailed', (r) => errs.push('запит впав: ' + r.url().slice(0, 80)))
await p.goto('file://' + FILE, { waitUntil: 'load' })
await p.waitForTimeout(2500)
const r = await p.evaluate(() => {
  const imgs = [...document.images]
  return {
    total: imgs.length,
    broken: imgs.filter((i) => !i.complete || i.naturalWidth === 0)
      .map((i) => (i.alt || '?') + ' ← ' + i.src.slice(0, 60)),
    ext: imgs.filter((i) => !i.src.startsWith('data:')).map((i) => i.src.slice(0, 80)),
    video: [...document.querySelectorAll('video source,video')]
      .map((v) => (v.src || '').slice(0, 30)),
    fonts: document.fonts.status,
    sections: document.querySelectorAll('section').length,
  }
})
console.log(JSON.stringify(r, null, 1))
if (errs.length) console.log('ПОМИЛКИ:', errs.slice(0, 10))
await b.close()
if (r.broken.length || r.ext.length || errs.length) process.exit(3)
console.log(`✓ ${r.total} зображень, усі намальовані; зовнішніх запитів нема`)
