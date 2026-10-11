/* Замір розкладки замість очного огляду кожної секції: переповнення
   по горизонталі на чотирьох ширинах + жодного битого зображення.
   Секції все одно дивляться оком — це відсіює грубі поломки дешево. */
import { chromium } from '@playwright/test'
const b = await chromium.launch({ executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome' })
let bad = 0
for (const w of [1920, 1440, 1024, 760, 420]) {
  const p = await (await b.newContext({ viewport:{ width:w, height:900 } })).newPage()
  const errs=[]; p.on('pageerror',e=>errs.push(e.message))
  await p.goto('file://' + process.cwd() + '/index.html')
  await p.waitForFunction(()=>document.fonts.status==='loaded')
  await p.waitForTimeout(900)
  const r = await p.evaluate(() => {
    const over = []
    document.querySelectorAll('section,footer,.wrap,table,.strip,.ex-wrap,.ig').forEach(e=>{
      if (e.scrollWidth > e.clientWidth + 1)
        over.push(`${e.id || e.tagName}.${(e.className||'').split(' ')[0]} ${e.scrollWidth}>${e.clientWidth}`)
    })
    return { doc: document.documentElement.scrollWidth, win: innerWidth, over,
      broken: [...document.images].filter(i=>!i.complete||!i.naturalWidth).length }
  })
  const ok = r.doc <= r.win + 1 && !r.over.length && !r.broken && !errs.length
  if (!ok) bad++
  console.log(`${ok?'✓':'✗'} ${w}px  doc=${r.doc} broken=${r.broken}` +
    (r.over.length ? `\n    переповнення: ${r.over.slice(0,6).join(' | ')}` : '') +
    (errs.length ? `\n    JS: ${errs[0]}` : ''))
  await p.close()
}
await b.close()
process.exit(bad ? 3 : 0)
