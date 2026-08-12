import { test } from '@playwright/test'

/**
 * Ізольований мікробенчмарк: чого САМЕ коштує `backdrop-filter: blur(48px)` під
 * анімацією transform. Потрібен, бо замір свайпу в `_anim-smoothness` забруднений
 * власним харнесом (кожен touchmove відправляється з rAF-колбека, тож у «час
 * кадру» входить робота самого тесту). Тут жодного harness-у: два однакові
 * елементи, різниця лише в наявності блюру.
 */
test('скільки коштує blur(48px) під анімацією', async ({ page }) => {
  test.setTimeout(120_000)
  await page.goto('about:blank')
  const run = async (withBlur: boolean) => page.evaluate(async (blur) => {
    document.body.innerHTML = ''
    document.body.style.cssText = 'margin:0;height:100vh;overflow:hidden;background:linear-gradient(#123,#611)'
    // Насичений фон під склом: блюр коштує рівно стільком, скільком коштує
    // перемалювати те, що під ним.
    for (let i = 0; i < 60; i++) {
      const d = document.createElement('div')
      d.textContent = 'Текст під склом ' + i
      d.style.cssText = `position:absolute;top:${i * 11}px;left:0;right:0;font:600 13px system-ui;color:#fff`
      document.body.appendChild(d)
    }
    const sheet = document.createElement('div')
    sheet.style.cssText =
      'position:fixed;left:0;right:0;bottom:0;height:60vh;border-radius:20px 20px 0 0;' +
      'background:rgba(14,11,32,.72);will-change:auto;' +
      (blur ? 'backdrop-filter:blur(48px) saturate(220%) brightness(1.1);' : '')
    document.body.appendChild(sheet)

    const frames: number[] = []
    await new Promise<void>((done) => {
      let last = performance.now()
      const t0 = last
      const tick = () => {
        const now = performance.now()
        frames.push(now - last)
        last = now
        const p = Math.min(1, (now - t0) / 1000)
        // Рух туди-назад, як у свайпі: transform міняється кожен кадр.
        sheet.style.transform = `translateY(${Math.sin(p * Math.PI * 2) * 120}px)`
        if (p < 1) requestAnimationFrame(tick)
        else done()
      }
      requestAnimationFrame(tick)
    })
    return frames.slice(2)
  }, withBlur)

  const stat = (f: number[]) => {
    const s = [...f].sort((a, b) => a - b)
    return { n: f.length, p50: s[Math.floor(s.length * .5)], p95: s[Math.floor(s.length * .95)],
             worst: s[s.length - 1], janky: f.filter((d) => d > 32).length }
  }
  // По три прогони кожного, поперемінно — щоб дрейф навантаження контейнера не
  // ліг цілком на один із варіантів.
  const withB: number[] = []; const without: number[] = []
  for (let i = 0; i < 3; i++) { withB.push(...await run(true)); without.push(...await run(false)) }
  console.log('З БЛЮРОМ   ', JSON.stringify(stat(withB)))
  console.log('БЕЗ БЛЮРУ  ', JSON.stringify(stat(without)))
})
