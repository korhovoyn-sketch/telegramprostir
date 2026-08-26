import { test, expect, type Page } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'

/**
 * ПІДПИС КОНТРОЛА, ЩО НЕ ВМІЩАЄТЬСЯ В САМ КОНТРОЛ.
 *
 * Прогалина, знайдена наскрізним аудитом: обрізання підписів перевіряли ТРИ
 * гарди, і жоден не дивився на сегменти й чіпи —
 *
 *   `screen-text-fit`  лише заголовок хедера й плейсхолдери полів;
 *   `devices`          лише CTA-пігулки (`.mbtn`/`.fbtn`);
 *   `modal-sweep`      лише `.modal-btn` усередині шитів.
 *
 * Через це «Розрахункової» у формі обʼєкта обрізалось на 9px і показувало
 * «Розрахунково…» — саме там, де користувач обирає, ЩО множиться на ставку
 * $/м². Тобто найдорожчий за наслідками вибір форми був підписаний недочитано.
 *
 * ЧОМУ ВИМІР ЧЕРЕЗ `Range`, А НЕ `scrollWidth`. Тут потрібні ОБИДВА випадки, і
 * вони різні: `.fr-seg-b` має `overflow:hidden`+`ellipsis`, тож текст
 * КЛІПАЄТЬСЯ і `scrollWidth === clientWidth` — обрізання невидиме; а `.chip`
 * ellipsis-а не має, тож текст просто ЛІЗЕ за край. `Range` по вмісту ловить
 * обидва однаково.
 */

const SELECTOR = [
  '.seg-b', '.fr-seg-b', '.view-seg-b', '.chip', '.notif-tab',
  '.sheet-row', '.acc-act', '.obj-act-btn', '.tmpl-l', '.fbar button',
].join(',')

/**
 * Заморожений борг. Порожньо — і має лишатись порожнім: знайдений дефект
 * ВИПРАВЛЕНО, а не заморожено. Запис сюди потребує причини, чому підпис
 * скоротити нікуди.
 */
const FIT_DEBT: Record<string, string[]> = {}

async function clipped(page: Page): Promise<string[]> {
  return page.evaluate((sel) => {
    const out: string[] = []
    document.querySelectorAll<HTMLElement>(sel).forEach((el) => {
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return
      const cs = getComputedStyle(el)
      if (cs.visibility === 'hidden') return
      const range = document.createRange()
      range.selectNodeContents(el)
      const need = range.getBoundingClientRect().width
      if (need === 0) return
      const avail = el.clientWidth - parseFloat(cs.paddingLeft || '0') - parseFloat(cs.paddingRight || '0')
      // 1px — шум антиаліасингу, не запас.
      if (need > avail + 1) {
        const t = (el.textContent ?? '').trim().replace(/\s+/g, ' ').slice(0, 30)
        out.push(`«${t}» обрізано на ${Math.round(need - avail)}px`)
      }
    })
    return [...new Set(out)]
  }, SELECTOR)
}

for (const group of ALL_GROUPS) {
  test(`підпис контрола вміщається — ${group.role}`, async ({ page }) => {
    test.setTimeout(300_000)
    page.setDefaultTimeout(20_000)
    await group.fixtures(page)
    const visited: string[] = []
    for (const s of group.screens) {
      await s.go(page)
      visited.push(s.label)
      const bad = (await clipped(page)).filter((b) => !(FIT_DEBT[s.label] ?? []).some((d) => b.includes(d)))
      expect(bad, `${s.label}: підпис не вміщається у свій контрол`).toEqual([])
    }
    // Антивакуум: маршрут не обірвався на першому ж кроці.
    expect(visited.length, 'обхід не дійшов до всіх екранів').toBe(group.screens.length)
  })
}
