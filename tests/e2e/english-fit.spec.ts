import { test, expect, type Page } from '@playwright/test'
import { setupApp, DEFAULT_USER } from './helpers/harness'
import { ALL_GROUPS, ownerFixtures, atDbObjects } from './helpers/screens'
import { enPage } from './helpers/en'

/**
 * ТЕКСТ АНГЛІЙСЬКОЮ: обрізання, вихід за край і слова, розірвані посеред.
 *
 * Усі інші гарди обрізання (`screen-text-fit`, `control-text-fit`, `devices`,
 * `modal-sweep`) ходять УКРАЇНСЬКОЮ — а англійський рядок має іншу довжину:
 * частіше коротший, але «Rentable area», «Service charges / mo» чи «Remind
 * me, days before» бувають ширші за український еквівалент, і вузький рядок
 * форми їх обрізає. Це інший текст у тих самих коробках, тож міряти його
 * потрібно окремо, а не вважати, що «якщо вміщується українське, то й це».
 *
 * Обхід той самий, що в решти гардів (`helpers/screens.ts`), через адаптер
 * `enPage`, який перекладає СЕЛЕКТОРИ тим самим словником, що й інтерфейс.
 *
 * Що міряється (усе по рендеру, жодного джерельного припущення):
 *   • заголовок хедера обрізано (`scrollWidth > clientWidth`);
 *   • плейсхолдер ширший за поле;
 *   • підпис контрола (сегмент, чіп, таб) і CTA ширші за свою коробку;
 *   • будь-який елемент із `overflow:hidden` і англійським текстом, що не
 *     влізає (ellipsis і мовчазне клiпання);
 *   • слово довше за свій контейнер — тоді `overflow-wrap:anywhere` рве його
 *     посеред («Rentab-le»), і це читається як помилка, а не як перенос;
 *   • горизонтальне переповнення сторінки.
 *
 * Український текст з даних фікстур (назви баз, імена орендарів) відсікається
 * за кирилицею: назва без пробілів законно обрізається, це не підпис.
 */

const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

/** Заморожений борг. Порожньо — і має лишатись порожнім. */
const FIT_DEBT: Record<string, string[]> = {}

const CONTROLS = [
  '.seg-b', '.fr-seg-b', '.view-seg-b', '.chip', '.notif-tab',
  '.sheet-row', '.acc-act', '.obj-act-btn', '.tmpl-l', '.fbar button',
].join(',')
const CTAS = '.mbtn, .fbtn, .modal-btn, .btn-glass'

async function probe(page: Page): Promise<string[]> {
  return page.evaluate(({ controls, ctas }) => {
    const cyr = /[а-яА-ЯіїєґІЇЄҐ]/
    const out: string[] = []
    const visible = (el: HTMLElement) => {
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) return false
      const cs = getComputedStyle(el)
      return cs.visibility !== 'hidden' && cs.display !== 'none'
    }
    const label = (el: Element) => (el.textContent ?? '').trim().replace(/\s+/g, ' ').slice(0, 40)

    // Заголовок хедера.
    const t = document.querySelector<HTMLElement>('.hdr-t')
    if (t && t.scrollWidth - t.clientWidth > 0) {
      const own = Array.from(t.childNodes).filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => (n.textContent ?? '').trim()).join('')
      if (!cyr.test(own)) out.push(`заголовок «${own}» обрізано на ${t.scrollWidth - t.clientWidth}px`)
    }

    // Плейсхолдери.
    document.querySelectorAll<HTMLInputElement>('input').forEach((i) => {
      const ph = i.getAttribute('placeholder') ?? ''
      if (!ph || cyr.test(ph) || i.type === 'hidden' || i.type === 'file' || !visible(i)) return
      const cs = getComputedStyle(i)
      const probeEl = document.createElement('span')
      probeEl.style.cssText = `position:absolute;visibility:hidden;white-space:pre;font:${cs.font}`
      probeEl.textContent = ph
      document.body.appendChild(probeEl)
      const need = probeEl.getBoundingClientRect().width
      probeEl.remove()
      const avail = i.clientWidth - parseFloat(cs.paddingLeft || '0') - parseFloat(cs.paddingRight || '0')
      if (need > avail + 1) out.push(`плейсхолдер «${ph}»: треба ${Math.round(need)}px, є ${Math.round(avail)}px`)
    })

    // Підписи контролів і CTA — через Range: `scrollWidth` брехливий там, де
    // немає ellipsis (текст не клiпається, а лізе за край).
    const fitRange = (sel: string, kind: string, skipHidden: boolean) => {
      document.querySelectorAll<HTMLElement>(sel).forEach((el) => {
        if (!visible(el)) return
        const cs = getComputedStyle(el)
        if (skipHidden && (el.classList.contains('fab-off') || cs.pointerEvents === 'none')) return
        if (cyr.test(el.textContent ?? '')) return
        const rect = el.getBoundingClientRect()
        // Схований FAB стоїть зі `scale`: Range віддає візуальні розміри, а
        // падінги лейаутні, тож масштаб знімаємо відношенням боксів.
        const scale = el.offsetWidth ? rect.width / el.offsetWidth : 1
        const range = document.createRange()
        range.selectNodeContents(el)
        const need = range.getBoundingClientRect().width / (scale || 1)
        if (need === 0) return
        const avail = el.clientWidth - parseFloat(cs.paddingLeft || '0') - parseFloat(cs.paddingRight || '0')
        if (need > avail + 1) out.push(`${kind} «${label(el)}» вилазить на ${Math.round(need - avail)}px`)
      })
    }
    fitRange(controls, 'контрол', false)
    fitRange(ctas, 'кнопка', true)

    // Будь-який елемент, що клiпає свій англійський текст.
    document.querySelectorAll<HTMLElement>('#app-root *, .modal *').forEach((el) => {
      if (!visible(el)) return
      const cs = getComputedStyle(el)
      const clips = cs.overflowX === 'hidden' || cs.overflowX === 'clip'
      if (!clips || el.scrollWidth - el.clientWidth <= 1) return
      const hasOwnText = Array.from(el.childNodes).some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? '').trim())
      if (!hasOwnText) return
      const txt = label(el)
      if (!txt || cyr.test(txt)) return
      out.push(`клiпає «${txt}» на ${el.scrollWidth - el.clientWidth}px (${el.className || el.tagName})`)
    })

    // Слово, розірване посеред: Range по САМОМУ слову дає більше одного рядка.
    // Міряти шрифтом «навпомацки» не можна — вийшли б хибні спрацювання на
    // великих літерах, інтервалах і вагах; Range питає в рушія, що він зробив.
    const seen = new Set<string>()
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const el = n.parentElement
      const text = n.textContent ?? ''
      if (!el || !text.trim() || cyr.test(text) || !visible(el)) continue
      if (!el.closest('#app-root, .modal')) continue
      const cs = getComputedStyle(el)
      if (cs.whiteSpace === 'pre' || cs.whiteSpace === 'pre-wrap') continue
      const re = /\S{6,}/g
      for (let m = re.exec(text); m; m = re.exec(text)) {
        const w = m[0]
        // Посилання рвуться посеред за задумом (`break-all` — єдиний спосіб
        // вмістити URL у вузьку коробку), це не помилка перекладу.
        if (seen.has(w) || /^https?:\/\//.test(w)) continue
        const range = document.createRange()
        range.setStart(n, m.index)
        range.setEnd(n, m.index + w.length)
        const tops = new Set(Array.from(range.getClientRects()).filter((r) => r.width > 0).map((r) => Math.round(r.top)))
        if (tops.size > 1) {
          seen.add(w)
          out.push(`слово «${w}» розірвано на ${tops.size} рядки (${el.className || el.tagName})`)
        }
      }
    }

    // Сторінка не мусить їхати вбік.
    const de = document.documentElement
    if (de.scrollWidth > de.clientWidth + 1) out.push(`сторінка ширша за вікно на ${de.scrollWidth - de.clientWidth}px`)

    return [...new Set(out)]
  }, { controls: CONTROLS, ctas: CTAS })
}

for (const group of ALL_GROUPS) {
  test(`англійський текст вміщується: ${group.role}`, async ({ page }) => {
    test.setTimeout(420_000)
    page.setDefaultTimeout(20_000)
    await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
    // Вхід віддає профіль акаунта, і мову визначає ВІН (див. «Мова СТАРТУ»):
    // онбординг із українським профілем у відповіді повернув би українську.
    if (group.role === 'onboarding') {
      await setupApp(page, { user: { ...DEFAULT_USER, role: null, language_code: 'en' } })
    } else {
      await group.fixtures(page)
    }
    const ep = enPage(page)

    const problems: string[] = []
    const visited: string[] = []
    for (const step of group.screens) {
      await step.go(ep)
      await page.waitForTimeout(400)
      visited.push(step.label)
      const allowed = FIT_DEBT[step.label] ?? []
      for (const p of await probe(page)) {
        if (!allowed.some((d) => p.includes(d))) problems.push(`${step.label}: ${p}`)
      }
    }

    expect(visited, `${group.role}: обхід не дійшов до всіх екранів`)
      .toEqual(group.screens.map((s) => s.label))
    expect(problems, 'англійський текст не вміщується — скороти переклад, не коробку').toEqual([])
  })
}

test('англійські шити й підтвердження вміщуються', async ({ page }) => {
  // Шити в обхід екранів не входять (це не кроки `screens.ts`), а їхні підписи
  // кнопок — найвужчі місця застосунку: половинна кнопка при 375px ≈ 167px.
  test.setTimeout(240_000)
  page.setDefaultTimeout(20_000)
  await page.addInitScript(() => localStorage.setItem('ps_lang', 'en'))
  await ownerFixtures(page)
  const ep = enPage(page)
  const problems: string[] = []
  const seenSheets: string[] = []
  const check = async (name: string) => {
    await expect(page.locator('.modal').last()).toBeVisible()
    await page.waitForTimeout(450)
    seenSheets.push(name)
    for (const p of await probe(page)) problems.push(`${name}: ${p}`)
  }
  const closeSheet = async () => {
    await page.keyboard.press('Escape')
    await expect(page.locator('.modal:not(.closing)')).toHaveCount(0, { timeout: 5_000 })
  }

  await atDbObjects(ep)
  await ep.getByLabel('Меню бази').click()
  await check('меню бази')

  // Видалення бази — підтвердження поверх меню (нативний попап у харнесі вимкнено,
  // тож це DOM-фолбек із тими самими підписами).
  await ep.getByText('Видалити базу', { exact: true }).click()
  await check('підтвердження видалення бази')
  await closeSheet()
  await closeSheet()

  await atDbObjects(ep)
  await ep.getByLabel('Меню бази').click()
  await page.waitForTimeout(450)
  await ep.getByText('Аналітика і поширення', { exact: true }).click()
  await expect(ep.getByText(/Аналітика|Поділитись/).first()).toBeVisible({ timeout: 15_000 })
  await ep.getByRole('button', { name: /Поділитись|Поділитися/ }).first().click()
  await check('шит поширення')
  await closeSheet()

  await page.goto('/')
  await expect(ep.getByText('Мої бази')).toBeVisible({ timeout: 20_000 })
  await ep.locator('.tabbar [aria-label="Профіль"]').click()
  await expect(ep.getByText('Налаштування')).toBeVisible({ timeout: 15_000 })
  await ep.getByText('Вийти з акаунту', { exact: true }).click()
  await check('вихід з акаунту')

  expect(seenSheets.length, 'не всі шити відкрились').toBe(4)
  expect(problems, 'англійський підпис у шиті не вміщується').toEqual([])
})

test('антивакуум: проба справді бачить обрізання', async ({ page }) => {
  await page.goto('about:blank')
  await page.setContent(`
    <div id="app-root">
      <div class="seg-b" style="width:40px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 4px">Rentable area</div>
      <div style="width:30px;font:14px sans-serif;overflow-wrap:anywhere">Superlongwordhere</div>
    </div>`)
  const found = await probe(page)
  expect(found.some((p) => p.includes('контрол «Rentable area»')), found.join(' | ')).toBe(true)
  expect(found.some((p) => p.includes('слово «Superlongwordhere»')), found.join(' | ')).toBe(true)
  expect(found.some((p) => p.includes('клiпає «Rentable area»')), found.join(' | ')).toBe(true)
  expect(CYR.test('Rentable')).toBe(false)
})
