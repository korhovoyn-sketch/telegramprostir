import { test, expect, type Browser, type Page } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'
import { smallTargets, TAP_DEBT } from './helpers/contrast'

/**
 * ОБХІД УСІХ ЕКРАНІВ НА ПʼЯТИ ГЕОМЕТРІЯХ ПРИСТРОЇВ.
 *
 * Увесь інший набір ганяється на ОДНІЙ геометрії — iPhone SE (375×667), і це
 * не примха: вона найвужча серед поширених iOS, тож «влізло тут — влізе
 * всюди» здається безпечним припущенням. Воно хибне у двох напрямках:
 *
 *  • **вужче за 375 буває.** Galaxy S8/S10e і ціла родина бюджетних Android —
 *    це 360 CSS-пікселів. Пʼятнадцять пікселів різниці — рівно та смуга, на
 *    якій ламаються підписи кнопок і рядки з іконкою+числом;
 *  • **ширше теж ламає.** Планшет розтягує мобільний лейаут: смуги, розраховані
 *    на «в екран», на 744px поводяться інакше, а горизонтальні скролери
 *    перестають скролитись і починають рвати сторінку.
 *
 * ЩО САМЕ ТУТ МІРЯЄТЬСЯ, і чому це три різні речі:
 *  1. горизонтальне переповнення — симптом читається ПРЯМО (`scrollWidth`
 *     контейнера більший за `clientWidth`), тож гард не залежить від того, який
 *     саме елемент виліз;
 *  2. підпис первинної дії не вилазить за свою кнопку — `scrollWidth` тут
 *     БРЕХЛИВИЙ, бо в `.mbtn`/`.fbtn` немає ellipsis: текст не клiпається, а
 *     просто лізе за край. Міряти треба `Range` по вмісту (той самий прийом, що
 *     в `modal-sweep`, де на 375px спалились шість підписів);
 *  3. зона дотику 44px — база заморожена СПІЛЬНИМ `TAP_DEBT` із гардом
 *     контрасту. Спільним навмисно: власна копія списку розійшлась би з ним за
 *     два раунди, і «нових порушень немає» перестало б щось означати.
 *
 * ЧОГО ЦЕЙ ГАРД НЕ ДОВОДИТЬ. Що застосунок працює на iOS. Тут Chromium
 * емулює ГЕОМЕТРІЮ і тач — не рушій: `backdrop-filter`, каретка під склом і
 * поведінка клавіатури в WebKit лишаються поза досяжністю (у пісочниці
 * `playwright install` заборонений, тож WebKit узяти нізвідки). Все, що
 * доводиться, — верстка тримається на цих ширинах.
 */

interface Device {
  name: string
  width: number
  height: number
  dsf: number
  /** iOS чи Android — впливає лише на UA, який читає код фолбеків. */
  ua: string
}

const IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
const ANDROID = 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
const IPAD = 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'

/**
 * 375×667 свідомо ВІДСУТНІЙ: це проєкт `iphone-se` з конфігу, тобто його
 * проходять усі решта 277 тестів. Дублювати його тут означало б платити за
 * найдовший обхід двічі й нічого нового не дізнатись.
 */
const DEVICES: Device[] = [
  // Найвужче, що реально трапляється. Саме тут ламаються підписи.
  { name: 'Galaxy S8 (360)', width: 360, height: 740, dsf: 3, ua: ANDROID },
  { name: 'iPhone 13/14 (390)', width: 390, height: 844, dsf: 3, ua: IOS },
  { name: 'Pixel 7 (412)', width: 412, height: 915, dsf: 2.6, ua: ANDROID },
  { name: 'iPhone 15 Pro Max (430)', width: 430, height: 932, dsf: 3, ua: IOS },
  // Планшет: мобільний лейаут, розтягнутий удвічі проти проєктного.
  { name: 'iPad mini (744)', width: 744, height: 1133, dsf: 2, ua: IPAD },
]

/**
 * ВИСОТУ ТУТ СВІДОМО НЕ ПІДМІНЮЄМО, хоч спокуса є: базовий стаб харнеса зашив
 * `viewportHeight: 568` (iPhone SE мінус хром клієнта), і на екрані 932px це
 * виглядає неправдою. Підміна нічого не дала б: оболонка стоїть на
 * `max(var(--tg-vh), 100svh)` — саме той фікс, яким лікували чорну смугу під
 * клавіатурою, — тож на будь-якому пристрої висота виходить із вікна, а
 * телеграмне значення бере гору лише коли воно БІЛЬШЕ.
 *
 * Перша версія цього гарда таки підміняла — і напоролась на власну помилку
 * заміру: `window.innerHeight`, прочитаний в `addInitScript`, віддає вікно
 * браузера ДО застосування емуляції (2015 замість 740), тож `--tg-vh` став
 * 1713px, оболонка виросла вдвічі, а FAB і таббар поїхали за нижній край. Гард
 * повідомляв би про «дефект», якого в застосунку немає.
 */

interface Overflow { sel: string; scroll: number; client: number; worst: string }

/**
 * Горизонтальне переповнення міряється на КОНТЕЙНЕРАХ, а не на кожному
 * елементі: чіп, що виїхав за край свого `overflow-x:auto` скролера, — це
 * «ще не доскролено», а не дефект (та сама пастка вже описана в зонді
 * тап-таргетів). Скролер клiпає вміст, тож на `scrollWidth` предка він не
 * впливає — і перевірка предків сама відкидає легальні випадки.
 *
 * `worst` — найдальший праворуч видимий елемент: він не є частиною критерію,
 * а лише підказкою в повідомленні, з чого починати розбір.
 */
const horizontalOverflow = (page: Page) => page.evaluate((): Overflow[] => {
  const out: Overflow[] = []
  const name = (e: Element) => {
    const cls = e.className?.toString().trim().split(/\s+/)[0]
    return cls ? `${e.tagName.toLowerCase()}.${cls}` : e.tagName.toLowerCase()
  }
  const roots = [
    document.documentElement,
    document.body,
    ...Array.from(document.querySelectorAll('#app-root, .scr, .body')),
  ]
  for (const el of roots as HTMLElement[]) {
    if (!el.isConnected) continue
    const cs = getComputedStyle(el)
    // Контейнер, якому скрол дозволений за задумом, переповненим не вважається.
    if (cs.overflowX === 'auto' || cs.overflowX === 'scroll') continue
    if (el.scrollWidth <= el.clientWidth + 1) continue
    let worst = '—'
    let max = -Infinity
    el.querySelectorAll('*').forEach((c) => {
      const r = c.getBoundingClientRect()
      if (r.width < 1 || r.height < 1) return
      if (r.right > max) { max = r.right; worst = `${name(c)} → ${Math.round(r.right)}px` }
    })
    out.push({ sel: name(el), scroll: el.scrollWidth, client: el.clientWidth, worst })
  }
  return out
})

interface Spill { cls: string; label: string; text: number; box: number }

/**
 * Підпис вилазить за свою кнопку.
 *
 * `scrollWidth` тут не працює: у первинних кнопок немає `text-overflow`, тож
 * довгий підпис не клiпається — він просто виходить за край, і scrollWidth
 * лишається рівним clientWidth. Єдиний надійний вимір — реальний бокс ВМІСТУ
 * через `Range`, проти ширини кнопки мінус її горизонтальні падінги.
 */
const labelSpill = (page: Page) => page.evaluate((): Spill[] => {
  const out: Spill[] = []
  // `.acc-act` доданий після реального пропуску: три текстові підписи в рядку
  // доступів вилазили за свої кнопки на 22–31px при 375px, і жоден гард цього
  // не бачив — перевірка стояла лише на трьох селекторах вище. Знайшлось оком
  // на перезнятому бейслайні, тобто найдорожчим способом.
  document.querySelectorAll('.mbtn, .fbtn, .modal-btn, .acc-act').forEach((el) => {
    const e = el as HTMLElement
    const r = e.getBoundingClientRect()
    if (r.width < 4 || r.height < 4) return
    const cs = getComputedStyle(e)
    if (cs.visibility === 'hidden' || cs.display === 'none') return
    const range = document.createRange()
    range.selectNodeContents(e)
    const tr = range.getBoundingClientRect()
    range.detach()
    const inner = r.width - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)
    // 1px — на субпіксельне округлення, не «майже влізло».
    if (tr.width > inner + 1) {
      out.push({
        cls: e.className.toString().slice(0, 24),
        label: (e.textContent || '').trim().slice(0, 28),
        text: Math.round(tr.width), box: Math.round(inner),
      })
    }
  })
  return out
})

for (const dev of DEVICES) {
  test(`${dev.name}: верстка тримається на всіх екранах`, async ({ browser }: { browser: Browser }) => {
    test.setTimeout(600_000)
    const problems: string[] = []
    const visited: string[] = []

    for (const group of ALL_GROUPS) {
      // Роль = власний контекст: `page.route` реєструється на сторінку, і
      // повторний `setupApp` мовчки лишив би фікстури попередньої ролі.
      const ctx = await browser.newContext({
        viewport: { width: dev.width, height: dev.height },
        deviceScaleFactor: dev.dsf,
        isMobile: true,
        hasTouch: true,
        userAgent: dev.ua,
      })
      const page = await ctx.newPage()
      page.setDefaultTimeout(25_000)
      try {
        await group.fixtures(page)
        for (const s of group.screens) {
          await s.go(page)
          // Екрани виїжджають анімацією; замір посеред неї — це замір руху.
          await page.waitForTimeout(450)
          visited.push(s.label)

          for (const o of await horizontalOverflow(page)) {
            problems.push(
              `${s.label}: ${o.sel} переповнений по горизонталі — ${o.scroll}px у ${o.client}px (найдалі: ${o.worst})`)
          }
          for (const sp of await labelSpill(page)) {
            problems.push(
              `${s.label}: підпис «${sp.label}» ${sp.text}px не влазить у кнопку .${sp.cls} (${sp.box}px)`)
          }
          for (const t of await smallTargets(page, 44)) {
            // Саме `key`, а не перший клас із `cls`: той обрізаний до 24
            // символів, тож довге імʼя тихо перестало б збігатись із боргом.
            if (TAP_DEBT.has(t.key)) continue
            problems.push(`${s.label}: .${t.cls} «${t.label}» ${t.w}×${t.h} — зона дотику під 44px`)
          }
        }
      } finally {
        await ctx.close()
      }
    }

    // Антивакуумність: «проблем не знайдено» мусить означати «обійшли все».
    const expected = ALL_GROUPS.reduce((n, g) => n + g.screens.length, 0)
    expect(visited.length, `обхід обірвався: ${visited.length} із ${expected} екранів`).toBe(expected)
    expect([...new Set(problems)], `${dev.name} (${dev.width}×${dev.height})`).toEqual([])
  })
}
