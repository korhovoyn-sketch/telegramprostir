import { test, expect } from '@playwright/test'
import { OWNER_SCREENS, ownerFixtures } from './helpers/screens'

/**
 * НА ТАЧІ `:active` — ЄДИНИЙ СИГНАЛ, ЩО ТАП ЗАРЕЄСТРОВАНО.
 *
 * Hover тут немає за визначенням, тож контрол без стану натиску мовчить рівно
 * стільки, скільки летить його дія. Найдорожчий випадок, знайдений аудитом, —
 * рядок файлу: тап відкриває файл із мережевим запитом.
 *
 * Гард шукає елементи з `cursor:pointer`, для яких ЖОДНЕ `:active`-правило не
 * матчить ні їх, ні предка. Перевірка предків обовʼязкова: картка
 * масштабується цілком, тож `.obj-t` усередині неї відгук МАЄ — без цього
 * зонд рахував 39 «дефектів» замість 8, майже всі з них діти клікабельних
 * рядків. Дзеркало вже записаного уроку про тап-таргети («влучив у предка» ≠
 * «влучив у контрол»), тільки в інший бік.
 *
 * МІРЯЄ ЛИШЕ КЛАСОВАНІ контроли. Кнопки, зібрані інлайновими стилями без
 * класу (степер форми, горизонт календаря, дії з файлами), теж не мають
 * відгуку — але назвати їх у списку нічим, крім тексту, а текст нестабільний.
 * Це окрема робота: дати їм класи. Записано, щоб не виглядало як недогляд.
 */

// Контроли, ВЛАСНИЙ стан яких і є відгуком: перемикач переїжджає, сегмент
// підсвічується — миттєво, без мережі. Додавати їм ще й натиск нема потреби.
const OWN_STATE = new Set(['tgl', 'tgl-th', 'fr-seg-b'])

test('клікабельні класи мають стан натиску', async ({ page }) => {
  // 25 кроків обходу в одному тесті — та сама межа, що в `contrast` і
  // `design-system-runtime`: дефолтні 30с вичерпуються на середині маршруту.
  test.setTimeout(300_000)
  await ownerFixtures(page)
  const missing = new Map<string, string>()
  let checked = 0

  for (const step of OWNER_SCREENS) {
    await step.go(page)
    await page.waitForTimeout(250)
    const res = await page.evaluate(() => {
      const act: string[] = []
      for (const sh of Array.from(document.styleSheets)) {
        let rules: CSSRuleList
        try { rules = sh.cssRules } catch { continue }
        for (const r of Array.from(rules)) {
          const sel = (r as CSSStyleRule).selectorText
          if (!sel || !sel.includes(':active')) continue
          for (const one of sel.split(','))
            if (one.includes(':active')) act.push(one.replace(/:active|:not\([^)]*\)/g, '').trim())
        }
      }
      const bad: string[] = []
      let n = 0
      for (const el of Array.from(document.querySelectorAll<HTMLElement>('*'))) {
        // `className` у SVG — це SVGAnimatedString, не рядок: без getAttribute
        // зонд репортував «.[object SVGAnimatedString]» як окремий клас.
        const cls = (el.getAttribute('class') || '').trim()
        if (!cls) continue                                   // безкласові — див. шапку
        if (getComputedStyle(el).cursor !== 'pointer') continue
        if (!el.getBoundingClientRect().width) continue
        n++
        let hit = false
        for (let p: HTMLElement | null = el; p && !hit; p = p.parentElement)
          hit = act.some((s) => { try { return !!s && p!.matches(s) } catch { return false } })
        // Клікабельність могла прийти від БЕЗКЛАСОВОЇ кнопки згори (степер
        // форми, горизонт календаря, дії з файлами — зібрані інлайновими
        // стилями). Тоді знахідка належить ЇЙ, а не цій дитині: інакше той
        // самий контрол репортується під іменем свого `.ico`.
        if (!hit) {
          let ownerless = false
          for (let p: HTMLElement | null = el.parentElement; p && !ownerless; p = p.parentElement)
            if ((p.tagName === 'BUTTON' || p.tagName === 'A') && !p.getAttribute('class')) ownerless = true
          if (ownerless) continue
        }
        if (!hit) {
          // Разом із ланцюгом предків: клікабельність часто приходить згори,
          // і без цього повідомлення каже «.ico», не кажучи ВІД ЧОГО.
          const chain: string[] = []
          for (let p: HTMLElement | null = el.parentElement; p && chain.length < 3; p = p.parentElement)
            chain.push(p.getAttribute('class')?.trim().split(' ')[0] || p.tagName.toLowerCase())
          bad.push(`${cls.split(' ')[0]} ← ${chain.join(' ← ')}`)
        }
      }
      return { bad, n }
    })
    checked += res.n
    for (const c of res.bad) if (!OWN_STATE.has(c.split(' ')[0]) && !missing.has(c)) missing.set(c, step.label)
  }

  // АНТИВАКУУМ: без цього «жоден контрол не порушив правило» означало б
  // «селектор зламався і контролів не знайшлось».
  expect(checked, 'зонд мусив знайти клікабельні контроли').toBeGreaterThan(100)

  expect([...missing].map(([c, s]) => `.${c} (${s})`),
    'клікабельний клас без :active — на тачі тап у нього не дає жодного сигналу').toEqual([])
})

/**
 * ВИГЛЯДАЄ НАТИСКНИМ ⇒ МУСИТЬ БУТИ ДІЄЮ.
 *
 * Гард вище перевіряє ВІДГУК на тап. Він і пропустив дефект протилежного роду:
 * плитки статистики мали `cursor:pointer` і `:active{scale(.94)}` на ПʼЯТЬОХ
 * екранах, а `onClick` — на жодному. Тобто перевірка «є відгук» проходила
 * бездоганно на контролі, який не робить НІЧОГО: палець його втискає, і на
 * цьому все. Найгірше, що дорікнути нема чому — обидва правила виконані
 * окремо, зламане лише їхнє поєднання.
 *
 * Обробник React у DOM не видно (події делеговані в корінь), тож дією
 * вважається семантика: `button`, `a`, `input`, `label`, `[role]` — або такий
 * предок. Це заодно тримає вже записане правило «клікабельний елемент —
 * `<button>`, не `<div>`»: клікабельний `<div>` недосяжний з клавіатури і не
 * оголошується читалкою, тобто теж дефект, просто інший.
 */
const FAKE_TAP_DEBT = new Map<string, string>([
  // Ці ДІЮТЬ — просто дія висить на `<div>`/`<span>`, а не на `<button>`, і з
  // DOM обробника React не видно. Тобто це борг ДОСТУПНОСТІ (з клавіатури не
  // дійти, читалка не оголосить), а не фальшива афорданс, і виправляється він
  // окремою роботою — переведенням на `<button>`, як уже зроблено для
  // `.sheet-row` і `.fr-seg-b`. Список заморожений: НОВИЙ клікабельний `<div>`
  // сюди не потрапить сам і гард на нього впаде.
  ['row', 'рядок бази — відкриває базу'],
  ['obj-card', 'картка обʼєкта — відкриває обʼєкт'],
  ['seg-b', 'сегмент фільтра — перемикає вибірку'],
  ['fold-hd', 'заголовок папки — згортає секцію'],
  ['notif-i', 'рядок сповіщення — веде до джерела'],
  ['notif-tab', 'вкладка сповіщень — перемикає фільтр'],
  ['type-card', 'вибір типу бази'],
  ['color-c', 'вибір кольору бази'],
  ['format-card', 'вибір формату експорту'],
  ['tmpl', 'вибір шаблона PDF'],
  ['photo-t', 'мініатюра фото — відкриває галерею'],
  ['fr', 'рядок форми — деякі відкривають пікер'],
])

test('клікабельний вигляд означає справжню дію', async ({ page }) => {
  test.setTimeout(300_000)
  await ownerFixtures(page)
  const fake = new Map<string, string>()
  let checked = 0

  for (const step of OWNER_SCREENS) {
    await step.go(page)
    await page.waitForTimeout(250)
    const res = await page.evaluate(() => {
      const ACTIONABLE = 'button,a,input,select,textarea,label,[role="button"],[role="link"],[role="tab"],[role="switch"],[role="checkbox"],[contenteditable]'
      // `cursor` УСПАДКОВУЄТЬСЯ, тож `getComputedStyle` віддає `pointer` і для
      // кожної дитини клікабельного рядка. Перша версія зонда через це знайшла
      // 56 «дефектів», де майже все — `.row-t`, `.obj-s`, `.ico` всередині
      // свого ж контрола. Рахувати треба ті, чиє ВЛАСНЕ правило оголошує
      // курсор, — той самий прийом, що збирає `:active` у гарді вище.
      const ptr: string[] = []
      for (const sh of Array.from(document.styleSheets)) {
        let rules: CSSRuleList
        try { rules = sh.cssRules } catch { continue }
        for (const r of Array.from(rules)) {
          const st = r as CSSStyleRule
          if (!st.selectorText || st.style?.cursor !== 'pointer') continue
          for (const one of st.selectorText.split(','))
            ptr.push(one.replace(/:(hover|active|focus[a-z-]*)|:not\([^)]*\)/g, '').trim())
        }
      }
      const bad: string[] = []
      let n = 0
      for (const el of Array.from(document.querySelectorAll<HTMLElement>('*'))) {
        const cls = (el.getAttribute('class') || '').trim()
        if (!cls) continue
        if (getComputedStyle(el).cursor !== 'pointer') continue
        if (!el.getBoundingClientRect().width) continue
        // Курсор мусить бути ОГОЛОШЕНИЙ на цьому елементі, а не успадкований.
        if (!ptr.some((sel) => { try { return !!sel && el.matches(sel) } catch { return false } })) continue
        n++
        // Сам елемент або будь-який предок — справжній контрол. Предка треба
        // питати з тієї ж причини, що й у гарді вище: клікабельність часто
        // приходить згори, і без цього кожна іконка всередині кнопки
        // репортувалась би окремо.
        if (el.closest(ACTIONABLE)) continue
        // Дитина теж рахується: обгортка може лише малювати рамку, а натискним
        // бути вкладений `<button>`.
        if (el.querySelector(ACTIONABLE)) continue
        bad.push(cls.split(' ')[0])
      }
      return { bad, n }
    })
    checked += res.n
    for (const c of res.bad) if (!FAKE_TAP_DEBT.has(c) && !fake.has(c)) fake.set(c, step.label)
  }

  // АНТИВАКУУМ: той самий, що вище — «порушень немає» мусить означати
  // «контроли знайшлись і перевірені», а не «селектор помер».
  expect(checked, 'зонд мусив знайти клікабельні контроли').toBeGreaterThan(100)

  expect([...fake].map(([c, s]) => `.${c} (${s})`),
    'елемент виглядає натискним, але не є дією — палець його втискає, і нічого не стається')
    .toEqual([])
})
