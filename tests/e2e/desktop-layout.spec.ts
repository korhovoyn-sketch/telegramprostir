import { test, expect, type Page, type Browser } from '@playwright/test'
import { ALL_GROUPS } from './helpers/screens'

/**
 * ДЕСКТОПНА ВЕРСТКА — ОДИН ЛІВИЙ КРАЙ НА ЕКРАН.
 *
 * `desktop.spec.ts` перевіряє РАМКУ (її ширину, шит у її межах, підпис під
 * нею) на одному екрані. Чого не перевіряв ніхто — що всередині рамки вміст
 * вирівняний. А саме там і був дефект: на кожному з 34 знятих кадрів частина
 * блоків стояла на колонці читання, а частина — на краю рамки, тобто ТРИ
 * РІЗНІ ЛІВІ КРАЇ на одному екрані (привітання й `.display` у db-list, чіпи
 * сортування в db-objects, оверлайни й чіпи послуг у property-detail,
 * `.notif-tabs`, картки формату експорту, плитки профілю).
 *
 * Гард міряє саме це, а не «ширина ≤ 620»: обмеження ширини блок міг мати й
 * лишатись притиснутим до лівого краю — рівно так воно й було, поки
 * центрування глушив інлайновий `margin` (див. коментар у globals.css).
 *
 * Ходить УСІМА екранами через `helpers/screens.ts` на двох ширинах: 1280 —
 * типовий ноутбук, 1920 — де рамка вже впирається у власну межу 1100 і поля
 * стають широкими.
 */

/**
 * ДВІ ШИРИНИ, І ДРУГА — НЕ «ЩЕ ШИРША».
 *
 * 1920 сюди НЕ береться свідомо: рамка обмежена 1100, тож при 1280 вона вже
 * 1100 — на 1920 змінюється лише поле обабіч, а вміст рендериться ІДЕНТИЧНО.
 * Другий прохід там коштував би повного обходу й не міг би знайти нічого.
 *
 * Натомість 720 — вузький кінець десктопного режиму: рамка 640, і межу
 * колонки задає вже не `--measure`, а `100% - 2 * var(--g3)`. Це інша гілка
 * `min()`, і саме вона лишалась би неперевіреною.
 */
const SIZES = [
  { w: 1280, h: 800, groups: ALL_GROUPS },
  { w: 720, h: 800, groups: ALL_GROUPS.slice(0, 1) },
]

/**
 * Межі колонки читання, пораховані з РЕАЛЬНОЇ геометрії `.body` і токена
 * `--measure`, а не з константи в тесті: інакше гард закріпив би своє число, а
 * не те, за яким живе застосунок.
 */
async function columnBounds(page: Page) {
  return page.evaluate(() => {
    // Від РАМКИ, а не від `.body`: екрани без `.body` (сканер, вибір ролі)
    // будують колонку класом `.col-read`, і межа в них та сама.
    const frame = document.getElementById('app-root')
    if (!frame) return null
    const root = getComputedStyle(document.documentElement)
    const measure = parseFloat(root.getPropertyValue('--measure'))
    const gutter = parseFloat(root.getPropertyValue('--g3'))
    if (Number.isNaN(measure) || Number.isNaN(gutter)) return null
    const box = frame.getBoundingClientRect()
    const track = Math.min(measure, box.width - 2 * gutter)
    const left = box.left + (box.width - track) / 2
    return { left, right: left + track, track }
  })
}

/**
 * Прямі діти `.body`, які мусять лежати в колонці. Свідомо відкидаються:
 * • `.list.cards`, `.list.fold-list` і `.dash-panel` — опт-аут: колекція бере
 *   всю рамку КІЛЬКІСТЮ карток. Звичайний `.list` (рядки) сюди НЕ входить і
 *   перевіряється нарівні з рештою — саме тому опт-аут зроблено опт-ином;
 * • вийняті з потоку (`fixed`/`absolute`) — флекс ними не керує за побудовою;
 * • невидимі й нульові — міряти в них нема чого.
 */
async function inColumnChildren(page: Page) {
  return page.evaluate(() => {
    // Екран без `.body` міряється по дітях `.scr` — САМЕ ТАК, а не по своїх
    // `.col-read`. Перша версія брала `.col-read`, і це робило перевірку
    // САМОЗДІЙСНЮВАНОЮ: прибрати клас означало прибрати елемент із заміру,
    // тож гард проходив на зламаному коді (доведено фальсифікацією — крок
    // «прибрано .col-read з вибору ролі» дав `1 passed`). Тепер клас є ФІКСОМ,
    // а не селектором вибірки.
    const host = document.querySelector<HTMLElement>('.body')
      ?? document.querySelector<HTMLElement>('.scr')
    if (!host) return []
    return Array.from(host.children).flatMap((el) => {
      const e = el as HTMLElement
      if (e.classList.contains('cards') || e.classList.contains('fold-list')
          || e.classList.contains('dash-panel')) return []
      // Хром: `.hdr` і `.tabbar` СВІДОМО займають усю рамку, а на колонку
      // виводять лише свій ВМІСТ (через `padding-inline`) — їхній бокс мірять
      // інші гарди. Тут вони зʼявляються лише на екранах без `.body`, де
      // вибірка йде по `.scr`.
      if (e.classList.contains('hdr') || e.classList.contains('tabbar')) return []
      const cs = getComputedStyle(e)
      if (cs.position === 'fixed' || cs.position === 'absolute') return []
      if (cs.display === 'none' || cs.visibility === 'hidden') return []
      const b = e.getBoundingClientRect()
      if (b.width < 2 || b.height < 2) return []
      return [{ cls: (e.className || e.tagName).toString().slice(0, 40), l: Math.round(b.left), r: Math.round(b.right) }]
    })
  })
}

for (const size of SIZES) {
  for (const group of size.groups) {
    test(`десктоп ${size.w} · ${group.role}: вміст лежить в одній колонці`, async ({ browser }: { browser: Browser }) => {
      test.setTimeout(300_000)
      const ctx = await browser.newContext({ viewport: { width: size.w, height: size.h }, deviceScaleFactor: 1 })
      const page = await ctx.newPage()
      page.setDefaultTimeout(25_000)
      try {
        await group.fixtures(page)

        let checkedScreens = 0
        let checkedNodes = 0
        let sawFullBleed = false
        const bad: string[] = []
        // Екрани, у яких колонки немає ВЗАГАЛІ. Пропускати їх мовчки не можна:
        // саме так із вимірювання випали `role-select` і `qr-scanner`, і
        // дефекти там знайшлись лише очима на кадрі.
        const noColumn: string[] = []
        const emptyScreens: string[] = []

        for (const s of group.screens) {
          await s.go(page)
          await page.waitForTimeout(350)

          // Рамка лишається ПАНЕЛЛЮ: не ширша за власну межу і строго вужча
          // за вікно. Без цього все нижче виконувалось би тривіально.
          const root = await page.evaluate(() => {
            const b = document.getElementById('app-root')!.getBoundingClientRect()
            return { l: Math.round(b.left), w: Math.round(b.width), win: window.innerWidth,
                     over: document.documentElement.scrollWidth <= window.innerWidth + 1 }
          })
          expect(root.w, `${s.label}: рамка ${root.w}px ширша за межу 1100`).toBeLessThanOrEqual(1100)
          expect(root.w, `${s.label}: рамка на всю ширину вікна — це вже не панель`).toBeLessThan(root.win)
          expect(root.over, `${s.label}: горизонтальне переповнення сторінки`).toBe(true)

          const col = await columnBounds(page)
          if (!col) continue
          const hasTargets = await page.evaluate(() =>
            !!document.querySelector('.body') || !!document.querySelector('.col-read'))
          if (!hasTargets) { noColumn.push(s.label); continue }
          checkedScreens++

          // Інваріант — НЕ «влазить у колонку», а «в колонці І ПО ЦЕНТРУ».
          // Самої межі ширини мало: блок міг її мати й лишатись притиснутим до
          // лівого краю рамки — рівно так дефект і виглядав. Але й рівності
          // країв вимагати не можна: пігулка первинної дії свідомо вужча за
          // колонку (`width: fit-content`), і вона правильна, поки центрована.
          const colCenter = (col.left + col.right) / 2
          const nodes = await inColumnChildren(page)
          // Антивакуум ПОЕКРАННИЙ, без магічного числа: екран, що не дав
          // жодного вузла, — це зламаний селектор або обірваний крок, і саме
          // він робить «порушень немає» порожньою обіцянкою. Спільний поріг
          // тут не працює: в онбордингу два екрани, у власника — тринадцять.
          if (nodes.length === 0) emptyScreens.push(s.label)
          for (const ch of nodes) {
            checkedNodes++
            const outside = ch.l < col.left - 1.5 || ch.r > col.right + 1.5
            const offCenter = Math.abs((ch.l + ch.r) / 2 - colCenter) > 1.5
            if (outside || offCenter) {
              bad.push(`${s.label} · ${ch.cls}: ${ch.l}–${ch.r} проти колонки ${Math.round(col.left)}–${Math.round(col.right)}`)
            }
          }

          // Антивакуум опт-ауту: колекція мусить бути ШИРШОЮ за колонку, інакше
          // «все в колонці» можна було б «пройти», забравши повноширинні списки.
          const listW = await page.evaluate(() => {
            const l = document.querySelector<HTMLElement>('.body > .list.cards')
            return l ? Math.round(l.getBoundingClientRect().width) : 0
          })
          if (listW > 0 && size.w >= 820 && listW > col.track + 1) sawFullBleed = true
          if (size.w < 820) sawFullBleed = true // грид карток нижче порога вимкнений
        }

        expect(bad, `блоки поза колонкою читання:\n${bad.join('\n')}`).toEqual([])
        // Повноекранні за задумом: сплеш (заставка) і галерея фото. Новий
        // екран у цьому списку = свідоме рішення, а не недогляд.
        expect(noColumn.filter((l) => !['splash', 'photo-gallery'].includes(l)),
          'екран без колонки читання — додай `.col-read` або внеси в список свідомо повноекранних')
          .toEqual([])
        // Антивакуум вибірки: маршрут міг обірватись, і «порушень немає»
        // означало б «нічого не міряли». Поріг ВІДНОСНИЙ, а не число: у
        // гостя всього три екрани, в онбордингу два, тож будь-яка константа
        // або валила б малі групи, або нічого не доводила для великих.
        expect(checkedScreens + noColumn.length, 'обхід не дійшов до всіх екранів групи')
          .toBe(group.screens.length)
        expect(emptyScreens, `екрани без жодного заміряного вузла: ${emptyScreens.join(', ')}`)
          .toEqual([])
        expect(checkedNodes, 'жодного вузла не заміряно').toBeGreaterThan(0)
        if (group.role === 'owner') {
          expect(sawFullBleed, 'жоден `.list.cards` не вийшов за колонку — опт-ин не працює').toBe(true)
        }
      } finally {
        await ctx.close()
      }
    })
  }
}
