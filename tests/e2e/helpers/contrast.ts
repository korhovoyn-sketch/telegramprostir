import { expect, type Page } from '@playwright/test'
import sharp from 'sharp'

/**
 * Замір контрасту тексту й фактичної зони дотику по РЕАЛЬНОМУ рендеру.
 *
 * Спільний код для `contrast.spec.ts` (гард) і `_contrast.spec.ts` (принтер
 * найгірших місць). Аналітично контраст тут не порахувати: увесь текст — біле з
 * альфою, під ним шари скла над градієнтом, який СВІТЛІШАЄ донизу (низ
 * `.bg-blue` — #5480dc). Тож фон беремо з рендера: знімок робиться двічі —
 * звичайний і з прозорим текстом; другий дає чистий фон, у ньому й
 * усереднюються пікселі під кожним текстовим блоком.
 */

export interface TextBox {
  text: string
  cls: string
  /** Ключ для allowlist: власний клас, або «батьківський>тег» для безкласових. */
  key: string
  color: [number, number, number, number]
  size: number
  weight: number
  x: number; y: number; w: number; h: number
}

export interface Row {
  ratio: number
  need: number
  text: string
  cls: string
  key: string
  size: number
  weight: number
}

/** Видимі текстові блоки з їхнім кольором і геометрією. */
export const textBoxes = (page: Page) => page.evaluate((): TextBox[] => {
  const first = (el: Element) => (el.className?.toString().trim().split(/\s+/)[0] ?? '')
  const out: TextBox[] = []
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  const seen = new Set<Element>()
  let n: Node | null
  while ((n = walker.nextNode())) {
    const txt = (n.textContent ?? '').trim()
    if (txt.length < 2) continue
    const el = n.parentElement
    if (!el || seen.has(el)) continue
    seen.add(el)
    const r = el.getBoundingClientRect()
    if (r.width < 6 || r.height < 6 || r.top < 0 || r.bottom > window.innerHeight) continue
    const cs = getComputedStyle(el)
    if (cs.visibility === 'hidden' || cs.opacity === '0') continue
    const m = cs.color.match(/[\d.]+/g)
    if (!m) continue
    const own = first(el)
    out.push({
      text: txt.slice(0, 28),
      cls: el.className?.toString().slice(0, 22) || el.tagName.toLowerCase(),
      // Безкласовий вузол (напр. <span> усередині оверлайна) не має власного
      // ключа — інакше allowlist «span» дозволяв би будь-який текст на екрані.
      key: own || `${first(el.parentElement ?? el) || '?'}>${el.tagName.toLowerCase()}`,
      color: [Number(m[0]), Number(m[1]), Number(m[2]), m[3] === undefined ? 1 : Number(m[3])],
      size: Math.round(parseFloat(cs.fontSize)),
      weight: Number(cs.fontWeight) || 400,
      x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height),
    })
  }
  return out
})

const lum = (r: number, g: number, b: number) => {
  const f = (v: number) => {
    const s = v / 255
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
  }
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
const ratio = (a: number, b: number) => (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)

/** WCAG AA: 4.5 звичайний текст, 3.0 «великий» (≥18.66px bold або ≥24px). */
export const needRatio = (size: number, weight: number) =>
  size >= 24 || (size >= 18.66 && weight >= 700) ? 3 : 4.5

/**
 * Контраст усіх текстових блоків поточного екрана.
 *
 * УВАГА: робить текст прозорим через `addStyleTag`, тобто НЕОБОРОТНО псує
 * сторінку для подальших кроків. Після виклику треба перейти на екран заново.
 */
export async function measureContrast(page: Page): Promise<Row[]> {
  const boxes = await textBoxes(page)
  await page.addStyleTag({ content: '*{color:transparent !important;text-shadow:none !important}' })
  const shot = await page.screenshot()
  const { data, info } = await sharp(shot).ensureAlpha().raw().toBuffer({ resolveWithObject: true })
  const scale = info.width / (page.viewportSize()?.width ?? 375)

  const rows: Row[] = []
  for (const b of boxes) {
    let sr = 0, sg = 0, sb = 0, cnt = 0
    const x0 = Math.max(0, Math.round(b.x * scale)), x1 = Math.min(info.width, Math.round((b.x + b.w) * scale))
    const y0 = Math.max(0, Math.round(b.y * scale)), y1 = Math.min(info.height, Math.round((b.y + b.h) * scale))
    for (let y = y0; y < y1; y += 2) {
      for (let x = x0; x < x1; x += 2) {
        const i = (y * info.width + x) * info.channels
        sr += data[i]; sg += data[i + 1]; sb += data[i + 2]; cnt++
      }
    }
    if (!cnt) continue
    const [br, bgc, bb] = [sr / cnt, sg / cnt, sb / cnt]
    // Текст із альфою компонується на цей фон.
    const a = b.color[3]
    const tr = b.color[0] * a + br * (1 - a)
    const tg = b.color[1] * a + bgc * (1 - a)
    const tb = b.color[2] * a + bb * (1 - a)
    rows.push({
      ratio: Math.round(ratio(lum(tr, tg, tb), lum(br, bgc, bb)) * 100) / 100,
      need: needRatio(b.size, b.weight),
      text: b.text, cls: b.cls, key: b.key, size: b.size, weight: b.weight,
    })
  }
  return rows
}

export const belowAA = (rows: Row[]) =>
  rows.filter((x) => x.ratio < x.need).sort((a, b) => a.ratio - b.ratio)

export interface SmallTarget { cls: string; key: string; label: string; w: number; h: number }

/**
 * Контроли, чия ФАКТИЧНА зона дотику менша за `min`.
 *
 * Міряється `elementFromPoint`, а не бокс: невидимий `::after` розширює зону до
 * 44px, не змінюючи вигляд рядка, і для боксового заміру лишався б невидимим.
 */
export const smallTargets = (page: Page, min: number) => page.evaluate<SmallTarget[], number>((m) => {
  const out: SmallTarget[] = []
  const bar = document.querySelector('.tabbar') as HTMLElement | null
  // Міряти від верху таббару, а не від `innerHeight`: оболонка (--tg-vh) нижча
  // за вікно, тож усе під нею просто нижче фолду, а не «вкрадене».
  const fold = bar ? bar.getBoundingClientRect().top : window.innerHeight
  document.querySelectorAll('button,[role="button"],a,input[type="checkbox"],.sheet-row,.notif-tab,.seg-b,.view-seg-b,.fr-seg-b,.tab,.obj-act-btn,.hdr-back').forEach((el) => {
    const e = el as HTMLElement
    const r = e.getBoundingClientRect()
    if (r.width < 4 || r.height < 4) return
    if (r.top < 0 || r.bottom > fold) return
    // Контрол у горизонтально прокрутному контейнері (таби сповіщень) може лежати
    // ЗА межами viewport — це «ще не проскролено», а не малий таргет:
    // elementFromPoint там завжди null і фальшиво давав висоту 1.
    if (r.left < 0 || r.right > window.innerWidth) return
    const cs = getComputedStyle(e)
    if (cs.visibility === 'hidden') return
    // Неактивний контрол не приймає тапів ЗА ЗАДУМОМ (`.btn-glass:disabled` має
    // `pointer-events:none`), тож `elementFromPoint` віддає елемент під ним, і
    // зонд рахував ефективну висоту 1px. Це не «крихітна кнопка», а вимкнена —
    // на 4 екранах, з яких зонд ходив раніше, disabled-кнопок просто не було.
    if (cs.pointerEvents === 'none') return
    // Те саме, але по горизонталі: чіп, ЧАСТКОВО виїхавший за край свого
    // h-скролера, лишається в DOM із повним боксом, хоч видно лише його край.
    // Центр такого чіпа фізично належить сусідньому контролу — і зонд читав це
    // як «крадіжка тапу», хоч користувач просто ще не доскролив стрічку.
    // Перевірка проти `window.innerWidth` вище цього не бачить: клiпає не вікно,
    // а контейнер.
    for (let p = e.parentElement; p; p = p.parentElement) {
      const ps = getComputedStyle(p)
      if (ps.overflowX !== 'auto' && ps.overflowX !== 'scroll') continue
      const pr = p.getBoundingClientRect()
      if (r.left < pr.left - 1 || r.right > pr.right + 1) return
    }
    const cx = Math.round(r.left + r.width / 2)
    const cy = Math.round(r.top + r.height / 2)
    // Влучанням вважається САМ контрол або його нащадок. `h.contains(e)` тут був
    // помилкою: тап в обгородку (`.seg`, рядок картки) її задовольняв, тож зонд
    // «бачив» 44px там, де насправді був бокс 34px — і гард на 44 проходив навіть
    // після видалення розширення `::after`.
    const hits = (y: number) => {
      if (y < 1 || y > fold - 1) return false
      const h = document.elementFromPoint(cx, y)
      return !!h && (h === e || e.contains(h))
    }
    let up = 0, down = 0
    while (up < 30 && hits(cy - up - 1)) up++
    while (down < 30 && hits(cy + down + 1)) down++
    const effH = up + down + 1
    if (r.width < m || effH < m) {
      out.push({
        cls: e.className?.toString().slice(0, 24) || e.tagName.toLowerCase(),
        key: e.className?.toString().trim().split(/\s+/)[0] || e.tagName.toLowerCase(),
        label: (e.getAttribute('aria-label') || e.textContent || '').trim().slice(0, 22),
        w: Math.round(r.width), h: effH,
      })
    }
  })
  return out
}, min)

/** Зручний асерт: усі порушення поза allowlist. */
export function expectAllowed(
  found: { key: string; label: string }[],
  allow: ReadonlySet<string>,
  message: string,
) {
  const unexpected = [...new Set(found.filter((f) => !allow.has(f.key)).map((f) => `${f.key} «${f.label}»`))]
  expect(unexpected, message).toEqual([])
}

/**
 * Заморожений борг зони дотику.
 *
 * `.view-seg-b` — квадратні кнопки-іконки «Картки / Компактно» 38px впритул
 * одна до одної в спільній обгородці: розширення вкрало б тап у сусідню, тож це
 * рішення про геометрію пари, а не про сам контрол.
 *
 * `.obj-act-btn` — рядок дій картки. Природний бокс (~35px) СВІДОМО не
 * розширюють через `::after`: над кнопками тіло картки, яке відкриває обʼєкт, і
 * розширена зона вкрала б у нього тапи.
 *
 * Решта зʼявилась разом із розширенням обходу на 21 екран — і це інвентар, а не
 * рішення «так і треба»: степер кількості в формі (32×32), чіпи сортування
 * (32px), кнопки календаря платежів (29–36px), «Поділитись»/«Відкликати» в
 * гостях і команді (31px), «Написати власнику» (36px). Усі проходять поріг
 * `ui-audit` (32px, WCAG 2.5.8 AA — 24px) і не дотягують до Apple HIG 44.
 * Піднімати їх — окрема робота з переверсткою рядків, а не правка порогу.
 */
export const TAP_DEBT: ReadonlySet<string> = new Set([
  'view-seg-b', 'obj-act-btn', 'sort-chip', 'owner-act', 'button',
  // Сегмент фільтра («Всі / Вільно / Зайнято / Продаж»), 34px — рішення
  // власника про компактніше меню. Розширити зону через `::after` тут
  // НЕМОЖЛИВО: власний `overflow:hidden` під ellipsis клiпає псевдоелемент
  // (див. розділ про тап-таргети в CLAUDE.md). Прецедент — UISegmentedControl
  // Apple має 32pt, а смуга займає всю ширину екрана.
  'seg-b',
])
