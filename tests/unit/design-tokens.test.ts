import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Невідомий CSS-токен НЕ помітний під час рев'ю: `background:var(--bg2)` виглядає
// нормально, але браузер робить властивість невалідною — фон стає прозорим, а
// рамка зникає. Так панель дій над обраними об'єктами і екран помилки місяцями
// були без фону. Тест ловить весь клас механічно.

const CSS_PATH = 'src/app/globals.css'

// Токени, які задає РАНТАЙМ (JS або інлайн-стиль), а не :root. Кожен такий
// обов'язково вживається з фолбеком — інакше він нічим не кращий за помилку.
const RUNTIME_TOKENS = new Set([
  '--keyboard-h', '--tg-vh', '--pw',
  // Врізи від Telegram: env() у його iOS-webview не наповнюється, тож ці два
  // пише page.tsx із safeAreaInset/contentSafeAreaInset (обидва з фолбеком 0px).
  '--tg-safe-top', '--tg-safe-bottom',
  // Хід смужки сканера. Задає сам екран інлайном, бо це висота ЙОГО рамки:
  // анімація рухає `translateY`, а не `top` (інакше лейаут перераховувався б
  // кожен кадр усі 2s циклу), а translateY(%) тут непридатний — відсоток брався
  // б від власних 2px смужки.
  '--scan-h',
  // Позиція і затримка кожної зірочки навколо будинку: задаються ІНЛАЙНОМ на
  // конкретному елементі (у кожної свій кут розльоту), тож у :root їх бути не
  // може за побудовою. Обидві з фолбеком — див. сусідній гард.
  '--sx', '--sy', '--sd',
])

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.(tsx?|css)$/.test(name)) out.push(p)
  }
  return out
}

/** Коментарі не впливають на рендер — і саме в них живуть згадки старих токенів. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
}

const css = readFileSync(CSS_PATH, 'utf8')
const defined = new Set([...css.matchAll(/(--[a-zA-Z0-9-]+)\s*:/g)].map((m) => m[1]))
const files = walk('src')

describe('CSS-токени', () => {
  it('кожен var(--token) або оголошений у CSS, або рантаймовий', () => {
    const unknown: string[] = []
    for (const file of files) {
      const txt = stripComments(readFileSync(file, 'utf8'))
      for (const m of txt.matchAll(/var\((--[a-zA-Z0-9-]+)/g)) {
        const token = m[1]
        if (defined.has(token) || RUNTIME_TOKENS.has(token)) continue
        unknown.push(`${file}: ${token}`)
      }
    }
    expect(unknown, 'невідомі токени роблять властивість невалідною (прозорий фон / зникла рамка)').toEqual([])
  })

  it('рантаймові токени завжди мають фолбек', () => {
    const bare: string[] = []
    for (const file of files) {
      const txt = stripComments(readFileSync(file, 'utf8'))
      for (const token of RUNTIME_TOKENS) {
        const re = new RegExp(`var\\(\\s*${token}\\s*\\)`, 'g')
        if (re.test(txt)) bare.push(`${file}: ${token}`)
      }
    }
    expect(bare, 'рантаймовий токен без фолбека = порожнє значення до першого запису з JS').toEqual([])
  })
})

// ── Шкали не мають дублюватись літералами ───────────────────────────────────
// Токен, повз який пишуть значення руками, перестає бути системою: саме так
// у проєкті зʼявились дві сімʼї синього і дванадцять акцентів дашборда
// всередині компонента.

/** Значення токенів із :root → назва, для пошуку «переписаних руками» кольорів. */
function paletteByValue(): Map<string, string> {
  const root = stripComments(css).match(/:root\{([\s\S]*?)\n\}/)![1]
  const map = new Map<string, string>()
  for (const m of root.matchAll(/(--[a-zA-Z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\))\s*;/g)) {
    const norm = m[2].toLowerCase().replace(/\s+/g, '')
    if (!map.has(norm)) map.set(norm, m[1])
  }
  return map
}

// Файли з власною палітрою: публічна /v рендериться окремо від застосунку,
// іконки/декор — це графіка з градієнтами, експорт малює PDF (не екран).
const OWN_PALETTE = [
  // Нативний хром Telegram (setHeaderColor/setBackgroundColor) приймає ЛИШЕ hex,
  // var() там не працює — колір лежить у названій константі поряд із токеном.
  'src/app/page.tsx',
  'src/app/v/page.tsx',
  'src/components/Icons.tsx',
  'src/components/Confetti.tsx',
  'src/components/ProxMascot.tsx',
  'src/screens/ExportScreen.tsx',
]

describe('шкали дизайн-системи', () => {
  it('колір, який уже має токен, не переписують літералом у JSX', () => {
    const palette = paletteByValue()
    const bad: string[] = []
    for (const file of files) {
      if (!file.endsWith('.tsx') || OWN_PALETTE.some((o) => file.endsWith(o))) continue
      const txt = stripComments(readFileSync(file, 'utf8'))
      for (const m of txt.matchAll(/'(#[0-9a-fA-F]{3,8}|rgba?\([^)']*\))'/g)) {
        const norm = m[1].toLowerCase().replace(/\s+/g, '')
        const token = palette.get(norm)
        if (token) bad.push(`${file}: ${m[1]} → var(${token})`)
      }
    }
    expect(bad).toEqual([])
  })

  it('розміри шрифту зі шкали беруться токеном, а не літералом', () => {
    const root = stripComments(css).match(/:root\{([\s\S]*?)\n\}/)![1]
    const scale = new Set(
      [...root.matchAll(/--fs-[a-z0-9]+\s*:\s*(\d+)px/g)].map((m) => Number(m[1])),
    )
    const body = stripComments(css).slice(stripComments(css).indexOf('\n}', stripComments(css).indexOf(':root{')))
    const bad = [...body.matchAll(/font-size:\s*(\d+)px/g)]
      .map((m) => Number(m[1]))
      .filter((v) => scale.has(v))
    expect(bad, 'значення зі шкали мусить бути var(--fs-*)').toEqual([])
  })

  it('шар береться зі шкали --z-*, а не пишеться числом', () => {
    // Шарування — єдина властивість, значення якої нічого не означає саме по
    // собі: важливий лише порядок відносно інших. Поки числа стояли по місцях
    // (19 різних у CSS + 7 інлайном), прочитати цей порядок було неможливо
    // навіть уважно: `.batchbar` на 100 проти `.modal-overlay` на 50 виглядає
    // як «панель поверх шита», а насправді вона в іншому контексті накладання
    // (`#app-root` — `position:fixed`, тобто контекст створює). Числа без
    // спільної шкали не читаються ні в бік дефекту, ні в бік «усе гаразд».
    const nc = stripComments(css)
    const body = nc.slice(nc.indexOf('\n}', nc.indexOf(':root{')))
    const rawCss = [...body.matchAll(/z-index:\s*(-?\d+)/g)].map((m) => `globals.css: ${m[0]}`)
    const rawTsx: string[] = []
    for (const file of files) {
      if (!file.endsWith('.tsx')) continue
      const txt = stripComments(readFileSync(file, 'utf8'))
      for (const m of txt.matchAll(/zIndex:\s*(-?\d+)/g)) rawTsx.push(`${file}: ${m[0]}`)
    }
    expect([...rawCss, ...rawTsx], 'сирий z-index не порівняти з рештою — візьми var(--z-*)').toEqual([])
  })

  it('шкала --z-* строго зростає в порядку оголошення', () => {
    // Порядок у файлі — це і є документація шару. Якщо він розійдеться зі
    // значеннями, читач повірить файлу, а браузер — числу.
    const root = stripComments(css).match(/:root\{([\s\S]*?)\n\}/)![1]
    const scale = [...root.matchAll(/(--z-[a-z-]+)\s*:\s*(-?\d+)\s*;/g)]
      .map((m) => ({ name: m[1], v: Number(m[2]) }))
    expect(scale.length, 'шкала шарів зникла — селектор застарів').toBeGreaterThan(8)
    const outOfOrder = scale
      .filter((t, i) => i > 0 && t.v <= scale[i - 1].v)
      .map((t, i) => `${scale[scale.indexOf(t) - 1].name} → ${t.name}`)
    expect(outOfOrder, 'значення мусить зростати разом із позицією в блоці').toEqual([])
  })

  it('рецепт тіні, вжитий утретє, — це токен', () => {
    // НЕ «кожна box-shadow має бути токеном»: більшість тут — власна графіка
    // правила (фокус-кільце, світіння, inset-смуга), і токенізувати їх означало
    // б вигадати систему. Родина починається з третього входження — і саме там
    // дрейф невидимий: четвертий сегмент мав .28 замість .3 на inset-волосинці.
    const nc = stripComments(css)
    const body = nc.slice(nc.indexOf('\n}', nc.indexOf(':root{')))
    const seen = new Map<string, number>()
    for (const m of body.matchAll(/box-shadow:\s*([^;}]+)/g)) {
      const v = m[1].replace(/\s+/g, '')
      if (v.includes('var(--shadow') || v === 'none') continue
      seen.set(v, (seen.get(v) ?? 0) + 1)
    }
    const repeated = [...seen].filter(([, n]) => n >= 3).map(([v, n]) => `${n}× ${v}`)
    expect(repeated, 'однаковий рецепт у трьох місцях — заведи --shadow-*').toEqual([])
  })

  it('жодна крива не має перельоту вище одиниці', () => {
    // Пружину прибрано рішенням власника, і причина заміряна, а не вигадана:
    // покадровий розбір запису з iPhone показав, що шит меню опинявся на 75px
    // ВИЩЕ кінцевої позиції, потім хитався 87 → 95 → 93 → 90 і лише тоді ставав.
    // На довгому шляху переліт читається не як живість, а як ривок.
    //
    // Перевіряємо контрольні точки y (2-га і 4-та в cubic-bezier): якщо котрась
    // > 1, крива виходить за кінцеве значення й вертається назад.
    const root = stripComments(css).match(/:root\{([\s\S]*?)\n\}/)![1]
    const bad: string[] = []
    for (const m of root.matchAll(/(--[a-z-]*ease[a-z-]*)\s*:\s*cubic-bezier\(([^)]*)\)/g)) {
      // cubic-bezier(x1,y1,x2,y2) → нас цікавлять y1 та y2, тобто індекси 1 і 3.
      // Перша версія брала 2 і 4: індекс 4 не існує, `undefined > 1` завжди
      // false, і гард проходив навіть із поверненою пружиною. Спіймано власною
      // ж фальсифікацією — рівно те, заради чого вона й робиться.
      const p = m[2].split(',').map((n) => Number(n.trim()))
      expect(p.length, `${m[1]}: крива має бути з 4 чисел`).toBe(4)
      const [, y1, , y2] = p
      if (y1 > 1 || y2 > 1) bad.push(`${m[1]}: y1=${y1} y2=${y2}`)
    }
    expect(bad, 'крива з викидом вище 1 — це переліт; власник просив спокійне сповільнення').toEqual([])
  })

  it('виїзд шита рухає transform, а не геометрію', () => {
    // Лейаутна анімація на поверхні розміром з екран — найдорожче, що можна
    // зробити; `modalSlideUp` мусить лишатись на transform.
    const nc = stripComments(css)
    const kf = nc.match(/@keyframes\s+modalSlideUp\s*\{([\s\S]*?)\}\s*\n/)
    expect(kf, '@keyframes modalSlideUp зник — селектор застарів').not.toBeNull()
    const props = [...kf![1].matchAll(/([a-z-]+)\s*:/g)].map((m) => m[1])
    expect([...new Set(props)], 'лише transform').toEqual(['transform'])
  })

  it('криві анімацій живуть у токенах, а не літералами в правилах', () => {
    const nc = stripComments(css)
    const body = nc.slice(nc.indexOf('\n}', nc.indexOf(':root{')))
    const bad = [...body.matchAll(/cubic-bezier\([^)]*\)/g)].map((m) => m[0])
    expect(bad, 'та сама крива має бути --ease*').toEqual([])
  })
})

// Модалка не підіймає клавіатуру САМА.
//
// Рішення власника, і причина в тому, що фокус тягне за собою цілий ланцюг:
// iOS підіймає клавіатуру → проба `kbFallback` (350+200мс) → `padding-bottom
// .25s` оверлея → `max-height .25s` шита. Три геометрії одночасно на поверхні
// з блюром — це і є «клавіатура перекриває або піджимає шит».
//
// Спершу гард розрізняв два випадки — фокус по таймеру (заборонений) і
// `autoFocus` на полі, що зʼявилось ВІД ТАПУ (дозволений як «пряма відповідь на
// дію»). Це була моя інтерпретація, і вона лишила дефект живим: тап по «+ Нова
// папка» / «Перейменувати» МОНТУЄ поле, тобто міняє висоту самого шита — і
// фокус у той самий кадр запускає весь ланцюг вище поверх 48px-блюру. Саме цей
// сценарій власник і описав словом «відразу». Рішення однозначне й поширюється
// на обидва випадки: клавіатуру підіймає тап КОРИСТУВАЧА по полю, не код.
//
// Екранні `autoFocus` (`CreateDatabaseScreen`, `PropertyFormScreen`) сюди НЕ
// входять: там немає ні слайд-анімації шита, ні клавіатурної корекції оверлея.
describe('клавіатура в модалках', () => {
  it('жоден шит не фокусує поле сам — ні при відкритті, ні на тапі', () => {
    const SHEETS = files.filter((f) =>
      /src\/components\/ui\/(Modal|ShareSheet|Folder\w+|DbPickerModal|FilePreviewModal|SheetCreateRow)\.tsx$/.test(f))
    expect(SHEETS.length, 'список шитів порожній — регекс застарів').toBeGreaterThan(4)
    const bad: string[] = []
    for (const file of SHEETS) {
      const txt = stripComments(readFileSync(file, 'utf8'))
      // Фокус із таймера/ефекту = автоматичний.
      if (/setTimeout\([^)]*focus\(\)/.test(txt) || /\.focus\(\)\s*,\s*\d+\s*\)/.test(txt)) {
        bad.push(`${file}: фокус по таймеру`)
      }
      // `autoFocus` на полі, змонтованому тапом, — той самий ланцюг.
      if (/\bautoFocus\b/.test(txt)) bad.push(`${file}: autoFocus`)
    }
    expect(bad, 'шит підіймає клавіатуру сам — прибери фокус, хай його дає тап користувача').toEqual([])
  })
})

// Мертвий @keyframes — це не лише байти в бандлі, а й фальшивий слід: наступний
// розробник бачить назву й думає, що анімація десь працює. `drawLine` так і
// пролежав невживаним.
describe('анімації', () => {
  it('кожен @keyframes десь вживається', () => {
    const nc = stripComments(css)
    const defined = [...nc.matchAll(/@keyframes\s+([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1])
    const used = new Set<string>()
    for (const re of [/animation:\s*([a-zA-Z][a-zA-Z0-9]*)/g, /animation-name:\s*([a-zA-Z][a-zA-Z0-9]*)/g]) {
      for (const m of nc.matchAll(re)) used.add(m[1])
    }
    // Анімації, які вішає JSX інлайн-стилем.
    for (const file of files) {
      if (!file.endsWith('.tsx')) continue
      const txt = stripComments(readFileSync(file, 'utf8'))
      for (const m of txt.matchAll(/animation:\s*['"`]?([a-zA-Z][a-zA-Z0-9]*)/g)) used.add(m[1])
    }
    expect(defined.filter((d) => !used.has(d)), 'невживаний keyframes').toEqual([])
  })
})

// Шкала кольору тексту — це ЧОТИРИ токени (--t1…--t4). Але 13 правил вигадують
// власне біле-з-альфою, і саме тому підняття токенів їх не зачепило: замір
// контрасту показав, що плитки дашборда (`rgba(255,255,255,.48)`) лишались нижче
// WCAG AA, поки їх не перевели на токен. Гард вище цього не ловив — він порівнює
// лише з ІСНУЮЧИМИ значеннями токенів, а .48 не збігалось із .46.
//
// Це базовий знімок відомого боргу: перелічені класи лишаються, НОВІ — падають.
const OWN_TEXT_ALPHA = new Set([
  // Тост і галерея живуть над власним темним тлом, не над градієнтом екрана.
  'toast-s', 'toast-close', 'gallery-info', 'photo-t',
  // Сплеш і hero об'єкта — власна мова над орбом/фото.
  'splash-sub', 'splash-orb-text', 'splash-orb-pct', 'obj-hero-addr', 'obj-hero-photos',
  // Превʼю форматів експорту імітують сам документ, а не інтерфейс.
  'pcard', 'pcard-icon', 'pcard-tag',
  // Неактивна іконка таббару: підняття зменшило б різницю з активною.
  'tab',
])

describe('шкала кольору тексту', () => {
  it('нові правила беруть колір тексту з токена, а не з власної альфи', () => {
    const nc = stripComments(css)
    const found: string[] = []
    for (const m of nc.matchAll(/\.([a-z][a-z0-9-]*)\{[^}]*?color:\s*rgba\(255,\s*255,\s*255,\s*\.?\d+\)/g)) {
      if (!OWN_TEXT_ALPHA.has(m[1])) found.push(m[1])
    }
    expect(found, 'колір тексту має бути var(--t1…--t4) — інакше він випадає зі шкали і з перевірки контрасту').toEqual([])
  })
})
