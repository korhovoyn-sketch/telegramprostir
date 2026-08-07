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
const RUNTIME_TOKENS = new Set(['--keyboard-h', '--tg-vh', '--pw'])

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

  it('криві анімацій живуть у токенах, а не літералами в правилах', () => {
    const nc = stripComments(css)
    const body = nc.slice(nc.indexOf('\n}', nc.indexOf(':root{')))
    const bad = [...body.matchAll(/cubic-bezier\([^)]*\)/g)].map((m) => m[0])
    expect(bad, 'та сама крива має бути --ease*').toEqual([])
  })
})
