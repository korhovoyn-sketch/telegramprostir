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
