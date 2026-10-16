import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { thumbBackground } from '@/lib/utils'

/**
 * SHORTHAND `background` ПОРУЧ ІЗ LONGHAND-ОМ В ОДНОМУ ІНЛАЙНОВОМУ СТИЛІ.
 *
 * React для `undefined`/`null`/`''` виставляє властивість у порожній рядок, а
 * `style.background = ''` СКИДАЄ всі `background-*`, задані перед ним. Тобто
 * `{ backgroundImage: url, background: thumb ? undefined : фолбек }` не малює
 * картинку НІКОЛИ — і саме так мініатюри обʼєктів у підбірках роками лишались
 * порожніми квадратами: у рієлтора, у вікні «Додати обʼєкт» і в клієнта, якому
 * підбірку надіслали. Заміряно: `getComputedStyle(...).backgroundImage` —
 * `'none'` при живому URL у пропсах.
 *
 * Рантаймом це видно лише там, де фікстура має фото, тобто майже ніде, тому
 * гард ДЖЕРЕЛЬНИЙ: жоден `style={{…}}` не сміє тримати обидва ключі.
 */

const ROOT = join(__dirname, '..', '..', 'src')

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.tsx')) out.push(p)
  }
  return out
}

/** Тіла всіх `style={{ … }}` — з урахуванням вкладених дужок. */
function styleObjects(src: string): string[] {
  const out: string[] = []
  let i = src.indexOf('style={{')
  while (i !== -1) {
    let depth = 0
    let j = i + 'style='.length
    for (; j < src.length; j++) {
      if (src[j] === '{') depth++
      else if (src[j] === '}') { depth--; if (depth === 0) break }
    }
    out.push(src.slice(i, j + 1))
    i = src.indexOf('style={{', j)
  }
  return out
}

const LONGHAND = /\bbackground(Image|Size|Position|Repeat|Color)\s*:/
const SHORTHAND = /(^|[\s,{])background\s*:/

describe('інлайновий фон', () => {
  const files = walk(ROOT)

  it('жоден style={{}} не змішує `background` із `background*`', () => {
    const bad: string[] = []
    let seen = 0
    for (const f of files) {
      for (const o of styleObjects(readFileSync(f, 'utf8'))) {
        seen++
        if (LONGHAND.test(o) && SHORTHAND.test(o)) bad.push(`${relative(ROOT, f)}: ${o.replace(/\s+/g, ' ').slice(0, 120)}`)
      }
    }
    // Антивакуум: інакше «порушень немає» означало б «парсер нічого не знайшов».
    expect(seen).toBeGreaterThan(200)
    expect(bad).toEqual([])
  })

  it('детектор ловить саме той рецепт, що ламав мініатюри', () => {
    const broken = "style={{ backgroundImage: t ? `url(${t})` : undefined, backgroundSize: 'cover', background: t ? undefined : 'var(--purple-bg)' }}"
    const [o] = styleObjects(broken)
    expect(LONGHAND.test(o) && SHORTHAND.test(o)).toBe(true)
  })

  it('thumbBackground: фото — одним shorthand-ом, без фото — підкладка', () => {
    expect(thumbBackground('https://x/p/1.jpg')).toBe('center / cover no-repeat url("https://x/p/1.jpg")')
    expect(thumbBackground(null)).toBe('var(--purple-bg)')
  })
})
