import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'

/**
 * Рух і поле вводу — те, чого рантайм у Chromium не покаже.
 *
 * Анімація `left`/`box-shadow` у headless виглядає так само плавно, як
 * `transform`: композитор Chromium вибачає те, що на iOS перемальовує сцену
 * щокадру. Тож тут — ДЖЕРЕЛО: що саме анімується.
 */

const root = path.resolve(__dirname, '../..')
const read = (p: string) => fs.readFileSync(path.join(root, p), 'utf8')
const noComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '')

/** Тіла `@keyframes` з урахуванням вкладених дужок. */
function keyframes(css: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  const re = /@keyframes\s+([\w-]+)\s*\{/g
  let m: RegExpExecArray | null
  while ((m = re.exec(css))) {
    let i = re.lastIndex, depth = 1
    while (depth && i < css.length) {
      if (css[i] === '{') depth++
      else if (css[i] === '}') depth--
      i++
    }
    const body = css.slice(re.lastIndex, i - 1)
    const props = new Set([...body.matchAll(/(?:^|[{;\s])([a-z-]+)\s*:/g)].map((x) => x[1]))
    out.set(m[1], props)
  }
  return out
}

const SOURCES = ['src/app/globals.css', 'src/app/v/page.tsx']

describe('@keyframes рухають лише композиторні властивості', () => {
  it('transform і opacity — і нічого іншого', () => {
    // `left` у сяйві кнопки /v перераховував лейаут КОЖЕН кадр, безкінечно;
    // `box-shadow` у кільці фокуса перемальовував поле на кожен тап. Обидва
    // в Chromium виглядали плавно — помітно лише на iOS.
    const bad: string[] = []
    let total = 0
    for (const f of SOURCES) {
      for (const [name, props] of keyframes(noComments(read(f)))) {
        total++
        const extra = [...props].filter((p) => p !== 'transform' && p !== 'opacity')
        if (extra.length) bad.push(`${f}: ${name} → ${extra.join(', ')}`)
      }
    }
    expect(bad).toEqual([])
    // антивакуум: розбір справді бачить анімації обох файлів
    expect(total).toBeGreaterThan(40)
    expect(keyframes(noComments(read('src/app/v/page.tsx'))).has('vSheen')).toBe(true)
  })
})

describe('фокус поля', () => {
  it('жодної анімації на :focus поля — тап не сміє малювати рамку', () => {
    // `inputRing` гнав box-shadow навколо САМОГО інпута на кожен тап: синій
    // прямокутник поверх рядка форми, що зникав за .42s. Фокус показує рядок
    // (`.fr:focus-within`), а не поле.
    const css = noComments(read('src/app/globals.css'))
    const rules = [...css.matchAll(/([^{}]*:focus[^{}]*)\{([^}]*)\}/g)]
      .filter(([, sel, body]) => /\b(input|textarea|\.fr-i|\.fr-textarea)\b/.test(sel) && /animation\s*:/.test(body))
      .map(([, sel]) => sel.trim())
    expect(rules).toEqual([])
    expect(css).toMatch(/\.fr:focus-within\{/)
  })
})

describe('автозаповнення', () => {
  it('підкладка браузера не перефарбовує поле в світле', () => {
    const css = noComments(read('src/app/globals.css'))
    const rule = css.match(/input:-webkit-autofill[^{]*\{([^}]*)\}/)
    expect(rule, 'правила для :-webkit-autofill немає').not.toBeNull()
    expect(rule![1]).toMatch(/-webkit-text-fill-color:\s*var\(--t1\)/)
    expect(rule![1]).toMatch(/transition:\s*background-color\s+\d{5,}s/)
    // reduced-motion гасить УСІ переходи — без окремого винятку там підкладка
    // повертається саме в тих, хто вимкнув рух.
    expect(css).toMatch(/input:-webkit-autofill\s*\{\s*transition-duration:\s*\d{5,}s\s*!important/)
  })

  it('поля контактів кажуть браузеру, ЩО в них', () => {
    const missing: string[] = []
    const walk = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name)
        if (e.isDirectory()) walk(p)
        else if (p.endsWith('.tsx')) {
          const s = fs.readFileSync(p, 'utf8')
          for (const m of s.matchAll(/<input\b[^>]*?type="(email|tel)"[^>]*?\/?>/g)) {
            if (!new RegExp(`autoComplete="${m[1]}"`).test(m[0])) missing.push(`${path.relative(root, p)}: type="${m[1]}"`)
          }
        }
      }
    }
    walk(path.join(root, 'src'))
    expect(missing).toEqual([])
  })
})

describe('перехід між екранами', () => {
  it('напрямок живе на КОРЕНІ екрана, а не на обгортці', () => {
    // Обгортка по X + `.scr` по Y = діагональ і два входи поспіль (заміряно).
    const css = noComments(read('src/app/globals.css'))
    expect(css).not.toMatch(/(^|\})\s*\.nav-(forward|back|root)\s*\{[^}]*animation/)
    expect(css).not.toMatch(/(^|\})\s*\.scr\s*\{[^}]*animation\s*:\s*screenEnter/)
    expect(css).toMatch(/\.nav-wrap\.nav-forward > \*\{animation:navRight/)
    expect(css).toMatch(/\.nav-wrap > \.scr-wait\{animation:none\}/)
    // заглушка без власного фону — інакше спалах чужого кольору
    const page = read('src/app/page.tsx')
    expect(page).toMatch(/className="scr scr-wait"/)
  })
})

describe('заповнення анімацій', () => {
  it('`forwards`/`both` лише там, де кінцевий кадр ≠ природний стан', () => {
    // Вхід із `both` назавжди тримав transform, і `:active{transform:scale()}`
    // мовчав на картках, рядках і плитках — анімація в каскаді бʼє звичайні
    // оголошення. Те саме зупиняло шит під пальцем.
    const ALLOWED = new Map([
      ['orbRise', 'частинка зникає — природний стан видимий'],
      ['btnPress', 'живе лише поки :active'],
      ['modalSlideDown', 'виїзд — тримає до розмонтування'],
      ['overlayFadeOut', 'виїзд — тримає до розмонтування'],
    ])
    const bad: string[] = []
    for (const f of SOURCES) {
      const css = noComments(read(f))
      for (const m of css.matchAll(/animation\s*:\s*([\w-]+)([^;}]*)/g)) {
        if (/\b(both|forwards)\b/.test(m[2]) && !ALLOWED.has(m[1])) bad.push(`${f}: ${m[1]}${m[2]}`)
      }
    }
    expect(bad).toEqual([])
    // антивакуум: розбір бачить і дозволені випадки
    expect(noComments(read('src/app/globals.css'))).toMatch(/animation:orbRise[^;}]*\bboth\b/)
  })
})
