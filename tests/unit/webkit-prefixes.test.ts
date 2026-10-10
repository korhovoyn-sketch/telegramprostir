import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/**
 * ПРЕФІКСИ, ЯКІ НЕВИДИМІ В CHROMIUM ЗА ПОБУДОВОЮ.
 *
 * Chromium розуміє і `backdrop-filter`, і `-webkit-backdrop-filter`, тож
 * ВІДСУТНІСТЬ префікса він не може показати ЖОДНИМ рантаймовим заміром —
 * ні скріншотом, ні `getComputedStyle`. А в пісочниці й у CI інших рушіїв
 * немає (`/opt/pw-browsers` — самий chromium, `playwright install`
 * заборонений). Тобто цей клас дефектів мусить ловитись ДЖЕРЕЛЬНО, інакше
 * не ловиться взагалі.
 *
 * Ціна — не абстрактна. Safari почав розуміти `backdrop-filter` без
 * префікса лише у 18, тобто на всьому iOS ≤ 17 (а це і Telegram-iOS, і
 * звичайний Safari, у якому сторонні відкривають публічну `/v`) правило без
 * `-webkit-` просто не застосовується: скло стає пласкою напівпрозорою
 * плашкою. Знайдено п'ять таких місць — бейдж статусу на герої, кнопка
 * шарингу поверх фото і лічильник галереї (двічі: у застосунку і на `/v`).
 * Решта 33 входжень префікс мали, тобто це був ДРЕЙФ, а не рішення.
 *
 * `mask-image` тримається тут із тієї ж причини: у Chromium обидві форми
 * працюють, а WebKit довго знав лише префіксну.
 */

const ROOT = join(__dirname, '..', '..', 'src')
const CSS = join(ROOT, 'app', 'globals.css')

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.tsx') || p.endsWith('.ts')) out.push(p)
  }
  return out
}

/** Властивості, які WebKit довго знав ЛИШЕ з префіксом. */
const NEED_PREFIX = ['backdrop-filter', 'mask-image'] as const

describe('префікси WebKit (у Chromium невидимі за побудовою)', () => {
  const css = readFileSync(CSS, 'utf8').split('\n')

  for (const prop of NEED_PREFIX) {
    it(`кожен \`${prop}\` у globals.css має свого \`-webkit-\` сусіда`, () => {
      const webkit = `-webkit-${prop}`
      // Оголошення, а не згадка: властивість, за якою йде двокрапка, і перед
      // якою НЕ стоїть дефіс (інакше сам префікс матчив би себе).
      const decl = new RegExp(String.raw`(?<!-)\b${prop}\s*:`)
      const missing: string[] = []

      css.forEach((line, i) => {
        const code = line.split('/*')[0]
        if (!decl.test(code)) return
        // Префікс може стояти в тому самому рядку (мінімізований блок) або
        // сусіднім — у цьому файлі вживані обидва стилі.
        const near = (css[i - 1] ?? '') + code + (css[i + 1] ?? '')
        if (!near.includes(webkit)) {
          missing.push(`globals.css:${i + 1}  ${code.trim().slice(0, 70)}`)
        }
      })

      expect(missing, `без ${webkit}:\n${missing.join('\n')}`).toEqual([])
    })
  }

  it('кожен інлайновий `backdropFilter` у JSX має `WebkitBackdropFilter`', () => {
    const missing: string[] = []
    for (const file of walk(ROOT)) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, i) => {
        if (!/(?<!Webkit)\bbackdropFilter\s*:/.test(line)) return
        // React не автопрефіксує, тож пара мусить бути в тому ж об'єкті
        // стилю — беремо вікно рядків, бо стиль часто розбитий на кілька.
        const near = lines.slice(Math.max(0, i - 3), i + 3).join('')
        if (!near.includes('WebkitBackdropFilter')) {
          missing.push(`${file.slice(ROOT.length + 1)}:${i + 1}  ${line.trim().slice(0, 70)}`)
        }
      })
    }
    expect(missing, `без WebkitBackdropFilter:\n${missing.join('\n')}`).toEqual([])
  })

  it('АНТИВАКУУМ: гард справді бачить обидві форми запису', () => {
    // Інакше «порушень немає» могло б означати «регекс не матчить нічого».
    const text = readFileSync(CSS, 'utf8')
    const decls = text.match(/(?<!-)\bbackdrop-filter\s*:/g) ?? []
    const prefixed = text.match(/-webkit-backdrop-filter\s*:/g) ?? []
    // 24 на момент написання — поріг із ЗАМІРУ, не з пам'яті: перша
    // редакція стояла на «>30» і впала на власному антивакуумі.
    expect(decls.length).toBeGreaterThan(20)
    expect(prefixed.length).toBe(decls.length)
  })
})
