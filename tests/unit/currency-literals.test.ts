import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Захардкоджений «$» у підписі — баг, який НЕ видно на рев'ю і не видно в
 * тестах поведінки: для власника з USD усе правильно, а власник, який веде
 * ціни в ₴ або € (обидва — підтримувана й перемикана в Профілі опція), бачить
 * чужу валюту.
 *
 * Клас уже ловили на публічній сторінці `/v`, але `ExportScreen` тоді пропустили:
 * він НЕ знав про валюту взагалі — 12 літералів у PDF і XLSX, тобто у
 * ЗАВАНТАЖУВАНОМУ документі («Разом на місяць ($)», «$/добу», `$${total}`).
 * Правило проєкту: символ валюти береться лише з `currencySymbol(user?.currency)`.
 *
 * Гард джерельний СВІДОМО: правило саме по собі джерельне, а рантайм-перевірка
 * вмісту PDF/XLSX коштувала б непропорційно дорого.
 */

// Єдине легальне місце, де символ валюти написаний літералом.
const ALLOWED = new Set(['src/lib/utils.ts'])

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.tsx?$/.test(name)) out.push(p)
  }
  return out
}

/**
 * Прибирає все, де «$» не є символом валюти:
 * коментарі, `${...}`-інтерполяцію і regex-літерали (там `$` — якір кінця рядка).
 */
function stripNonCurrency(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/\$\{/g, '')
    // regex-літерал: /…/flags — достатньо для наших випадків (\.\w+$/, ^…$/i)
    .replace(/\/(?![/*])(?:\\.|\[(?:\\.|[^\]])*\]|[^/\n\\])+\/[gimsuy]*/g, '')
}

describe('символ валюти', () => {
  it('жоден екран не пише «$» літералом — лише currencySymbol(user?.currency)', () => {
    const offenders: string[] = []
    for (const file of walk('src')) {
      if (ALLOWED.has(file)) continue
      const cleaned = stripNonCurrency(readFileSync(file, 'utf8'))
      cleaned.split('\n').forEach((line, i) => {
        if (line.includes('$')) offenders.push(`${file}:${i + 1}  ${line.trim().slice(0, 90)}`)
      })
    }
    expect(offenders, `захардкоджений символ валюти:\n${offenders.join('\n')}`).toEqual([])
  })
})
