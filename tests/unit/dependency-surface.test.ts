import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ЧОМУ ЦЕЙ ФАЙЛ ІСНУЄ.
 *
 * `npm audit` показує чотири `high`, і жоден із них не має безпечного фіксу:
 * `xlsx` фікса не має взагалі, а `next`/`postcss`/`sharp` лікуються лише
 * мажорним стрибком Next. Замість сліпого апгрейду ми ОБҐРУНТУВАЛИ
 * недосяжність — але обґрунтування, зроблене один раз, протухає мовчки.
 *
 * Тут стоять рівно ті умови, на яких тримається висновок «користувача це не
 * стосується». Зникне умова — впаде тест, і аудит доведеться перепройти
 * свідомо, а не виявити діру постфактум.
 */

const SRC = resolve(process.cwd(), 'src')

function walk(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name)
    if (e.isDirectory()) walk(p, acc)
    else if (/\.tsx?$/.test(e.name)) acc.push(p)
  }
  return acc
}

describe('поверхня вразливих залежностей лишається недосяжною', () => {
  /**
   * `xlsx` — Prototype Pollution in sheetJS, фікса НЕМАЄ. Вразливість живе в
   * ПАРСИНГУ: щоб її дістати, треба згодувати бібліотеці чужий файл. Ми лише
   * ГЕНЕРУЄМО книгу з власних даних, тож недосяжно. Щойно зʼявиться читання —
   * недосяжність зникає, і цей тест мусить це показати.
   */
  it('xlsx використовується лише на ЗАПИС — жодного парсингу чужих файлів', () => {
    const offenders: string[] = []
    for (const f of walk(SRC)) {
      const src = readFileSync(f, 'utf8')
      if (!/xlsx/i.test(src)) continue
      // `XLSX.read`, `XLSX.readFile`, а також деструктуризований `read(`
      if (/\bXLSX\s*\.\s*read(File)?\s*\(/.test(src) || /\bread(File)?\s*\(\s*[^)]*\/\*\s*xlsx/.test(src)) {
        offenders.push(f.replace(SRC + '/', ''))
      }
    }
    expect(offenders,
      'xlsx почав ЧИТАТИ файли — advisory Prototype Pollution стає досяжним, а фікса для нього немає')
      .toEqual([])
  })

  /**
   * `sharp` (CVE в libvips) підтягується Next-ом для оптимізації зображень.
   * У статичному експорті з `images.unoptimized` вона вимкнена, тобто sharp не
   * викликається взагалі — і в `out/` його немає. Обидві умови мусять
   * лишатись, інакше вразлива обробка зображень оживає.
   */
  it('статичний експорт із вимкненою оптимізацією — sharp не викликається', () => {
    const cfg = readFileSync(resolve(process.cwd(), 'next.config.ts'), 'utf8')
    expect(cfg, 'output більше не `export` — зʼявляється рантайм, а з ним і поверхня sharp/postcss')
      .toMatch(/output\s*:\s*'export'/)
    expect(cfg, 'images.unoptimized знято — Next почне обробляти зображення через sharp')
      .toMatch(/unoptimized\s*:\s*true/)
  })
})
