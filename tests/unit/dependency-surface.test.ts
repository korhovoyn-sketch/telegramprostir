import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ЧОМУ ЦЕЙ ФАЙЛ ІСНУЄ.
 *
 * Частина advisory не має безпечного фіксу: `xlsx` не має його взагалі, а
 * `next`/`postcss` лікуються лише мажорним стрибком Next. Замість сліпого
 * апгрейду ми ОБҐРУНТУВАЛИ недосяжність — але обґрунтування, зроблене один
 * раз, протухає мовчки.
 *
 * І воно ПРОТУХЛО. Попередня редакція цього докблоку стверджувала «чотири
 * high, жоден не має безпечного фіксу» — а на момент релізного аудиту
 * безпечний (немажорний) фікс мали вже ПʼЯТЬ пакетів, з них три `high`
 * (`browserslist`, `js-yaml`, `sharp`). Тобто твердження було не лише
 * застарілим, а й таким, що виправдовувало бездіяльність там, де діяти було
 * дешево. Advisory-база рухається сама, тож «фіксу немає» — це стан на дату,
 * а не властивість. Тепер за цим стежить крок `npm audit` у CI: він мовчить
 * на відомо-нефіксованих і падає, щойно десь зʼявився безпечний фікс.
 *
 * Тут же лишаються ті умови, на яких тримається висновок «користувача це не
 * стосується» для решти. Зникне умова — впаде тест, і аудит доведеться
 * перепройти свідомо, а не виявити діру постфактум.
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
  it('статичний експорт із вимкненою оптимізацією — Next не обробляє зображення', () => {
    const cfg = readFileSync(resolve(process.cwd(), 'next.config.ts'), 'utf8')
    expect(cfg, 'output більше не `export` — зʼявляється рантайм, а з ним і поверхня sharp/postcss')
      .toMatch(/output\s*:\s*'export'/)
    expect(cfg, 'images.unoptimized знято — Next почне обробляти зображення через sharp')
      .toMatch(/unoptimized\s*:\s*true/)
  })

  /**
   * `vitest`/`@vitest/mocker` — Path Traversal через redirect-мок. Фікс лише
   * мажорний (vitest 5). Недосяжність тут ІНШОГО роду, ніж у решти: це
   * devDependency, тобто в `out/` її немає за побудовою, а вектор вимагає
   * підконтрольного зловмиснику мок-шляху — тобто вже права писати в наші ж
   * тести. Умова, яку тут стережемо, рівно одна: вітест лишається DEV-
   * залежністю і не переповзає в рантайм.
   */
  it('vitest лишається dev-залежністю — у рантайм не потрапляє', () => {
    const pkg = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8'))
    const runtime = Object.keys(pkg.dependencies ?? {})
    expect(runtime.filter((d) => /^(vitest|@vitest\/)/.test(d)),
      'vitest опинився серед dependencies — advisory стає частиною поставки')
      .toEqual([])
  })
})
