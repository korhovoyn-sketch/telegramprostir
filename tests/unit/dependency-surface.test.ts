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
   * ІНСТРУМЕНТИ ЗБІРКИ Й ТЕСТІВ — недосяжність ІНШОГО роду, ніж у решти: вони
   * devDependencies, тобто в `out/` їх немає за побудовою, а кожен вектор
   * живиться НАШИМ ЖЕ вводом (конфіг, CSS, тести). Дістати його означає вже
   * мати право писати в репозиторій. Фікс у всіх лише мажорний:
   *
   * | пакет | advisory | фікс |
   * |---|---|---|
   * | `vitest` (+ `tinypool`, `@vitest/mocker`) | Path Traversal у redirect-моку; **critical**: Prototype Pollution → RCE в опціях воркера | vitest 5 |
   * | `tailwindcss` (+ `braces`, `micromatch`, `chokidar`, `postcss-selector-parser`, `postcss-nested`) | ReDoS/stack exhaustion на глобах `content`, квадратичний парс селекторів | tailwind 4 |
   * | `eslint-config-next` (+ `fast-glob`, `@next/eslint-plugin-next`) | ті самі глоби — лише під час лінту | 14 → мажор |
   *
   * `tinypool` позначений critical, і саме тому тут стоїть таблиця, а не
   * «dev — отже байдуже»: RCE-гаджет вимагає підконтрольних опцій воркера, а
   * їх задає раннер із наших тестів. Умов, на яких це тримається, дві: пакет
   * НЕ переповзає в `dependencies` і `src/` НЕ імпортує його — інакше код
   * інструмента опиняється в бандлі.
   *
   * Пастка заміру, наступана при першому ж аудиті після мерджу: npm 10 (Node
   * 22 у пісочниці) звітує `postcss-nested` як `fixAvailable: true`, хоч
   * `npm audit fix` не міняє lockfile — 8.x поза діапазоном `tailwindcss@3`
   * (`^6.2.0`). npm 11 (Node 24, як у CI) це не бреше. Крок у CI правий; на
   * локальний `npm audit` під іншою мажорною Node не спиратися.
   */
  const DEV_ONLY = [/^vitest$/, /^@vitest\//, /^tailwindcss$/, /^eslint-config-next$/]
  const pkg = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8'))

  it('інструменти з advisory лишаються dev-залежностями', () => {
    const runtime = Object.keys(pkg.dependencies ?? {})
    expect(runtime.filter((d) => DEV_ONLY.some((re) => re.test(d))),
      'інструмент збірки/тестів опинився серед dependencies — advisory стає частиною поставки')
      .toEqual([])
    // Антивакуум: список описує те, що СПРАВДІ стоїть. Пакет, якого вже немає,
    // мусить піти й з таблиці вище — інакше обґрунтування знову протухне мовчки.
    const dev = Object.keys(pkg.devDependencies ?? {})
    for (const re of DEV_ONLY) {
      expect(dev.some((d) => re.test(d)), `${re} більше немає в devDependencies — прибери з DEV_ONLY і з таблиці`)
        .toBe(true)
    }
  })

  it('src/ не імпортує інструменти збірки — їхній код не потрапляє в бандл', () => {
    const offenders: string[] = []
    for (const f of walk(SRC)) {
      const src = readFileSync(f, 'utf8')
      for (const m of src.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"]([^'"]+)['"]/g)) {
        const name = m[1].startsWith('@') ? m[1].split('/').slice(0, 2).join('/') : m[1].split('/')[0]
        if (DEV_ONLY.some((re) => re.test(name))) offenders.push(`${f.replace(SRC + '/', '')} → ${m[1]}`)
      }
    }
    expect(offenders, 'рантайм-код тягне інструмент збірки — він опиниться в out/ разом зі своїми advisory')
      .toEqual([])
  })
})
