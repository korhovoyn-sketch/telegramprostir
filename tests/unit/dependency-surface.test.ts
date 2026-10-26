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
const EDGE = resolve(process.cwd(), 'supabase/functions')

function walk(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name)
    if (e.isDirectory()) walk(p, acc)
    else if (/\.tsx?$/.test(e.name)) acc.push(p)
  }
  return acc
}

/**
 * Схеми-колекції, у яких НЕМАЄ стелі довжини. `.max(` усередині аргументу
 * (на ЕЛЕМЕНТІ: `z.array(z.string().max(5))`) колекцію не обмежує — тому
 * аргумент пропускаємо за дужками й дивимось лише на ланцюг ПІСЛЯ нього.
 */
function unboundedCollections(src: string): string[] {
  const found: string[] = []
  const closeOf = (open: number): number => {
    let depth = 0
    for (let i = open; i < src.length; i++) {
      if (src[i] === '(') depth++
      else if (src[i] === ')' && --depth === 0) return i
    }
    return src.length
  }
  for (const m of src.matchAll(/\bz\.(array|set|record)\s*\(/g)) {
    let i = closeOf(m.index! + m[0].length - 1) + 1
    const chain: string[] = []
    for (;;) {
      const c = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(src.slice(i))
      if (!c) break
      chain.push(c[1])
      i = closeOf(i + c[0].length - 1) + 1
    }
    if (!chain.some((n) => n === 'max' || n === 'length')) {
      found.push(src.slice(m.index!, Math.min(i, m.index! + 80)).replace(/\s+/g, ' '))
    }
  }
  return found
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
   *
   * Та сама умова тримає й залишок advisory самого `next` (DoS через Server
   * Actions, фікс лише в 16.x): у статичному експорті сервера немає взагалі,
   * тож немає й ендпоінта, куди слати такий запит.
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

  /**
   * `zod` — GHSA-mrhx-c7xc-m3w5 (high, 1.10.2026): `z.array` без стелі
   * довжини накопичує по issue на КОЖЕН хибний елемент, без ліміту й без
   * дострокового виходу, тож величезний масив у запиті вичерпує памʼять.
   * Фікс — лише zod 4.6.6, тобто мажор (інший формат помилок, суворіший
   * `.uuid()`), і не напередодні релізу.
   *
   * Досяжність вимагає ДВОХ речей разом: схеми-колекції без стелі і того,
   * що саму колекцію підсовує СТОРОННІЙ. У нас немає жодної такої пари:
   *   * edge-функції — єдине місце, де zod розбирає ЧУЖИЙ ввід (тіло запиту), —
   *     колекцій не мають узагалі. Їхній zod до того ж з esm.sh, а не з
   *     node_modules, тож `npm audit` його НЕ БАЧИТЬ — тим важливіше, щоб умову
   *     тримав тест, а не памʼять;
   *   * клієнт розбирає zod-ом лише відповіді ВЛАСНИХ RPC (по одному рядку):
   *     масив там контролює наш сервер, тобто «напасти» може лише той, хто вже
   *     володіє бекендом, — і поклав би лише вкладку самого користувача.
   */
  it('zod у edge-функціях: жодної колекції без стелі довжини', () => {
    // Позитивний контроль: перевірка розрізняє стелю на ЕЛЕМЕНТІ і на масиві.
    expect(unboundedCollections('z.array(z.string().max(5))')).toHaveLength(1)
    expect(unboundedCollections('z.array(z.string()).min(1).max(50)')).toEqual([])
    expect(unboundedCollections('z.record(z.string(), z.number())')).toHaveLength(1)

    const offenders: string[] = []
    let schemas = 0
    for (const dir of readdirSync(EDGE, { withFileTypes: true })) {
      if (!dir.isDirectory()) continue
      for (const f of walk(resolve(EDGE, dir.name))) {
        const src = readFileSync(f, 'utf8')
        if (!/['"][^'"]*zod@/.test(src)) continue
        schemas += (src.match(/\bz\.object\s*\(/g) ?? []).length
        for (const u of unboundedCollections(src)) offenders.push(`${f.replace(EDGE + '/', '')}: ${u}`)
      }
    }
    // Антивакуум: інакше «колекцій немає» означало б і «схем не знайдено».
    expect(schemas, 'у edge-функціях не знайдено жодної zod-схеми — гард осліп').toBeGreaterThanOrEqual(3)
    expect(offenders,
      'edge-функція розбирає ЧУЖИЙ ввід колекцією без .max() — GHSA-mrhx-c7xc-m3w5 стає досяжним (додай стелю)')
      .toEqual([])
  })

  it('zod на клієнті розбирає лише відповіді власних RPC', () => {
    const users: string[] = []
    for (const f of walk(SRC)) {
      const src = readFileSync(f, 'utf8')
      if (!/(?:from\s+|import\s*\(\s*)['"]zod['"]/.test(src)) continue
      users.push(f.replace(SRC + '/', ''))
      expect(/\.rpc\s*\(/.test(src), `${f.replace(SRC + '/', '')} імпортує zod, але не кличе RPC — що саме він розбирає?`)
        .toBe(true)
    }
    // Список ЗАМОРОЖЕНИЙ свідомо: новий споживач — це нове питання «чий це
    // масив?», і відповісти на нього треба до мерджу, а не після інциденту.
    expect(users.sort(),
      'новий споживач zod: переконайся, що він не розбирає колекцію від користувача чи стороннього (GHSA-mrhx-c7xc-m3w5), і лише тоді додай сюди')
      .toEqual([
        'components/ui/ShareSheet.tsx',
        'hooks/useAuth.ts',
        'screens/PaymentConfirmScreen.tsx',
        'screens/PaymentDueScreen.tsx',
        'screens/QRScannerScreen.tsx',
      ])
  })
})
