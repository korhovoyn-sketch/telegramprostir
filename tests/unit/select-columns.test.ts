import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * КОЛОНКА, ЯКОЇ НЕМА В SELECT, — ЦЕ КОЛОНКА, ЯКУ РЕДАГУВАННЯ СТИРАЄ.
 *
 * Дефект, заради якого це написано: `PROPERTY_COLUMNS` не містив
 * `parking_type` і `ev_charger`. Форма префілиться з рядка ЦЬОГО select-а, тож
 * вони приходили `undefined` → поля скидались у порожнє → PATCH писав `null`.
 * Створення працювало, тобто бив дефект саме по редагуванню вже заповненого
 * паркінга, і тост казав «Збережено».
 *
 * ЧОМУ ЦЬОГО НЕ БАЧИВ ЖОДЕН З 296 E2E. Мок-харнес НЕ читає параметр `select=`
 * — він повертає фікстуру цілком, з усіма полями. Тобто набір структурно
 * СЛІПИЙ до пропущеної колонки: код бере її з відповіді, якої в проді не буде.
 * Рантаймом це не закрити, поки харнес не почне проєктувати рядок через
 * `select=`; доти правда живе в джерелі.
 *
 * Правило: кожна колонка, яку форма ПИШЕ, мусить бути в списку, яким її
 * ЧИТАЮТЬ. Інакше редагування — це тихе стирання.
 */

const SRC = resolve(process.cwd(), 'src')
const read = (rel: string) => readFileSync(resolve(SRC, rel), 'utf8')

/** Усі .ts/.tsx під src — спільний обхід для гардів нижче. */
function walk(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name)
    if (e.isDirectory()) walk(p, acc)
    else if (/\.tsx?$/.test(e.name)) acc.push(p)
  }
  return acc
}


/** Колонки, які `PropertyFormScreen` кладе в payload. */
function writtenColumns(): string[] {
  const src = read('screens/PropertyFormScreen.tsx')
  const start = src.indexOf('const payload = {')
  expect(start, 'payload форми не знайдено — тест застарів').toBeGreaterThan(-1)
  const body = src.slice(start, src.indexOf('\n    }', start))
  return [...body.matchAll(/^\s{6}([a-z_]+):/gm)].map((m) => m[1])
}

describe('SELECT покриває все, що пише форма', () => {
  const written = writtenColumns()

  it('payload форми розібрано', () => {
    expect(written.length, 'колонок у payload підозріло мало').toBeGreaterThan(15)
    expect(written).toContain('parking_type')
    expect(written).toContain('ev_charger')
  })

  it('кожна записувана колонка є у PROPERTY_COLUMNS', () => {
    const hooks = read('hooks/useProperties.ts')
    const block = hooks.slice(hooks.indexOf('PROPERTY_COLUMNS = `'), hooks.indexOf('`', hooks.indexOf('PROPERTY_COLUMNS = `') + 22))
    const selected = block.split('`')[1].split(',').map((c) => c.trim()).filter(Boolean)

    // `db_id` форма пише при створенні, але воно ключ, не редаговане поле.
    const missing = written.filter((c) => !selected.includes(c))
    expect(missing,
      'форма ПИШЕ ці колонки, але READ-select їх не тягне: редагування зітре їх у null')
      .toEqual([])
  })

  /**
   * ДРУГИЙ, НЕЗАЛЕЖНИЙ список колонок `properties` живе в `ExportScreen` —
   * гард вище його не бачив, бо читає лише `hooks/useProperties.ts`. Тобто два
   * списки могли розходитись вільно, а це рівно той клас, заради якого гард і
   * писався.
   *
   * Тут інша ціна помилки, ніж у формі: не «редагування зітре в null», а
   * «поле в документі порожнє», причому мовчки — власник надсилає файл
   * клієнту, не знаючи, що там дірка. Тому питання те саме: чи кожна колонка,
   * яку експорт ЧИТАЄ, є в його ВЛАСНІЙ вибірці.
   */
  it('кожна колонка, яку читає ExportScreen, є в його власному select', () => {
    const src = read('screens/ExportScreen.tsx')

    const sel = src.slice(src.indexOf(".select('id,db_id,owner_id,name,floor"))
    const selected = sel.slice(sel.indexOf("'") + 1, sel.indexOf("')"))
      .replace(/photos:property_photos\([^)]*\)/, 'photos')
      .split(',').map((c) => c.trim()).filter(Boolean)

    // Читання виду `p.<колонка>` у тілі документа. Похідні/обчислені поля не
    // є колонками й перелічені явно — інакше гард сварився б на власні
    // проміжні значення.
    const DERIVED = new Set(['photos', 'id', 'rent', 'utils', 'total', 'length', 'map', 'filter'])
    const readCols = new Set<string>()
    for (const m of src.matchAll(/\bp\.([a-z][a-z0-9_]*)\b/g)) {
      const col = m[1]
      if (!col.includes('_') && !selected.includes(col)) continue // p.name, p.status — теж колонки
      if (!DERIVED.has(col)) readCols.add(col)
    }

    const missing = [...readCols].filter((c) => !selected.includes(c))
    expect(missing,
      'ExportScreen ЧИТАЄ ці колонки, але свій select їх не тягне — у документі буде порожньо')
      .toEqual([])
  })
})

describe('токен шарингу не роздається ширше, ніж треба', () => {


  it("жоден select('*') не читає таблицю з share_token", () => {
    // `share_token` — це ПУБЛІЧНИЙ /v-лінк. Відданий рієлторові чи гостю, він
    // переживає відписку й відкликання доступу: ротації токенів при цьому
    // ніхто не робить. `select('*')` на properties/databases/collections
    // роздає його мовчки.
    const TOKENED = /\.from\(\s*['"](properties|databases|collections)['"]\s*\)/
    // Виняток позначається МАРКЕРОМ У КОДІ, а не номером рядка й не іменем
    // файла. Номери зʼїжджають від будь-якої сусідньої правки (уже зʼїхали за
    // один раунд), а файловий виняток мовчки амністує все майбутнє в тому
    // файлі — саме те, від чого застерігає `mutation-discipline`.
    const OK_MARK = /idor-ok:/
    const offenders: string[] = []
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8')
      const lines = src.split('\n')
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        // Коментарі не є запитами — інакше гард ловить власне пояснення.
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue
        if (!/\.select\(\s*['"`]\s*\*/.test(line) && !/\(\*/.test(line)) continue
        // Дивимось назад на кілька рядків — `.from(...)` зазвичай вище.
        const ctx = lines.slice(Math.max(0, i - 4), i + 1).join('\n')
        if (TOKENED.test(ctx) || /properties\(\*|databases\(\*|collections\(\*/.test(line)) {
          // Маркер шукаємо у трьох рядках над запитом — саме там живе причина.
          const near = lines.slice(Math.max(0, i - 4), i + 1).join('\n')
          if (OK_MARK.test(near)) continue
          offenders.push(`${file.replace(SRC + '/', '')}:${i + 1} — ${line.trim().slice(0, 70)}`)
        }
      }
    }
    expect(offenders, "select('*') на таблиці з share_token роздає публічний лінк").toEqual([])
  })
})

describe('порядок фото визначає обкладинку', () => {
  it('withSortedPhotos ставить sort_order 0 першим незалежно від порядку в масиві', async () => {
    const { withSortedPhotos } = await import('../../src/lib/utils')
    const row = { photos: [
      { id: 'c', storage_path: 'c.jpg', sort_order: 2 },
      { id: 'a', storage_path: 'a.jpg', sort_order: 0 },
      { id: 'b', storage_path: 'b.jpg', sort_order: 1 },
    ] }
    expect(withSortedPhotos(row).photos.map((p) => p.id)).toEqual(['a', 'b', 'c'])
  })

  it('не мутує вхідний рядок', async () => {
    const { withSortedPhotos } = await import('../../src/lib/utils')
    const photos = [{ sort_order: 2 }, { sort_order: 0 }]
    const row = { photos }
    withSortedPhotos(row)
    expect(row.photos[0].sort_order, 'оригінал змінено — оптимістичні відкати поїдуть').toBe(2)
  })

  it('нульовий і одиничний масив проходять без роботи', async () => {
    const { withSortedPhotos } = await import('../../src/lib/utils')
    const one = { photos: [{ sort_order: 5 }] }
    expect(withSortedPhotos(one)).toBe(one)
    expect(withSortedPhotos({ photos: [] }).photos).toEqual([])
  })

  it('відсутній sort_order трактується як 0, а не як NaN', async () => {
    const { withSortedPhotos } = await import('../../src/lib/utils')
    const row = { photos: [{ id: 'x', sort_order: 1 }, { id: 'y', sort_order: null }] }
    expect(withSortedPhotos(row).photos.map((p) => p.id)).toEqual(['y', 'x'])
  })
})

/**
 * СПРАВЖНІЙ ІНВАРІАНТ — не «немає `select('*')`», а «токен не їде НЕ-ВЛАСНИКУ».
 *
 * Перевірка вище ловила лише зірочку — і пропустила ЯВНИЙ список колонок, що
 * називає `share_token` поіменно. Саме так витік до редактора команди пережив
 * раунд, у якому його «виправили»: те саме читання в `RealtorDashboardScreen`
 * полагодили, а головне, в `useDatabases`, лишили. Гард звітував зелене про
 * той самий клас, заради якого писався.
 *
 * `share_token` — це публічний /v-лінк. Відданий рієлторові, гостю чи
 * редакторові, він переживає відписку й відкликання доступу (ротації ніхто не
 * робить), а SWR-снапшот кладе його ще й у localStorage.
 */
describe('share_token не потрапляє до не-власника', () => {
  it('кожен select із share_token або owner-скоупний, або має маркер', () => {
    const offenders: string[] = []
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8')
      const lines = src.split('\n')
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue
        if (!/share_token/.test(line)) continue
        // Тільки рядки-запити: константи-списки колонок перевіряються за
        // місцем ВЖИВАННЯ, інакше сам `DB_COLUMNS` вважався б порушенням.
        if (!/\.select\s*\(|DB_COLUMNS\s*=|PROPERTY_COLUMNS\s*=|COLUMNS\s*=/.test(line)) continue
        if (!/\.select\s*\(/.test(line)) continue
        // Власник читає СВОЄ — це і є легальний випадок.
        const ctx = lines.slice(i, Math.min(lines.length, i + 6)).join('\n')
        if (/\.eq\(\s*['"]owner_id['"]\s*,\s*user/.test(ctx)) continue
        const near = lines.slice(Math.max(0, i - 4), i + 1).join('\n')
        if (/idor-ok:/.test(near)) continue
        offenders.push(`${file.replace(SRC + '/', '')}:${i + 1} — ${line.trim().slice(0, 70)}`)
      }
    }
    expect(offenders, 'share_token у запиті без owner-скоупу і без маркера').toEqual([])
  })

  it('member-бази читаються БЕЗ токена', () => {
    // Прицільно на місце, де витік прожив цілий раунд: у `useDatabases`
    // member-гілка мусить брати окремий список колонок.
    const src = readFileSync(resolve(SRC, 'hooks/useDatabases.ts'), 'utf8')
    const memberList = src.match(/const DB_COLUMNS_MEMBER = '([^']+)'/)
    expect(memberList, 'окремого списку для member-баз немає').toBeTruthy()
    expect(memberList![1], 'member-список тягне токен власника').not.toContain('share_token')

    const call = src.slice(src.indexOf(".in('id', memberIds)") - 400, src.indexOf(".in('id', memberIds)"))
    expect(call, 'member-запит бере повний список із токеном').toContain('DB_COLUMNS_MEMBER')
  })
})

/**
 * ОБКЛАДИНКА — ЦЕ `photos[0]`, ТОБТО ПОРЯДОК МАСИВУ.
 *
 * PostgREST не гарантує порядок вбудованого відношення, тож кожен шлях, що
 * кладе рядок обʼєкта у стор, мусить пройти його через `withSortedPhotos`.
 * Пропущений шлях не падає й не помітний у тестах — просто на героєві колись
 * зʼявляється інше фото.
 *
 * Знайдено ревʼю: оптимістична гілка `updateProperty` лишилась без сортування,
 * хоч сусідня (8 рядків нижче) його отримала. Досяжна вона зі «Здати в
 * оренду» / «Звільнити обʼєкт» / undo — тобто зі звичайного перемикання
 * статусу.
 */
describe('порядок фото на кожному шляху в стор', () => {
  it('кожен `one<Property>(data)` загорнутий у withSortedPhotos', () => {
    const src = readFileSync(resolve(SRC, 'hooks/useProperties.ts'), 'utf8')
    const bare: string[] = []
    src.split('\n').forEach((line, i) => {
      if (!/one<Property>\(data\)/.test(line)) return
      if (/withSortedPhotos\(\s*one<Property>\(data\)\s*\)/.test(line)) return
      bare.push(`hooks/useProperties.ts:${i + 1} — ${line.trim().slice(0, 70)}`)
    })
    expect(bare, 'рядок обʼєкта їде у стор із несортованими фото — обкладинка попливе')
      .toEqual([])
  })

  it('вибірка не порожня — інакше гард вакуумний', () => {
    const src = readFileSync(resolve(SRC, 'hooks/useProperties.ts'), 'utf8')
    expect((src.match(/one<Property>\(data\)/g) ?? []).length,
      'жодного входження не знайдено: назва хелпера змінилась').toBeGreaterThan(1)
  })
})
