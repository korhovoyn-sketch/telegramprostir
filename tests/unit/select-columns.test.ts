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
})

describe('токен шарингу не роздається ширше, ніж треба', () => {
  function walk(dir: string, acc: string[] = []): string[] {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = resolve(dir, e.name)
      if (e.isDirectory()) walk(p, acc)
      else if (/\.tsx?$/.test(e.name)) acc.push(p)
    }
    return acc
  }

  it("жоден select('*') не читає таблицю з share_token", () => {
    // `share_token` — це ПУБЛІЧНИЙ /v-лінк. Відданий рієлторові чи гостю, він
    // переживає відписку й відкликання доступу: ротації токенів при цьому
    // ніхто не робить. `select('*')` на properties/databases/collections
    // роздає його мовчки.
    const TOKENED = /\.from\(\s*['"](properties|databases|collections)['"]\s*\)/
    // Виняток СЕМАНТИЧНИЙ, не файловий: рядок читає ВЛАСНІ підбірки рієлтора
    // (`.eq('realtor_id', user.id)`), тож `share_token` там — його власний, і
    // він потрібен, щоб ділитись. Витік — це чужий токен, а не свій.
    const OWN_DATA = [
      "screens/CollectionsScreen.tsx:488",
    ]
    const offenders: string[] = []
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8')
      const lines = src.split('\n')
      lines.forEach((line, i) => {
        if (!/\.select\(\s*['"`]\s*\*/.test(line) && !/\(\*\)/.test(line)) return
        // Дивимось назад на кілька рядків — `.from(...)` зазвичай вище.
        const ctx = lines.slice(Math.max(0, i - 4), i + 1).join('\n')
        if (TOKENED.test(ctx) || /properties\(\*\)|databases\(\*\)|collections\(\*\)/.test(line)) {
          const at = `${file.replace(SRC + '/', '')}:${i + 1}`
          if (!OWN_DATA.includes(at)) offenders.push(`${at} — ${line.trim().slice(0, 70)}`)
        }
      })
    }
    expect(offenders, "select('*') на таблиці з share_token роздає публічний лінк").toEqual([])
  })
})
