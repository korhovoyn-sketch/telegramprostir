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
