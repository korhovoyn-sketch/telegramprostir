import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * КОНТРАКТ RPC ↔ КЛІЄНТ.
 *
 * Три з пʼяти останніх раундів мали дефект саме цього класу, і нічого в репо
 * його не перевіряло: міграція міняє форму JSON, клієнт читає старі ключі,
 * TypeScript мовчить (це `JSONB` з БД, а не типізований рядок), тести мовчать
 * (мок віддає фікстуру, написану під клієнт). Екран просто рендериться
 * порожнім — без падіння, без ErrorBoundary, без жодного сигналу.
 *
 * Найгірший випадок був щойно: 050 перейменувала `type`→`kind`,
 * `database`→`db` і викинула `owner_first`/`status`. Гостьовий екран —
 * ПЕРШИЙ, який бачить запрошена людина — показав би сірий безіменний тайл і
 * обірване речення «…надає вам доступ до:».
 *
 * Гард джерельний за потребою: рантаймом його не закрити, бо e2e ганяються
 * проти мока, а мережі до Supabase з цього середовища немає.
 */

const MIG = resolve(process.cwd(), 'supabase/migrations')
const SRC = resolve(process.cwd(), 'src')

/** Остання (за номером) міграція, що визначає функцію — вона й діє в БД. */
function lastDefinitionOf(fn: string): string {
  const files = readdirSync(MIG).filter((f) => f.endsWith('.sql')).sort()
  let body = ''
  for (const f of files) {
    const src = readFileSync(resolve(MIG, f), 'utf8')
    const at = src.search(new RegExp(`CREATE (OR REPLACE )?FUNCTION ${fn}\\b`))
    if (at === -1) continue
    const end = src.indexOf('$$;', at)
    body = src.slice(at, end === -1 ? undefined : end)
  }
  return body
}

/**
 * Ключі верхнього рівня — ОКРЕМО ПО КОЖНІЙ ГІЛЦІ.
 *
 * Перша версія брала ОБʼЄДНАННЯ і через це була вакуумною: я перейменував
 * `type`→`kind` лише в db-гілці, а гард лишився зеленим, бо `type` далі
 * зустрічався в property-гілці. Але клієнт отримує РІВНО ОДНУ гілку — і
 * порожній екран дає саме та, у якій ключа бракує.
 */
function branchKeys(body: string): Record<string, string>[] {
  const branches: Record<string, string>[] = []
  for (const m of body.matchAll(/SELECT jsonb_build_object\(([\s\S]*?)INTO v_result/g)) {
    const keys: Record<string, string> = {}
    let depth = 0
    for (const line of m[1].split('\n')) {
      if (depth === 0) {
        const k = line.match(/^\s*'([a-z_]+)'\s*,\s*(.*)$/)
        if (k) keys[k[1]] = k[2].trim()
      }
      depth += (line.match(/\(/g) ?? []).length - (line.match(/\)/g) ?? []).length
      if (depth < 0) depth = 0
    }
    branches.push(keys)
  }
  return branches
}

describe('get_guest_property_preview: форма JSON збігається з тим, що читає екран', () => {
  const body = lastDefinitionOf('get_guest_property_preview')

  it('останнє визначення функції знайдено', () => {
    expect(body.length, 'функцію не знайдено — гард застарів').toBeGreaterThan(200)
  })

  const screen = readFileSync(resolve(SRC, 'screens/GuestDatabaseScreen.tsx'), 'utf8')
  // Що екран дістає з відповіді RPC.
  const read = new Set<string>()
  for (const m of screen.matchAll(/guestPreview[?.]*\.([a-z_]+)/g)) read.add(m[1])
  // Ці ключі належать ОДНІЙ гілці кожен — вимагати їх від обох було б
  // неправдою про контракт. Форма реальна така:
  //   лінк на обʼєкт → property
  //   лінк на базу   → database + properties
  const PER_BRANCH = ['property', 'properties', 'database']
  const ALWAYS = [...read].filter((k) => !PER_BRANCH.includes(k))

  it('КОЖНА гілка віддає ключі, які екран читає безумовно', () => {
    const branches = branchKeys(body)
    expect(branches.length, 'гілок не розібрано').toBeGreaterThan(1)
    branches.forEach((keys, i) => {
      const missing = ALWAYS.filter((k) => !(k in keys))
      expect(missing,
        `гілка ${i + 1} не віддає ${missing.join(',')} — екран рендериться порожнім. Є: ${Object.keys(keys).join(',')}`)
        .toEqual([])
    })
  })

  it('гілки віддають рівно ту форму, яку екран розбирає по `type`', () => {
    // `GuestDatabaseScreen` гілкується на `type === 'property'`, тож форма
    // мусить точно відповідати: інакше половина екрана мовчки порожня.
    const shapes = branchKeys(body).map((keys) => ({
      type: (keys.type ?? '').replace(/[',]/g, '').trim(),
      has: PER_BRANCH.filter((k) => k in keys).sort().join('+'),
    }))
    expect(shapes.find((x) => x.type === 'property')?.has,
      'гілка обʼєкта мусить нести саме `property`').toBe('property')
    expect(shapes.find((x) => x.type === 'database')?.has,
      'гілка бази мусить нести `database` і `properties`').toBe('database+properties')
  })

  it('вибірка не порожня — інакше гард вакуумний', () => {
    expect(read.size, 'екран нічого не читає з guestPreview: регекс застарів').toBeGreaterThan(3)
    for (const keys of branchKeys(body)) {
      expect(Object.keys(keys).length, 'ключів у гілці не розібрано').toBeGreaterThan(2)
    }
  })
})
