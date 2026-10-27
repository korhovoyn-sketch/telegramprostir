import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ПЕРИМЕТР ФУНКЦІЙ ОПИСАНИЙ ТРИЧІ — і мусить бути описаний однаково.
 *
 * 075 закриває anon усе, крім allowlist-а; `scripts/verify-behaviour.sql`
 * перевіряє це на стенді; рядки 70–71 `verify_release.sql` — у проді. Три
 * копії списку розходяться за один раунд, і тоді котрась перевірка мовчки
 * пропускає те, що інша вважає дірою (або навпаки — вимагає закрити
 * функцію, яку кличуть політики, і кладе анонімні запити помилкою).
 *
 * Рантаймом цього не звірити: кожна з трьох перевірок на своїй базі зелена
 * і з розійденим списком.
 */
const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8')
const stripComments = (sql: string) => sql.replace(/--[^\n]*/g, '')

/** Списки імен у `proname <op> ( 'a', 'b' … )`, з балансом дужок. */
function nameLists(sql: string, op: 'IN' | 'NOT IN'): string[][] {
  const src = stripComments(sql)
  const re = op === 'IN' ? /proname\s+IN\s*\(/g : /proname\s+NOT\s+IN\s*\(/g
  const out: string[][] = []
  for (const m of src.matchAll(re)) {
    const open = m.index! + m[0].length - 1
    let depth = 0
    let end = src.length
    for (let i = open; i < src.length; i++) {
      if (src[i] === '(') depth++
      else if (src[i] === ')' && --depth === 0) { end = i; break }
    }
    out.push([...src.slice(open, end).matchAll(/'([a-z_]+)'/g)].map((x) => x[1]).sort())
  }
  return out
}

const MIG = read('supabase/migrations/075_function_acl_supabase_defaults.sql')
const STAND = read('scripts/verify-behaviour.sql')
const PROD = read('supabase/verify_release.sql')

describe('периметр функцій: 075, стенд і прод питають про ОДНЕ', () => {
  it('allowlist anon однаковий у міграції, на стенді й у verify_release', () => {
    const mig = nameLists(MIG, 'NOT IN')
    const stand = nameLists(STAND, 'NOT IN').filter((l) => l.includes('get_public_db_preview'))
    const prod = nameLists(PROD, 'NOT IN').filter((l) => l.includes('get_public_db_preview'))
    // Антивакуум: інакше «однакові» означало б і «не знайдено жодного».
    expect(mig, 'у 075 не знайдено allowlist-а anon').toHaveLength(1)
    expect(stand, 'у verify-behaviour не знайдено allowlist-а anon').toHaveLength(1)
    expect(prod, 'у verify_release не знайдено allowlist-а anon').toHaveLength(1)
    expect(mig[0].length, 'allowlist підозріло короткий — парсер осліп').toBeGreaterThanOrEqual(10)
    expect(stand[0], 'стенд і 075 розійшлись у тому, що anon дозволено').toEqual(mig[0])
    expect(prod[0], 'verify_release і 075 розійшлись у тому, що anon дозволено').toEqual(mig[0])
  })

  it('службовий список однаковий у міграції, на стенді й у verify_release', () => {
    // Ключ вибору — ОБИДВІ функції разом: лише повний службовий список має і
    // `mark_overdue_payments` (052), і `log_db_activity` (073). За кожною
    // окремо знаходяться й інші списки — рядок 052 у verify_release,
    // антивакуумна пара на стенді, — і вибір «першого» залежав би від порядку
    // перевірок у файлі.
    const pick = (sql: string) => nameLists(sql, 'IN')
      .filter((l) => l.includes('mark_overdue_payments') && l.includes('log_db_activity'))
    const [mig, stand, prod] = [pick(MIG), pick(STAND), pick(PROD)]
    expect(mig, 'у 075 не знайдено службового списку').toHaveLength(1)
    expect(stand, 'у verify-behaviour має бути рівно один службовий список').toHaveLength(1)
    expect(prod, 'у verify_release не знайдено службового списку').toHaveLength(1)
    expect(mig[0]).toContain('get_due_lease_reminders')
    expect(stand[0], 'стенд і 075 розійшлись у службових функціях').toEqual(mig[0])
    expect(prod[0], 'verify_release і 075 розійшлись у службових функціях').toEqual(mig[0])
  })
})
