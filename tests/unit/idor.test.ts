import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ДЖЕРЕЛЬНИЙ ГАРД НА IDOR.
 *
 * Класика цього застосунку: авторизація стоїть в ОДНІЙ функції, а дані віддає
 * ІНША. `lookup_shared_collection(p_token)` перевіряла токен і повертала id,
 * після чого `get_shared_collection(p_collection_id UUID)` — SECURITY DEFINER,
 * виданий `anon` — віддавала вміст підбірки БЕЗ жодної перевірки токена. Тобто
 * перевірку можна було просто обминути, викликавши другу напряму публічним
 * anon-ключем, який за задумом лежить у клієнтському бандлі.
 *
 * Правило, яке тримає цей файл: **SECURITY DEFINER функція, доступна anon,
 * не має права приймати UUID як ключ доступу.** Ключем може бути лише
 * нездогадний share-токен (TEXT) — або функція мусить сама звірити
 * `current_app_user_id()` з власником рядка.
 *
 * Рантаймом це не закрити: e2e ганяються проти мок-бекенда, тож реальні GRANT
 * і тіла функцій там не існують.
 */

const DIR = resolve(process.cwd(), 'supabase/migrations')
const FILES = readdirSync(DIR).filter((f) => f.endsWith('.sql')).sort()
const ALL = FILES.map((f) => readFileSync(resolve(DIR, f), 'utf8')).join('\n')

/** Останнє слово про функцію — за найпізнішою міграцією, що її згадує. */
function lastMentionFile(name: string): string | null {
  for (let i = FILES.length - 1; i >= 0; i--) {
    if (readFileSync(resolve(DIR, FILES[i]), 'utf8').includes(name)) return FILES[i]
  }
  return null
}

describe('IDOR: RPC, доступні anon', () => {
  it('жодна anon-функція не приймає UUID як ключ доступу', () => {
    // GRANT ... TO ... anon ... — збираємо сигнатури.
    const granted = [...ALL.matchAll(/GRANT EXECUTE ON FUNCTION\s+([a-z_]+)\(([^)]*)\)\s+TO\s+([^;]+);/gi)]
      .filter((m) => /\banon\b/.test(m[3]))
      .map((m) => ({ name: m[1], args: m[2].trim() }))

    expect(granted.length, 'жодного GRANT ... TO anon не знайдено — регекс застарів')
      .toBeGreaterThan(0)

    const offenders = granted
      .filter((g) => /\bUUID\b/i.test(g.args))
      // Функція, чий GRANT ще стоїть, але саму її дропнули пізнішою міграцією,
      // порушенням не є — діри в БД немає.
      .filter((g) => !new RegExp(`DROP FUNCTION IF EXISTS ${g.name}\\(`, 'i').test(ALL))
      .map((g) => `${g.name}(${g.args}) — останній дотик: ${lastMentionFile(g.name)}`)

    expect(offenders, 'anon-функція з UUID-аргументом: пряме посилання на обʼєкт замість токена')
      .toEqual([])
  })

  it('get_shared_collection лишається прибраною', () => {
    // Прицільний гард на конкретну діру: `CREATE OR REPLACE` у будь-якій
    // МАЙБУТНІЙ міграції відкрив би її знову, і загальне правило вище цього не
    // побачить, якщо GRANT забудуть повторити.
    const dropIdx = FILES.findIndex((f) =>
      readFileSync(resolve(DIR, f), 'utf8').includes('DROP FUNCTION IF EXISTS get_shared_collection('))
    expect(dropIdx, 'міграція, що дропає get_shared_collection, зникла').toBeGreaterThan(-1)

    const after = FILES.slice(dropIdx + 1)
      .filter((f) => /FUNCTION get_shared_collection\s*\(/.test(readFileSync(resolve(DIR, f), 'utf8')))
    expect(after, 'get_shared_collection перестворено після дропу — IDOR повернувся').toEqual([])
  })
})

describe('IDOR: клієнт не кличе прибраний RPC', () => {
  it('у src немає викликів get_shared_collection', () => {
    const src = resolve(process.cwd(), 'src')
    const hits: string[] = []
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = resolve(dir, e.name)
        if (e.isDirectory()) walk(p)
        else if (/\.tsx?$/.test(e.name) && readFileSync(p, 'utf8').includes("'get_shared_collection'")) {
          hits.push(p.replace(process.cwd() + '/', ''))
        }
      }
    }
    walk(src)
    expect(hits, 'екран досі ходить у прибраний RPC — після 049 він поверне помилку').toEqual([])
  })
})
