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


/**
 * 059 — UUID обʼєкта більше не є «легасі-токеном».
 *
 * `lookup_shared_property` і `record_public_view` мали гілку
 * `WHEN p_token ~ '^[0-9a-f]{8}-…$' THEN p.id = p_token::UUID`, тобто
 * приймали СИРИЙ UUID там, де ключем має бути нездогадний share-токен. Друга
 * з них видана `anon`, тож нею накручували ЧУЖУ аналітику.
 *
 * Рантаймом це теж покрито (`verify-rls.sql`, блок 15), але джерельний гард
 * тут дешевий і ловить намір ПОВЕРНУТИ патерн ще на ревʼю дифа — той самий
 * поділ праці, що вже діє для `get_shared_collection` (049).
 */
describe('059: UUID не приймається як share-токен', () => {
  it('жодна діюча функція не порівнює p_token з id обʼєкта', () => {
    const offenders: string[] = []
    for (const f of FILES) {
      // Беремо лише міграції ВІД 059: пізніша мовчки перекриває ранішу
      // (правило 6 чеклісту §5), тож ранні файли, де гілка ще була, порушенням
      // не є — вони вже перекриті.
      if (Number(f.match(/^0*(\d+)/)?.[1] ?? 0) < 59) continue
      // Коментарі ЗНІМАЮТЬСЯ: 059 цитує сам патерн у своїй шапці, пояснюючи,
      // що прибирає. Гард, який ловить власне пояснення, — це не суворість, а
      // хибне спрацювання; перевіряти треба КОД.
      const src = readFileSync(resolve(DIR, f), 'utf8')
        .split('\n').filter((l) => !l.trimStart().startsWith('--')).join('\n')
      if (/p\.id\s*=\s*p_token::UUID/.test(src)) offenders.push(f)
    }
    expect(offenders,
      'UUID обʼєкта знову приймається як токен — див. 059')
      .toEqual([])
  })
})

// ── Копія хелпера ідентичності БЕЗ доменного якоря ─────────────────────────
// 038 містить «самодостатню» копію `get_app_user_id_from_auth_uid()`, узяту ДО
// 031: без `email ~ '^\d{1,20}@telegram\.propspace\.app$'` і без `tg_id > 0`.
// `CREATE OR REPLACE` мовчки перетирає захищену версію, і саме так 038 колись
// стерла фікс 031, а 041 скопіювала регресований патерн далі (див. 045).
//
// Рантаймом це НЕ ловиться незалежно: на повному накаті остання міграція за
// номером перемагає, тож регресію в 062 спіймав би загальний verify_release —
// але лише тому, що вона там ОСТАННЯ. Внесена в 049, вона була б перекрита
// пізнішими файлами і лишилась би невидимою до наступного порядку накату.
describe('хелпер ідентичності не переозначується без якоря', () => {
  it('жодна міграція від 048 не несе копії без доменного якоря', () => {
    const late = readdirSync(DIR).filter((f) => /^\d{3}_/.test(f) && Number(f.slice(0, 3)) >= 48)
    for (const f of late) {
      const sql = readFileSync(resolve(DIR, f), 'utf-8')
        .split('\n').filter((l) => !l.trimStart().startsWith('--')).join('\n')
      const m = sql.match(/CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(?:public\.)?get_app_user_id_from_auth_uid[\s\S]*?\$\$([\s\S]*?)\$\$/i)
      if (!m) continue
      expect(m[1], `${f} переозначує хелпер без доменного якоря — це регресія 031/045`).toMatch(/telegram\\?\.propspace\\?\.app/)
      expect(m[1], `${f} переозначує хелпер без tg_id > 0`).toMatch(/tg_id\s*>\s*0/)
    }
  })
})

describe('релізна звірка знає кожен клієнтський RPC', () => {
  /**
   * КОЖЕН RPC, ЯКИЙ МОЖЕ ПОКЛИКАТИ КЛІЄНТ, МУСИТЬ БУТИ В `verify_release.sql`.
   *
   * Прогалини всередині 001–047 ДОВЕДЕНІ, а не гіпотетичні: накат `RELEASE.sql`
   * упав у проді на `mark_overdue_payments() does not exist`, бо 024 ніколи не
   * застосовували. Тобто «функція є в міграції» не означає «функція є в базі» —
   * присутність треба ПИТАТИ.
   *
   * Аудит знайшов пʼять RPC поза звіркою, і найгірший — `lookup_shared_collection`:
   * визначена ЛИШЕ в 020/023, у `RELEASE.sql` її немає, тож накат 048–062 її не
   * створює. Якби її в проді не було, deep link `col_<token>` (вхід за посиланням
   * на підбірку) падав би, і жоден файл репозиторію про це не сказав би.
   *
   * Джерельний гард, бо рантаймом це не закрити чесно: e2e мокають RPC через
   * `page.route`, тобто там існує будь-яка функція, яку назвеш.
   */
  it('жоден клієнтський RPC не лишився поза verify_release.sql', () => {
    const texts: string[] = []
    const collect = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const f = resolve(dir, e.name)
        if (e.isDirectory()) collect(f)
        // `types/supabase.ts` — згенерований опис СХЕМИ, а не виклики.
        else if (/\.tsx?$/.test(e.name) && !/supabase\.ts$/.test(e.name)) texts.push(readFileSync(f, 'utf8'))
      }
    }
    collect(resolve(process.cwd(), 'src'))
    const called = [...new Set([...texts.join('\n').matchAll(/\.rpc\('([a-z_]+)'/g)].map((m) => m[1]))]
    // Антивакуум: якщо регекс перестане знаходити виклики, гард мовчатиме.
    expect(called.length, 'жодного .rpc() не знайдено — регекс застарів').toBeGreaterThan(8)

    // Імена беруться з ТОГО, ПРО ЩО ЗАПИТ ПИТАЄ (`proname='…'`), а не з тексту
    // файлу. Перша версія робила `verify.includes(fn)` — і фальсифікація
    // показала, що гард вакуумний: назву далі «покривав» коментар, який я сам
    // же й написав поруч. Підрядковий пошук по файлу з прозою не доводить
    // нічого.
    const verify = readFileSync(resolve(process.cwd(), 'supabase/verify_release.sql'), 'utf8')
    const asked = new Set([...verify.matchAll(/proname\s*=\s*'([a-z_]+)'/g)].map((m) => m[1]))
    expect(asked.size, 'у verify_release не знайдено жодного proname — формат змінився').toBeGreaterThan(5)
    const missing = called.filter((fn) => !asked.has(fn))
    expect(missing, 'RPC є в клієнті, але релізна звірка про нього не питає').toEqual([])
  })
})
