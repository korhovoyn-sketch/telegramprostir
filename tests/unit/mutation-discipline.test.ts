import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * ГАРД НА ВИКОРИСТАННЯ ПРАВИЛА, А НЕ НА САМЕ ПРАВИЛО.
 *
 * `rls-silent.test.ts` доводить, що `assertAffected` працює. Але жоден тест не
 * перевіряв, що його ВЗАГАЛІ КЛИЧУТЬ — і клас «мовчазний провал під RLS»
 * рецидивував ЧОТИРИ рази поспіль: `useProperties`, `usePropertyFiles`,
 * `AccessList`, `useNotifications`. Конвенція його не тримає, бо дефект живе
 * не в хелпері, а в місці виклику.
 *
 * Правило: кожен `.delete()` / `.update(` у `src/` мусить у тому ж ланцюгу
 * мати `.select(` (щоб було що рахувати) або `.single()` (той сам падає з
 * PGRST116 на нулі рядків). Виняток дозволений лише з ПРИЧИНОЮ в allowlist.
 */

const SRC = resolve(process.cwd(), 'src')

/**
 * ВИНЯТКИ ПОЗНАЧАЮТЬСЯ МАРКЕРОМ У КОДІ, А НЕ СПИСКОМ ФАЙЛІВ.
 *
 * Тут раніше стояла таблиця `ALLOW` по ІМЕНАХ ФАЙЛІВ — і це суперечило тому,
 * що написано двадцятьма рядками нижче про семантичні винятки: бланкетний
 * файловий дозвіл амністує КОЖНУ майбутню мутацію в тому файлі, включно з
 * деструктивною. Тобто найнебезпечніші операції були б непокриті саме там, де
 * вже колись зробили виняток.
 *
 * Тепер причина живе поруч із самою мутацією:
 *
 *   // rls-ok: сповіщення — похідні дані, наступний load перечитає правду
 *   await supabase.from('notifications').update({ is_read: true }).eq('id', id)
 *
 * Маркер шукається у пʼятьох рядках над ланцюгом. Це переживає зсуви рядків
 * (номери вже зʼїжджали від сусідньої правки за один раунд) і, головне, не
 * поширюється на сусідів.
 */
const OK_MARK = /rls-ok:\s*\S/

function walk(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name)
    if (e.isDirectory()) walk(p, acc)
    else if (/\.tsx?$/.test(e.name)) acc.push(p)
  }
  return acc
}

/**
 * Ланцюг виклику: від `.from(` доти, доки рядки ПРОДОВЖУЮТЬ ланцюг.
 *
 * Перша версія брала фіксоване вікно у 500 символів — і воно захоплювало
 * `.select(` НАСТУПНОГО ланцюга, тож гард мовчки пропускав порушення. Спіймано
 * власною фальсифікацією: прибрав `.select('id')` з `deletePhoto` — тест
 * лишився зеленим. Гард, що не падає на зламаному коді, гірший за відсутній.
 */
function chains(src: string): string[] {
  const out: string[] = []
  const lines = src.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (!/\.from\(/.test(lines[i])) continue
    const acc = [lines[i]]
    // Продовженням вважається лише рядок, що починається з крапки: саме так у
    // цій кодовій базі пишуться ланцюги postgrest.
    for (let j = i + 1; j < lines.length && /^\s*\./.test(lines[j]); j++) acc.push(lines[j])
    out.push(acc.join('\n'))
  }
  return out
}

describe('дисципліна мутацій: кожен запис доводить, що зачепив рядки', () => {
  const files = walk(SRC)

  it('вибірка файлів не порожня', () => {
    expect(files.length).toBeGreaterThan(30)
  })

  it('жоден .delete()/.update() не лишається без доказу', () => {
    const offenders: string[] = []

    for (const file of files) {
      const rel = file.replace(SRC + '/', '')
      const src = readFileSync(file, 'utf8')
      for (const chain of chains(src)) {
        const mutates = /\.delete\(\)|\.update\(/.test(chain)
        if (!mutates) continue
        // storage-ланцюги (`storage.from('photos').remove`) — інша поверхня:
        // там немає RLS-рядків, які можна порахувати.
        if (/storage\s*\n?\s*\.from\(|supabase\.storage/.test(chain)) continue
        const proves = /\.select\(|\.single\(\)|\.maybeSingle\(\)/.test(chain)
        if (proves) continue
        // СЕМАНТИЧНИЙ виняток, а не файловий: мутація, що чіпає ВИКЛЮЧНО
        // `sort_order`, — це нормалізація порядку. Вона оборотна, самолікується
        // при наступному впорядкуванні і не стирає нічого. Файловий виняток тут
        // був би небезпечний: у `useProperties.ts` живуть найдеструктивніші
        // операції застосунку, і бланкетний allowlist маскував би їх.
        if (/\.update\(\s*\{\s*sort_order:[^}]*\}\s*\)/.test(chain)) continue
        const line = src.slice(0, src.indexOf(chain)).split('\n').length
        // Маркер із причиною безпосередньо над мутацією знімає її з обліку.
        const above = src.split('\n').slice(Math.max(0, line - 6), line).join('\n')
        if (OK_MARK.test(above)) continue
        offenders.push(`${rel}:${line} — ${chain.split('\n').slice(0, 3).join(' ').trim().slice(0, 90)}`)
      }
    }

    expect(offenders, 'мутація без .select()/.single(): під RLS відмова невідрізненна від успіху')
      .toEqual([])
  })

  it('кожен маркер `rls-ok:` несе змістовну причину', () => {
    const thin: string[] = []
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8')
      src.split('\n').forEach((line, i) => {
        const m = line.match(/rls-ok:(.*)$/)
        if (!m) return
        // Маркер без пояснення — це той самий бланкетний дозвіл, лише
        // розсипаний по рядках. Тридцять символів — не бюрократія, а поріг,
        // нижче якого причина не пишеться, а імітується.
        if (m[1].trim().length < 30) {
          thin.push(`${file.replace(SRC + '/', '')}:${i + 1} — «${m[1].trim()}»`)
        }
      })
    }
    expect(thin, 'маркер без змістовної причини').toEqual([])
  })
})

/**
 * `.select('id')` — це ПІВЗАХИСТУ. Рядки повертаються, але якщо їх ніхто не
 * рахує, порожній набір і далі читається як успіх.
 *
 * Знайдено власною фальсифікацією: прибрав `assertAffected` зі скасування
 * платежу — гард лишився зеленим, бо `.select('id')` у ланцюгу нікуди не
 * подівся. Тобто перевірка стверджувала більше, ніж робила.
 */
describe('доведення, а не лише повернення рядків', () => {
  it('кожна мутація з .select() у ЦИХ файлах рахує зачеплені рядки', () => {
    // Файли, де мутації деструктивні або грошові. Список свідомо вузький:
    // сенс не в тотальності, а в тому, щоб найдорожчі шляхи не могли тихо
    // втратити доказ — саме там його колись і не було.
    const CRITICAL = [
      'hooks/useProperties.ts', 'hooks/useDatabases.ts', 'hooks/usePropertyFiles.ts',
      'hooks/useFolders.ts', 'hooks/useAuth.ts',
      'components/AccessList.tsx', 'screens/PaymentCalendarScreen.tsx',
      'screens/CollectionsScreen.tsx',
    ]
    const bad: string[] = []
    for (const rel of CRITICAL) {
      const src = readFileSync(resolve(SRC, rel), 'utf8')
      for (const chain of chains(src)) {
        if (!/\.(delete|update)\s*\(/.test(chain)) continue
        if (!/\.select\s*\(/.test(chain)) continue          // покрито тестом вище
        // `.single()` — задокументований еквівалент доказу: на нулі рядків він
        // сам кидає PGRST116, тобто відмова НЕ виглядає успіхом. Вимагати
        // поверх нього `assertAffected` означало б просити подвійну перевірку
        // там, де перша вже надійна.
        if (/\.single\s*\(\s*\)/.test(chain)) continue
        const line = src.slice(0, src.indexOf(chain)).split('\n').length
        const above = src.split('\n').slice(Math.max(0, line - 6), line).join('\n')
        if (OK_MARK.test(above)) continue
        // Доказ шукаємо в межах 12 рядків ПІСЛЯ ланцюга — саме там він стоїть
        // у всіх наявних місцях (`if (error) throw` між ними — норма).
        const after = src.split('\n').slice(line - 1, line + 12).join('\n')
        if (!/assertAffected\s*\(/.test(after)) {
          bad.push(`${rel}:${line} — ${chain.split('\n')[0].trim().slice(0, 70)}`)
        }
      }
    }
    expect(bad, '.select() є, а assertAffected немає: порожній набір знову читається як успіх')
      .toEqual([])
  })
})

/**
 * `assertAffected(rows, rows.length, …)` — перевірка, що НЕ МОЖЕ ВПАСТИ.
 *
 * `assertAffected` порівнює `rows?.length` з `expected`. Якщо `expected`
 * виведений із тих самих `rows`, вираз зводиться до `got !== got` — тобто
 * виклик виглядає як доказ, але не доводить нічого.
 *
 * Знайдено ревʼю в коміті, ЧИЯ ТЕЗА була «тавтологічна перевірка нічого не
 * доводить» — тобто клас відтворився в тексті, що його ж і засуджував.
 * Правильне `expected` завжди приходить із ЗАПИТУ (`1`, `ids.length`), а не з
 * відповіді.
 */
describe('очікувана кількість не виводиться з відповіді', () => {
  it('жоден assertAffected не порівнює набір сам із собою', () => {
    const bad: string[] = []
    for (const file of walk(SRC)) {
      const src = readFileSync(file, 'utf8')
      src.split('\n').forEach((line, i) => {
        const m = line.match(/assertAffected\(\s*([A-Za-z_$][\w$]*)\s*,\s*([^,]+),/)
        if (!m) return
        const [, rows, expected] = m
        // `expected`, що згадує ту саму змінну або будь-який `.length` від
        // відповіді, — це `got !== got`.
        if (new RegExp(`\\b${rows}\\b`).test(expected)) {
          bad.push(`${file.replace(SRC + '/', '')}:${i + 1} — expected виведене з «${rows}»: ${line.trim().slice(0, 80)}`)
        }
      })
    }
    expect(bad, 'assertAffected із похідним expected не може впасти — це доказ із виду, а не по суті')
      .toEqual([])
  })
})
