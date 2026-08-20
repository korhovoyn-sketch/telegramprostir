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
 * Свідомі винятки. Кожен — з причиною; порожня причина не приймається.
 * Це дані, чия втрата оборотна, і жоден з них не стирає файли зі сховища.
 */
const ALLOW: Record<string, string> = {
  'hooks/useNotifications.ts':
    'сповіщення — похідні дані: наступний loadNotifications перечитає правду з сервера, ' +
    'а показати «прочитано» на секунду довше нешкідливо',
  'hooks/useFolders.ts':
    'reorder папок — перестановка sort_order; невдача видно одразу при наступному завантаженні, ' +
    'даних не втрачає',
  'screens/CollectionsScreen.tsx':
    'підбірки рієлтора — власні рядки без storage; помилка видно на перезавантаженні',
  'screens/PaymentCalendarScreen.tsx':
    'видалення розкладу і скасування платежу — рядки без файлів, екран перечитує стан на back()',
}

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
        if (ALLOW[rel]) continue
        const line = src.slice(0, src.indexOf(chain)).split('\n').length
        offenders.push(`${rel}:${line} — ${chain.split('\n').slice(0, 3).join(' ').trim().slice(0, 90)}`)
      }
    }

    expect(offenders, 'мутація без .select()/.single(): під RLS відмова невідрізненна від успіху')
      .toEqual([])
  })

  it('кожен виняток має НЕПОРОЖНЮ причину і справді існує', () => {
    for (const [rel, reason] of Object.entries(ALLOW)) {
      expect(reason.trim().length, `${rel}: виняток без причини`).toBeGreaterThan(30)
      const exists = files.some((f) => f.endsWith(rel))
      expect(exists, `${rel}: файл зник — виняток застарів і маскує нові порушення`).toBe(true)
    }
  })
})
