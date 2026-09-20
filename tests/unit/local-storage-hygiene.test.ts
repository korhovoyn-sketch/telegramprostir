import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { SESSION_PREFIXES, DEVICE_KEYS, clearSessionState } from '../../src/lib/localState'

/**
 * КЛЮЧ, ЯКИЙ НІХТО НЕ КЛАСИФІКУВАВ, ПЕРЕЖИВАЄ ВИХІД З АКАУНТА.
 *
 * Дефект, заради якого це написано: `clearPersistedSession()` стирав рівно
 * один ключ (`ps_user`), а на диску лишались SWR-снапшоти списків — назви
 * обʼєктів, ІМЕНА ОРЕНДАРІВ, ставки, дати договорів, адреси — плюс
 * чернетки форми і гостьовий токен. Те саме стосувалось ВИДАЛЕННЯ АКАУНТА,
 * тобто прямої обіцянки §5 Політики конфіденційності.
 *
 * ЧОМУ ЦЬОГО НЕ БАЧИВ ЖОДЕН ІЗ НАЯВНИХ ГАРДІВ. Усі вони питають про доступ
 * до СЕРВЕРА — RLS, гранти, політики. Локальне сховище лежить по інший бік
 * мережі, і там немає нікого, хто б питав «а чиї це дані і коли вони мають
 * зникнути». Клас видно лише з боку КЛІЄНТА.
 *
 * Гард читає ту саму класифікацію, з якої працює чистка, тож розійтись вони
 * не можуть: новий ключ або належить сесії (і стирається), або свідомо
 * названий ключем ПРИСТРОЮ — третього стану немає.
 */

const SRC = resolve(process.cwd(), 'src')

function walk(dir: string, acc: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = resolve(dir, e.name)
    if (e.isDirectory()) walk(p, acc)
    else if (/\.tsx?$/.test(e.name)) acc.push(p)
  }
  return acc
}

const FILES = walk(SRC).map((f) => ({ path: f, src: readFileSync(f, 'utf8') }))
const ALL = FILES.map((f) => f.src).join('\n')

/**
 * Ключ, з яким кличуть `setItem`, майже ніколи не літерал — це іменована
 * константа або шаблон. Тому: літерал беремо як є, ідентифікатор резолвимо
 * до ПЕРШОГО рядкового/шаблонного літерала в його оголошенні (по всьому src,
 * бо `PROFILE_KEY` експортується з одного файлу й уживається в іншому).
 */
function resolveKey(arg: string): string | null {
  const lit = arg.match(/^['"`]([^'"`$]+)/)
  if (lit) return lit[1]
  const ident = arg.match(/^([A-Za-z_$][\w$]*)/)
  if (!ident) return null
  const decl = new RegExp(
    `(?:const|let|var)\\s+${ident[1]}\\s*(?::[^=]+)?=\\s*[^\\n]*?['"\`]([^'"\`$]+)`,
  ).exec(ALL)
  if (decl) return decl[1]
  // `keyFor(...)` — ключ будує функція; беремо літерал з її тіла
  const fn = new RegExp(
    `(?:const|function)\\s+${ident[1]}[^\\n]*?=>?[^\\n]*?['"\`]([^'"\`$]+)`,
  ).exec(ALL)
  return fn ? fn[1] : null
}

function writtenKeys(): { key: string; where: string }[] {
  const out: { key: string; where: string }[] = []
  for (const f of FILES) {
    for (const m of f.src.matchAll(/localStorage\.setItem\(\s*([^,]+),/g)) {
      const key = resolveKey(m[1].trim())
      if (key) out.push({ key, where: f.path.slice(SRC.length + 1) })
    }
  }
  return out
}

describe('гігієна локального сховища', () => {
  it('кожен записаний ключ класифіковано: сесія або пристрій', () => {
    const keys = writtenKeys()

    // АНТИВАКУУМ: якщо витягувач ключів зламався, список порожній — і тест
    // «проходить», нічого не перевіривши. Нижня межа з поточного стану.
    expect(keys.length, 'жодного localStorage.setItem не знайдено — витягувач зламався')
      .toBeGreaterThanOrEqual(8)

    const unknown = keys.filter(({ key }) =>
      !SESSION_PREFIXES.some((p) => key.startsWith(p)) &&
      !DEVICE_KEYS.some((d) => key.startsWith(d)))

    expect(unknown.map((u) => `${u.key} (${u.where})`), [
      'Ключ localStorage не класифіковано в src/lib/localState.ts.',
      'Він містить дані акаунта → SESSION_PREFIXES (стирається при виході),',
      'чи це налаштування пристрою → DEVICE_KEYS (переживає вихід свідомо)?',
    ].join(' ')).toEqual([])
  })

  it('класифікація однозначна: ключ не може бути і сесійним, і пристроєвим', () => {
    const both = DEVICE_KEYS.filter((d) => SESSION_PREFIXES.some((p) => d.startsWith(p)))
    expect(both, 'ключ пристрою збігається з сесійним префіксом — чистка стерла б налаштування')
      .toEqual([])
  })

  it('вихід з акаунта справді кличе чистку', () => {
    const auth = readFileSync(resolve(SRC, 'hooks/useAuth.ts'), 'utf8')
    const body = auth.slice(auth.indexOf('function clearPersistedSession'))
    expect(body.slice(0, body.indexOf('}')), 'clearPersistedSession не кличе clearSessionState')
      .toContain('clearSessionState()')
    // Видалення акаунта йде тим самим шляхом — інакше обіцянка §5 не виконана
    expect(auth, 'deleteAccount не чистить локальний стан')
      .toMatch(/deleteAccount[\s\S]{0,4000}clearPersistedSession\(\)/)
  })

  /* Джерельні перевірки вище доводять, що ВИКЛИК на місці. Чи дані справді
     зникають — інше твердження, і воно перевіряється лише виконанням. */
  it('РАНТАЙМ: сесійне стирається, пристроєве лишається', () => {
    localStorage.clear()
    const gone = {
      'ps_user': '{"id":"u1","phone":"+380..."}',
      'snap_v1:u1:databases': '[{"id":"d1"}]',
      'snap_v1:u1:props:d1': '[{"tenant_name":"ФОП Плотко"}]',
      'snap_v1:u2:props:d9': '[{"tenant_name":"чужий акаунт на цьому ж пристрої"}]',
      'draft_v1:u1:prop-new:d1': '{"name":"Офіс 101"}',
      'ps_guest_join_token': 'db_abc123',
      'ps:foldCollapse:u1:d1': '["__none__"]',
    }
    const stays = { 'ps_lang': 'uk', 'ob_v1': '["x"]', 'ps:occCompact': '1', 'kb_h_v1': '{}' }
    Object.entries({ ...gone, ...stays }).forEach(([k, v]) => localStorage.setItem(k, v))

    clearSessionState()

    expect(Object.keys(gone).filter((k) => localStorage.getItem(k) !== null),
      'дані акаунта лишились на диску після виходу').toEqual([])
    // Антивакуум із другого боку: «стерло все» — теж провал, це налаштування
    // пристрою, і вихід з акаунта не має їх скидати.
    expect(Object.keys(stays).filter((k) => localStorage.getItem(k) === null),
      'чистка знесла налаштування пристрою').toEqual([])
  })

  it('чистка стирає ВСІ сесійні ключі, включно з ключами інших акаунтів', () => {
    const mod = readFileSync(resolve(SRC, 'lib/localState.ts'), 'utf8')
    // Ключі снапшотів і чернеток містять userId, тобто поіменно їх не знати:
    // перебір мусить іти по САМОМУ сховищу, а не по відомому списку імен.
    expect(mod, 'чистка не перебирає localStorage — ключі з userId лишаться')
      .toMatch(/localStorage\.key\(/)
  })
})
