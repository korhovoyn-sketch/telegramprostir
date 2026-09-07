import { describe, it, expect, afterEach } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { EN } from '@/lib/dict-en'
import { tr, loadLang, getLang, locale } from '@/lib/i18n'
import { pluralUk, objectsWord } from '@/lib/utils'

/**
 * ГАРД ДВОМОВНОСТІ — ДЖЕРЕЛЬНИЙ, і рантаймом його не замінити.
 *
 * E2e ганяються проти зібраного бандла, де прогалина перекладу виглядає як
 * український текст на англійському екрані — тобто НЕ падіння, а лише дивний
 * вигляд, який жоден асерт не ловить. Тому інваріант «ключ у коді ↔ ключ у
 * словнику» перевіряється по ДЖЕРЕЛУ, тим самим екстрактором, що збирає
 * словник.
 */
function keysFromSource(): string[] {
  // Через ФАЙЛ, а не через stdout: `keys.js` пише JSON у файл, а в stdout —
  // лічильник. Перша версія читала stdout і падала на власному способі
  // вимірювання, а не на коді.
  const dir = mkdtempSync(join(tmpdir(), 'i18n-'))
  const out = join(dir, 'keys.json')
  execFileSync('node', ['scripts/i18n/keys.js', out], { stdio: 'ignore' })
  return JSON.parse(readFileSync(out, 'utf8')) as string[]
}

describe('двомовність', () => {
  const keys = keysFromSource()

  it('кожен ключ із коду має переклад', () => {
    const missing = keys.filter((k) => !EN[k])
    expect(missing, `без перекладу: ${missing.slice(0, 8).join(' | ')}`).toEqual([])
  })

  it('у словнику немає осиротілих ключів', () => {
    // Осиротілий ключ означає рівно одне: український текст змінили у ВИКЛИКУ
    // і не змінили у словнику. Мовчки це дає англійський екран з українським
    // рядком саме там, де текст правили востаннє.
    const known = new Set(keys)
    const orphans = Object.keys(EN).filter((k) => !known.has(k))
    expect(orphans, `осиротіли: ${orphans.slice(0, 8).join(' | ')}`).toEqual([])
  })

  it('переклад не лишився українським', () => {
    // Найтихіша з можливих прогалин: рядок скопійовано в значення як є.
    // Кирилиця у ЗНАЧЕННІ — майже завжди недороблений переклад; виняток один
    // і він явний (транслітерований бренд у прикладі адреси не тримаємо).
    const cyr = /[а-яА-ЯіїєґІЇЄҐ]/
    const bad = Object.entries(EN).filter(([, v]) => cyr.test(v))
    expect(bad.map(([k]) => k), 'значення лишилось кириличним').toEqual([])
  })

  it('дірки {0} у перекладі збігаються з оригіналом', () => {
    // Загублена дірка зʼїдає підставлене значення (число, назву, суму), а
    // зайва малює сирий маркер. І перше, і друге видно лише в тій мові, якою
    // ніхто з нас щодня не користується.
    const holes = (s: string) => (s.match(/\{\d+\}/g) ?? []).sort().join(',')
    const bad = Object.entries(EN).filter(([k, v]) => holes(k) !== holes(v))
    expect(bad.map(([k]) => k), 'набір дірок розійшовся').toEqual([])
  })
})

describe('плюрали і локаль', () => {
  // Мова — МОДУЛЬНИЙ стан, тож тест, що впав до свого `loadLang('uk')`,
  // лишає її англійською і валить наступні. Спостережено: одна справжня
  // помилка давала ТРИ падіння, і два з них вказували не туди.
  afterEach(async () => { await loadLang('uk') })

  // Міряємо `pluralUk`/`objectsWord` — ТЕ, ЧИМ КОРИСТУЄТЬСЯ ЗАСТОСУНОК.
  // Перша версія гарда перевіряла окрему `plural()` з `i18n.ts`, і
  // фальсифікація це викрила: зламана англійська гілка `pluralUk` лишала тест
  // ЗЕЛЕНИМ, бо та функція не викликалась ніде. Її прибрано як мертвий код —
  // дві реалізації одного правила розійшлися б за один раунд.
  const UK = ['обʼєкт', 'обʼєкти', 'обʼєктів'] as const

  it('англійська: однина лише для 1 — включно з 21', async () => {
    await loadLang('en')
    // Саме тут словника НЕ досить: українська для 21 бере форму ОДНИНИ, тож
    // переклад тієї форми дав би «21 unit» замість «21 units».
    expect(objectsWord(1)).toBe('unit')
    expect(objectsWord(21)).toBe('units')
    expect(objectsWord(5)).toBe('units')
    expect(objectsWord(2)).toBe('units')
    await loadLang('uk')
  })

  it('українська: три форми, 11-14 — many', () => {
    expect(pluralUk(1, ...UK)).toBe('обʼєкт')
    expect(pluralUk(3, ...UK)).toBe('обʼєкти')
    expect(pluralUk(11, ...UK)).toBe('обʼєктів')
    expect(pluralUk(21, ...UK)).toBe('обʼєкт')
  })

  it('локаль дат іде за мовою', async () => {
    expect(locale()).toBe('uk-UA')
    await loadLang('en')
    expect(locale()).toBe('en-US')
    await loadLang('uk')
  })

  it('українською tr() повертає ключ ПОБАЙТОВО', () => {
    // Це і є причина, чому наявні 748 тестів працюють гардом усього кодмоду.
    expect(getLang()).toBe('uk')
    for (const k of ['Мої бази', 'Вільно', 'Разом на місяць']) expect(tr(k)).toBe(k)
  })

  it('англійською підстановки працюють', async () => {
    await loadLang('en')
    expect(tr('Максимум {0} обʼєктів за раз', 500)).toBe('Maximum 500 units at a time')
    await loadLang('uk')
  })
})

describe('«Вільно» — це Vacant, а не Free', () => {
  it('статус не обіцяє безкоштовність', () => {
    // Найдорожча з можливих помилок глосарію: англійське `free` читається як
    // «безкоштовно», тобто статус обʼєкта перетворюється на обіцянку ціни.
    expect(EN['Вільно']).toBe('Vacant')
    expect(EN['вільно']).toBe('vacant')
    expect(EN['Продаж']).toBe('For sale')
  })
})

describe('tr() на рівні модуля', () => {
  it('жодна константа не застигає українською', () => {
    // КЛАС, ЩО ДАВ УСІ РЕАЛЬНІ ДЕФЕКТИ ЦЬОГО РАУНДУ. Словник вантажиться
    // динамічно, тобто ПІЗНІШЕ за обчислення модулів, тож
    // `const LABELS = { x: tr('…') }` фіксує український текст назавжди —
    // і жоден перемикач мови його вже не змінить.
    //
    // Знайдено аудитом англійською: 133 виклики у 25 константах, серед них
    // типи баз, статуси, aria-мітки таббару, колонки імпорту, шаблони
    // експорту. Рантаймом це не закрити чесно: e2e ганяються проти
    // мок-бекенда, а прогалина виглядає як українське слово на англійському
    // екрані — не падіння, а «дивний вигляд», якого не бачить жоден асерт.
    //
    // Юридичні сторінки — законний виняток: `metadata` і дата оновлення
    // обчислюються НА ЗБІРЦІ (Next.js `Metadata`), а самі сторінки статичні
    // й українські за побудовою.
    const out = execFileSync('node', ['scripts/i18n/toplevel.js'], { encoding: 'utf8' })
    const rows = out.split('\n').filter((l) => /^\s+\d+×/.test(l))
    const bad = rows.filter((l) => !/app\/(privacy|terms)\/page\.tsx/.test(l))
    expect(bad, `застигли українською:\n${bad.join('\n')}`).toEqual([])
  })
})
