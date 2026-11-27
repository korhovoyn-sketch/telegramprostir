import { describe, it, expect, afterEach } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs'
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

  it('глосарій: терміни не розходяться по застосунку', () => {
    // Одне й те саме поняття різними словами — це дрейф, який жоден
    // асерт на екрані не бачить: кожен рядок окремо звучить пристойно. Список
    // — ЗАБОРОНЕНІ варіанти; обране слово стоїть у глосарії `gen-dict.js`.
    const forbidden: [RegExp, string][] = [
      [/\bobjects?\b/i, 'обʼєкт — це unit, не object'],
      [/\bbillable\b/i, 'розрахункова площа — rentable, не billable'],
      [/\brealtors?\b/i, 'ріелтор — agent'],
      [/\brefresh (the )?link\b/i, 'ротація посилання — reset, не refresh (refresh — це оновити сторінку)'],
      [/\blet out\b|\bunit let\b|\bno let units\b|\bcould not let\b/i, 'здати в оренду — rent out'],
    ]
    const bad = Object.entries(EN).flatMap(([k, v]) =>
      forbidden.filter(([re]) => re.test(v)).map(([, why]) => `${k.slice(0, 40)} → ${v.slice(0, 50)} (${why})`))
    expect(bad, 'термін розійшовся з глосарієм').toEqual([])
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

describe('мова документа', () => {
  afterEach(async () => { await loadLang('uk') })

  it('<html lang> іде за мовою інтерфейсу', async () => {
    // `lang` обирає голос читалки: англійський текст під `lang="uk"`
    // озвучувався б українською вимовою, тобто був би нерозбірливим. Атрибут
    // ставив лише `layout.tsx` статично, тож після перемикача мови він
    // лишався `uk` до перезавантаження. Початкове значення — сторонній
    // маркер: інакше тест проходив би, лишись атрибут `uk` з розмітки.
    document.documentElement.lang = 'xx'
    await loadLang('en')
    expect(document.documentElement.lang).toBe('en')
    await loadLang('uk')
    expect(document.documentElement.lang).toBe('uk')
  })

  it('словник, що не приїхав, мову документа не міняє', async () => {
    // Мова стає активною ЛИШЕ після словника — і `lang` разом із нею, а не
    // раніше: інакше на мить документ заявляв би англійську при українському
    // тексті на екрані.
    document.documentElement.lang = 'uk'
    const pending = loadLang('en')
    expect(document.documentElement.lang).toBe('uk')
    await pending
    expect(document.documentElement.lang).toBe('en')
  })
})

describe('мова поля дати', () => {
  it('екрани не зашивають мову в `lang=`', () => {
    // Нативне поле дати бере формат і підписи з `lang` елемента, тож зашита
    // `uk-UA` лишала англомовному користувачу українські «дд.мм.рррр» просто
    // у формі обʼєкта — єдине місце, де мова перемикалась би наполовину. Два
    // інші поля дат без `lang` наслідують `<html lang>`, який тепер іде за
    // мовою; зашитий атрибут перебивав би й це. Виняток один і явний —
    // `layout.tsx`, де стоїть початкове значення розмітки.
    const offenders: string[] = []
    let visited = 0
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name)
        if (e.isDirectory()) { walk(full); continue }
        if (!full.endsWith('.tsx') || full.endsWith(join('app', 'layout.tsx'))) continue
        visited++
        const src = readFileSync(full, 'utf8')
        for (const m of src.matchAll(/\blang\s*=\s*(?:"[^"]*"|'[^']*')/g)) offenders.push(`${full}: ${m[0]}`)
      }
    }
    walk('src')
    // Антивакуум: обхід справді бачив екрани, а не порожню теку.
    expect(visited, 'обхід src нічого не знайшов').toBeGreaterThan(20)
    expect(offenders, 'зашита мова в атрибуті lang').toEqual([])
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

describe('словник — генерований, а не правлений руками', () => {
  it('dict-en.ts збігається з тим, що дає генератор із dict.json', () => {
    // Файл підписаний «ГЕНЕРОВАНИЙ», і доти це трималось лише на слові: саме
    // джерело (`dict.json`) у репозиторії ВІДСУТНЄ БУЛО, тобто перегенерувати
    // було нізвідки, а ручна правка нічим не відрізнялась від законної.
    // Той самий клас, що вже закритий байтовою звіркою для `RELEASE.sql`.
    const dir = mkdtempSync(join(tmpdir(), 'dict-'))
    const out = join(dir, 'dict-en.ts')
    execFileSync('node', ['scripts/i18n/gen-dict.js', 'scripts/i18n/dict.json', out], { stdio: 'ignore' })
    expect(readFileSync(out, 'utf8'), 'перезбери: node scripts/i18n/gen-dict.js scripts/i18n/dict.json')
      .toBe(readFileSync('src/lib/dict-en.ts', 'utf8'))
  })
})

describe('розірваний підпис — один ключ, а не уламки', () => {
  it('код не кличе голе слово там, де переклад ПЕРЕСТАВЛЯЄ {0}', () => {
    // «3 поверх» українською збирався з двох вузлів — числа й слова. Англійська
    // порядок міняє («floor 3»), тож уламки давали «3 floor». Одинадцять місць;
    // при цьому експорт та імпорт у тих самих даних уже робили правильно —
    // цілим ключем. Це той самий інваріант, що `tx()` тримає для речень із
    // розміткою, лише дірка тут — ЧИСЛО, а не вузол.
    //
    // Умова СВІДОМО звужена до перестановки: `{0} м²` → `{0} m²` і
    // `{0} обʼєктів` → `{0} units` порядку не міняють, тож уламок там законний,
    // і строгіша перевірка дала б два хибні спрацювання.
    const used = new Set(keysFromSource())
    const bad = Object.keys(EN)
      .map((k) => ({ k, bare: /^\{0\} (.+)$/.exec(k)?.[1] }))
      .filter((x) => x.bare && used.has(x.bare) && !EN[x.k].startsWith('{0}'))
      .map((x) => `tr('${x.bare}') — є цілий ключ '${x.k}' → '${EN[x.k]}'`)
    expect(bad, `уламки замість цілого ключа:\n${bad.join('\n')}`).toEqual([])
  })
})
