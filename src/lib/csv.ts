/**
 * Розбір CSV — ВЛАСНИЙ, і це не «не знайшли бібліотеку».
 *
 * `xlsx` уже лежить у бандлі (експорт), але `XLSX.read` не викликається ніде
 * НАВМИСНО: парсинг і є поверхнею того `high`-advisory (Prototype Pollution),
 * який не має фіксу, і `tests/unit/dependency-surface.test.ts` це форсить.
 * Тобто «просто ввімкнути читання» означало б обміняти єдину обґрунтовано
 * недосяжну вразливість на досяжну — рівно там, куди користувач приносить
 * ЧУЖИЙ файл.
 *
 * Тому підтримується CSV, і рівно те, що зустрічається в реальних вивантаженнях
 * з Excel/Google Sheets: лапки, подвоєні лапки всередині поля, переноси рядків
 * у полі, CRLF, BOM і роздільник `;` (українська локаль Excel зберігає саме
 * так — файл із `,` там відкривається одним стовпцем, і навпаки).
 */

/**
 * Роздільник визначається за ПЕРШИМ рядком поза лапками: у ньому лежать
 * заголовки, тобто там не буває ні дат, ні десяткових ком, які збили б рахунок.
 * Порівнюємо кандидатів за кількістю входжень — у заголовку правильний
 * роздільник трапляється щонайменше стільки разів, скільки колонок мінус одна.
 */
export function detectDelimiter(text: string): string {
  let inQ = false
  let line = ''
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (ch === '"') { inQ = !inQ; line += ch; continue }
    if (!inQ && (ch === '\n' || ch === '\r')) break
    line += ch
  }
  const count = (d: string) => {
    let n = 0, q = false
    for (const ch of line) {
      if (ch === '"') q = !q
      else if (ch === d && !q) n++
    }
    return n
  }
  const candidates = [',', ';', '\t']
  let best = ','
  let bestN = -1
  for (const d of candidates) {
    const n = count(d)
    if (n > bestN) { best = d; bestN = n }
  }
  return bestN > 0 ? best : ','
}

/**
 * Рядки → матриця клітинок. Порожній ввід дає порожній масив; рядок із самих
 * порожніх клітинок відкидається (Excel любить дописувати такі в кінець файлу,
 * і без цього імпорт мовчки створював би безіменні обʼєкти).
 */
export function parseCsv(input: string, delimiter?: string): string[][] {
  // BOM ламає порівняння ПЕРШОГО заголовка («﻿Назва» ≠ «Назва») — тобто
  // автозіставлення колонок відвалювалось би рівно на файлі, вивантаженому з
  // Excel, і причину не було б видно ніде.
  const text = input.replace(/^﻿/, '')
  if (!text.trim()) return []
  const d = delimiter ?? detectDelimiter(text)

  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQ = false

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]

    if (inQ) {
      if (ch === '"') {
        // Подвоєна лапка всередині поля — це одна лапка, а не кінець поля.
        if (text[i + 1] === '"') { cell += '"'; i++ }
        else inQ = false
      } else cell += ch
      continue
    }

    if (ch === '"') { inQ = true; continue }
    if (ch === d) { row.push(cell); cell = ''; continue }
    if (ch === '\r') { if (text[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; continue }
    if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; continue }
    cell += ch
  }
  row.push(cell)
  rows.push(row)

  return rows
    .map((r) => r.map((c) => unescapeCsvCell(c.trim())))
    .filter((r) => r.some((c) => c !== ''))
}

/**
 * Матриця → текст CSV.
 *
 * Живе поруч із парсером НАВМИСНО: це дві половини одного контракту, і
 * розкидані по різних файлах вони розходяться першими. Юніт-тести ганяють їх
 * круговим рейсом (`parseCsv(toCsv(x)) === x`), що можливо лише поки вони
 * разом.
 *
 * Роздільник — кома, а не `;`: файл читає і наш парсер (він визначає
 * роздільник сам), і будь-який інструмент. BOM додає ВИКЛИКАЧ, коли файл іде
 * в Excel, — у сам рядок його класти не можна, бо тоді круговий рейс мусив би
 * його зрізати, і тест перестав би бути симетричним.
 */
/**
 * ФОРМУЛЬНА ІНʼЄКЦІЯ: лапки тут НЕ захист, і це головне непорозуміння класу.
 *
 * Excel/LibreOffice/Sheets вирішують «це формула» ПО ВМІСТУ клітинки вже
 * ПІСЛЯ того, як зрізали лапки при розборі CSV. Тобто `"=HYPERLINK(...)"`
 * обчислюється так само, як голе `=HYPERLINK(...)`. Єдиний надійний прийом —
 * префікс `'`, який ті самі програми трактують як «далі текст».
 *
 * Чому це не теорія саме тут: вільний текст обʼєкта (назва, орендар,
 * орендодавець, поверх, адреса, опис) може писати РЕДАКТОР КОМАНДИ у чужу
 * базу (`db_members`), а власник потім надсилає вивантажений файл третім
 * особам через `navigator.share`. Тобто ланцюг «чужий ввід → мій файл →
 * чужа машина» тут штатний, а не гіпотетичний.
 *
 * XLSX не зачеплений: `aoa_to_sheet` пише рядок типом `s`, тобто літералом.
 */
const RISKY_LEAD = /^[=+\-@\t\r]/

export function escapeCsvCell(s: string): string {
  return RISKY_LEAD.test(s) ? `'${s}` : s
}

/** Зворотний бік: щоб круговий рейс «експорт → імпорт» лишався тотожним. */
export function unescapeCsvCell(s: string): string {
  return s.startsWith("'") && RISKY_LEAD.test(s.slice(1)) ? s.slice(1) : s
}

export function toCsv(rows: (string | number | null | undefined)[][], delimiter = ','): string {
  const cell = (v: string | number | null | undefined): string => {
    // Числа не екрануємо: `-5` — це значення, а не формула, і префікс зробив
    // би з нього текст, який Excel більше не підсумує. Ризиковий провід
    // стосується лише РЯДКІВ, тобто того, що набрала людина.
    const s = v == null ? '' : typeof v === 'number' ? String(v) : escapeCsvCell(String(v))
    // Лапки, роздільник і будь-який перенос — три випадки, що вимагають
    // огорнути поле; подвоєна лапка всередині — єдиний спосіб її внести.
    return /["\r\n]/.test(s) || s.includes(delimiter)
      ? `"${s.replace(/"/g, '""')}"`
      : s
  }
  return rows.map((r) => r.map(cell).join(delimiter)).join('\r\n')
}

/** Excel відкриє UTF-8 як UTF-8 лише з BOM — інакше кирилиця стає «Ð.Ð°Ð·Ð²Ð°». */
export const CSV_BOM = '﻿'
