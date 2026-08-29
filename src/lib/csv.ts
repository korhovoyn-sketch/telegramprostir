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
    .map((r) => r.map((c) => c.trim()))
    .filter((r) => r.some((c) => c !== ''))
}
