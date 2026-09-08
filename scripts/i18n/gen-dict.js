/**
 * Збирає `src/lib/dict-en.ts` зі словника перекладів.
 *
 * Файл ГЕНЕРОВАНИЙ, і це навмисно: правити треба джерело перекладів, а не
 * результат — інакше наступна генерація мовчки затре ручну правку. Гард
 * `i18n.test.ts` тримає інваріант «ключ у коді ↔ ключ у словнику».
 */
const fs = require('fs')
const { allKeys } = require('./keys.js')

const dictPath = process.argv[2]
if (!dictPath) { console.error('вкажіть шлях до dict.json [і, опційно, вихідний файл]'); process.exit(1) }
const dict = JSON.parse(fs.readFileSync(dictPath, 'utf8'))
const keys = [...allKeys().keys()].sort((a, b) => a.localeCompare(b, 'uk'))

const missing = keys.filter((k) => !dict[k])
if (missing.length) {
  console.error(`БЕЗ ПЕРЕКЛАДУ: ${missing.length}`)
  missing.slice(0, 10).forEach((k) => console.error('   ', JSON.stringify(k)))
  process.exit(1)
}

const esc = (s) => JSON.stringify(s)
const body = keys.map((k) => `  ${esc(k)}: ${esc(dict[k])},`).join('\n')

const outPath = process.argv[3] || 'src/lib/dict-en.ts'
fs.writeFileSync(outPath, `/**
 * АНГЛІЙСЬКИЙ СЛОВНИК — ГЕНЕРОВАНИЙ ФАЙЛ, руками не правити.
 *
 * Ключ — український рядок із виклику \`tr()\`/\`tx()\`; значення — переклад.
 * ДЖЕРЕЛО — \`scripts/i18n/dict.json\`; збирає \`scripts/i18n/gen-dict.js\`:
 *
 *     node scripts/i18n/gen-dict.js scripts/i18n/dict.json
 *
 * Джерело — памʼять перекладів, тож воно може містити БІЛЬШЕ за цей файл:
 * генератор виписує лише ключі, які СПРАВДІ Є В КОДІ, тож ключ, що осиротів
 * після рефакторингу, зникає звідси сам, а переклад лишається на випадок,
 * коли рядок повернеться. Гард \`tests/unit/i18n.test.ts\` падає, щойно код
 * і словник розійдуться в будь-який бік, і окремо — щойно цей файл виявиться
 * ПРАВЛЕНИМ РУКАМИ, тобто не збігається з тим, що дає генератор.
 *
 * ГЛОСАРІЙ (терміни, що мусять читатись однаково по всьому застосунку):
 *   обʼєкт → unit            база → database        підбірка → collection
 *   Вільно → Vacant          Зайнято → Occupied     Продаж → For sale
 *   орендар → tenant         орендодавець → landlord
 *   договір → lease          експлуатаційні → service charges
 *   корисна площа → usable area   розрахункова площа → billable area
 *
 * «Вільно» — саме \`Vacant\`, а не \`Free\`: англійською \`free\` читається
 * як «безкоштовно», тобто статус обʼєкта перетворився б на обіцянку ціни.
 *
 * Завантажується ДИНАМІЧНО (\`await import\`) і лише для англійської — щоб
 * український користувач, якого більшість, не платив за цей файл на
 * холодному старті. Те саме правило, що для \`xlsx\` і \`jsPDF\`.
 */
export const EN: Record<string, string> = {
${body}
}
`)
console.error(`dict-en.ts: ${keys.length} ключів`)
