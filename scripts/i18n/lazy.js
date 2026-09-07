/**
 * `tr()` НА РІВНІ МОДУЛЯ ЗАСТИГАЄ УКРАЇНСЬКОЮ.
 *
 * Словник вантажиться динамічно, тобто ПІЗНІШЕ за обчислення модулів. Отже
 * будь-яка константа виду `const LABELS = { x: tr('…') }` фіксує український
 * текст назавжди — і жоден перемикач мови його вже не змінить.
 *
 * Знайдено аудитом англійською: на першому ж екрані «Бізнес-центр» і
 * aria-мітки таббару лишались українськими, хоч решта екрана перекладена.
 * Усього 133 виклики у 25 константах.
 *
 * Лікуємо ліниві́стю, а не статичним імпортом словника: той коштував би
 * 25 КБ gz на КОЖНОМУ холодному старті, включно з українськими користувачами,
 * яким англійська не потрібна. Те саме правило, за яким `xlsx` і `jsPDF`
 * лежать поза критичним шляхом.
 */
const ts = require('typescript')
const fs = require('fs')

function convert(file, names) {
  const text = fs.readFileSync(file, 'utf8')
  const src = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const edits = []
  const targets = new Set(names)

  const visit = (n) => {
    // 1. Саме оголошення → лінива функція.
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && targets.has(n.name.text) && n.initializer) {
      const init = n.initializer
      edits.push({ start: init.getStart(), end: init.getEnd(), repl: `() => (${init.getText()})` })
      // тип-анотацію знімаємо: `Record<…>` більше не описує функцію
      if (n.type) edits.push({ start: n.name.getEnd(), end: n.type.getEnd(), repl: '' })
      return
    }
    // 2. Кожне ВЖИВАННЯ → виклик.
    if (ts.isIdentifier(n) && targets.has(n.text)) {
      const p = n.parent
      const isDecl = ts.isVariableDeclaration(p) && p.name === n
      const isImportExport = ts.isImportSpecifier(p) || ts.isExportSpecifier(p)
      const isProp = (ts.isPropertyAccessExpression(p) && p.name === n) ||
                     (ts.isPropertyAssignment(p) && p.name === n)
      if (!isDecl && !isImportExport && !isProp) {
        edits.push({ start: n.getEnd(), end: n.getEnd(), repl: '()' })
      }
    }
    ts.forEachChild(n, visit)
  }
  visit(src)

  if (!edits.length) return 0
  let out = text
  for (const e of edits.sort((a, b) => b.start - a.start || b.end - a.end)) {
    out = out.slice(0, e.start) + e.repl + out.slice(e.end)
  }
  fs.writeFileSync(file, out)
  return edits.length
}

if (require.main === module) {
  const [file, ...names] = process.argv.slice(2)
  console.log(`${file}: ${convert(file, names)} правок (${names.join(', ')})`)
}
module.exports = { convert }
