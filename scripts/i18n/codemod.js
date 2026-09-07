/**
 * Кодмод: кириличні рядки → t() / tx().
 *
 * Правила відбору живуть в `extract.js` — ЄДИНОМУ джерелі і для словника, і
 * для замін. Дві копії розійшлися б, і ключ у виклику перестав би збігатися з
 * ключем у словнику саме там, де це найважче помітити.
 *
 * ПРОБІЛИ JSX — головна тонкість. `<div>\n  Текст\n</div>` має текстовий вузол
 * "\n  Текст\n", і JSX сам зрізає пробіли, що містять ПЕРЕНОС. А от
 * `<Icon /> Текст` має провідний пробіл БЕЗ переносу, і він значущий: замінивши
 * вузол цілком, ми склеїли б іконку з текстом. Тому пробіли по краях
 * зберігаються рівно тоді, коли в них немає `\n`.
 */
const ts = require('typescript')
const fs = require('fs')
const { walkFiles, CYR, templateKey, DATA_NAMES, insideNamed } = require('./extract.js')

const q = (s) => "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'"

/** Уже загорнуте руками — другий раз не чіпаємо. */
function alreadyWrapped(node) {
  const p = node.parent
  return p && ts.isCallExpression(p) && p.arguments[0] === node &&
    ts.isIdentifier(p.expression) && (p.expression.text === 'tr' || p.expression.text === 'tx')
}

function run(file, dry) {
  const text = fs.readFileSync(file, 'utf8')
  const src = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const edits = []

  const skip = (n) => insideNamed(n, DATA_NAMES) || alreadyWrapped(n) || insideStyle(n) || comparand(n)
  const insideStyle = (n) => { for (let a = n.parent; a; a = a.parent) if (ts.isJsxElement(a) && a.openingElement.tagName.getText() === 'style') return true; return false }
  const CMP = new Set(['includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf'])
  const comparand = (n) => {
    const p = n.parent; if (!p) return false
    if (ts.isBinaryExpression(p)) { const k = p.operatorToken.kind
      if (k === ts.SyntaxKind.EqualsEqualsEqualsToken || k === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
          k === ts.SyntaxKind.EqualsEqualsToken || k === ts.SyntaxKind.ExclamationEqualsToken) return true }
    if (ts.isCaseClause(p)) return true
    if (ts.isCallExpression(p) && p.arguments.includes(n) && ts.isPropertyAccessExpression(p.expression) && CMP.has(p.expression.name.getText())) return true
    if (ts.isElementAccessExpression(p) && p.argumentExpression === n) return true
    return false
  }

  const visit = (node) => {
    if (ts.isStringLiteral(node) && CYR.test(node.text)) {
      const p = node.parent
      const isPropName = ts.isPropertyAssignment(p) && p.name === node
      if (!isPropName && !skip(node)) {
        const call = `tr(${q(node.text)})`
        // Значення JSX-атрибута мусить стати виразом у фігурних дужках.
        const repl = ts.isJsxAttribute(p) ? `{${call}}` : call
        edits.push({ start: node.getStart(), end: node.getEnd(), repl })
      }
    } else if (ts.isNoSubstitutionTemplateLiteral(node) && CYR.test(node.text)) {
      if (!skip(node)) edits.push({ start: node.getStart(), end: node.getEnd(), repl: `tr(${q(node.text)})` })
    } else if (ts.isTemplateExpression(node) && CYR.test(node.getText())) {
      if (!skip(node)) {
        const key = templateKey(node)
        const args = node.templateSpans.map((s) => s.expression.getText())
        edits.push({ start: node.getStart(), end: node.getEnd(), repl: `tr(${q(key)}, ${args.join(', ')})` })
      }
    } else if (ts.isJsxText(node)) {
      const raw = node.getText()
      if (CYR.test(raw) && !skip(node)) {
        // `&quot;` у JSX рендериться як лапка, а в JS-рядку лишився б видимим
        // текстом «&quot;». Знайдено оглядом першого ж прогону.
        const decode = (x) => x.replace(/&quot;/g, '"').replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, '\u00a0').replace(/&#(\d+);/g, (_, d) => String.fromCharCode(+d))
        const core = decode(raw.trim())
        const rawTrim = raw.trim()
        const lead = raw.slice(0, raw.indexOf(rawTrim[0]))
        const tail = raw.slice(raw.indexOf(rawTrim[0]) + rawTrim.length)
        // Пробіл БЕЗ переносу значущий — JSX його не зрізає.
        const keepLead = lead && !lead.includes('\n') ? "{' '}" : lead.includes('\n') ? lead : ''
        const keepTail = tail && !tail.includes('\n') ? "{' '}" : tail.includes('\n') ? tail : ''
        edits.push({ start: node.getStart(), end: node.getEnd(), repl: `${keepLead}{tr(${q(core.replace(/\s+/g, ' '))})}${keepTail}` })
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(src)

  if (!edits.length) return 0
  // ВКЛАДЕНІ ВУЗЛИ. Шаблон може містити всередині `${}` інший перекладний
  // рядок — і тоді дві заміни ПЕРЕКРИВАЮТЬСЯ, бо позиції рахувались по
  // однаковому вихідному тексту. Перший прогін через це видав синтаксично
  // биту `…видалено')зворотно.\``.
  //
  // Лікує не хитріша арифметика позицій, а порядок: лишаємо ЗОВНІШНЮ заміну
  // (її ключ уже несе `{0}`, а аргументом іде сирий текст виразу), а
  // вкладені доганяє НАСТУПНИЙ прохід — після заміни шаблон зникає, і
  // внутрішній рядок стає звичайним аргументом. Тому прогін іде до збіжності.
  const outer = edits.filter((e) => !edits.some((o) => o !== e && o.start <= e.start && o.end >= e.end))
  let out = text
  for (const e of outer.sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.repl + out.slice(e.end)
  edits.length = outer.length
  if (!/from '@\/lib\/i18n'/.test(out)) {
    // Позиція з AST, а не з regex: `^import .*$` вважає ПЕРШИЙ рядок
    // багаторядкового `import {\n  a, b,\n} from '…'` цілим імпортом і
    // вставляє новий рядок ВСЕРЕДИНУ дужок. Наступано.
    //
    // Позиції імпортів беруться з вихідного AST і лишаються дійсними в `out`:
    // усі заміни стоять НИЖЧЕ (кирилиці в імпортах немає за побудовою).
    const imports = src.statements.filter(ts.isImportDeclaration)
    const at = imports.length ? imports[imports.length - 1].getEnd() : 0
    out = out.slice(0, at) + "\nimport { tr } from '@/lib/i18n'" + out.slice(at)
  }
  if (!dry) fs.writeFileSync(file, out)
  return edits.length
}

// `require.main` ОБОВʼЯЗКОВИЙ: без нього `require('./codemod')` виконує прогін
// на модульному рівні — і без `--dry` у тому argv переписує всі 65 файлів.
// Наступано.
if (require.main === module) {
  const dry = process.argv.includes('--dry')
  const only = process.argv.find((a) => a.startsWith('--only='))
  const files = only ? [only.slice(7)] : walkFiles('src')
  let total = 0, pass = 0
  // До збіжності: кожен прохід розкриває один рівень вкладеності.
  for (;;) {
    let round = 0
    for (const f of files) {
      if (f.endsWith('lib/i18n.ts') || f.endsWith('lib/tx.tsx')) continue
      round += run(f, dry)
    }
    total += round
    pass++
    if (!round || dry || pass > 6) break
  }
  console.log(`${dry ? '[dry] ' : ''}замін: ${total}, проходів: ${pass}`)
}

module.exports = { run }
