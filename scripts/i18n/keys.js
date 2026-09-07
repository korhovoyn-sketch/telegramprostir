/**
 * Ключі беруться з ВИКЛИКІВ `tr()`/`tx()`, а не з евристики «схоже на текст».
 * Це робить словник і код одним джерелом: ключ, якого немає у виклику, —
 * осиротілий, а виклик без ключа — прогалина перекладу. Обидва ловить гард.
 */
const ts = require('typescript')
const fs = require('fs')
const { walkFiles } = require('./extract.js')

function keysOf(file) {
  const src = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const out = []
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) &&
        (n.expression.text === 'tr' || n.expression.text === 'tx')) {
      const a = n.arguments[0]
      if (a && (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))) out.push(a.text)
    }
    ts.forEachChild(n, visit)
  }
  visit(src)
  return out
}

function allKeys() {
  const m = new Map()
  for (const f of walkFiles('src')) {
    if (f.endsWith('lib/i18n.ts') || f.endsWith('lib/tx.tsx')) continue
    for (const k of keysOf(f)) m.set(k, (m.get(k) || 0) + 1)
  }
  return m
}

if (require.main === module) {
  const m = allKeys()
  const sorted = [...m.keys()].sort((a, b) => a.localeCompare(b, 'uk'))
  fs.writeFileSync(process.argv[2] || 'keys.json', JSON.stringify(sorted, null, 1))
  console.error(`ключів: ${sorted.length}, викликів: ${[...m.values()].reduce((a, b) => a + b, 0)}`)
}
module.exports = { allKeys, keysOf }
