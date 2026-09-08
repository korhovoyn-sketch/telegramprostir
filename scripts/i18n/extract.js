/**
 * Витяг перекладних рядків через AST TypeScript — НЕ регекспом.
 *
 * Регексп тут структурно не годиться: він не відрізняє рядок-підпис від
 * рядка-ключа обʼєкта, від CSS-класу і від значення enum, а саме на цій
 * різниці стоїть коректність кодмоду. AST дає батьківський вузол, тобто
 * КОНТЕКСТ, у якому рядок вжито.
 *
 * Цей файл — ЄДИНЕ джерело правди і для екстракції, і для кодмоду: два
 * незалежні набори правил розійшлися б, і ключ у словнику перестав би
 * збігатися з ключем у виклику.
 */
const ts = require('typescript')
const fs = require('fs')
const path = require('path')

const CYR = /[а-яА-ЯіїєґІЇЄҐ]/

/** Місця, де кириличний рядок — ДАНІ, а не інтерфейс. Переклад їх зламав би. */
const SKIP_EXACT_FILES = new Set([
  // Аліаси імпорту зіставляються з заголовками ЧУЖОГО файлу; переклад
  // означав би, що застосунок перестає розуміти українські таблиці.
  'src/screens/ImportObjectsScreen.tsx:STATUS_ALIAS',
  'src/screens/ImportObjectsScreen.tsx:aliases',
])

function walkFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) walkFiles(p, out)
    else if (/\.tsx?$/.test(e.name)) out.push(p)
  }
  return out
}

/** Чи лежить вузол усередині оголошення з даним іменем (STATUS_ALIAS, aliases). */
function insideNamed(node, names) {
  for (let n = node.parent; n; n = n.parent) {
    if (ts.isVariableDeclaration(n) && n.name && names.has(n.name.getText())) return true
    if (ts.isPropertyAssignment(n) && n.name && names.has(n.name.getText())) return true
  }
  return false
}

const DATA_NAMES = new Set(['STATUS_ALIAS', 'aliases'])

/** Шаблон усередині `<style>` — це CSS, а не інтерфейс. Кирилиця там є лише
 *  в КОМЕНТАРЯХ правил, і «переклад» перетворив би таблицю стилів на ключ
 *  словника завдовжки 3440 символів. */
/**
 * Рядок, який ПОРІВНЮЮТЬ, — це дані, а не підпис. Правило свідомо загальне, а
 * не перелік функцій: воно ловить і майбутні входження.
 *
 * Що воно вже закрило:
 *   • `parseRentType`  — `.includes('добу')` розбирає комірку ЧУЖОГО CSV;
 *     переклад означав би, що застосунок перестає розуміти власний експорт.
 *   • `GuestDatabaseScreen` — `errorMsg.includes('не знайден')` класифікує
 *     повідомлення СЕРВЕРА (воно українське й від мови інтерфейсу не
 *     залежить). Переклад мовчки відправив би екран не в ту гілку: замість
 *     «недійсне посилання» показувався б повтор, і навпаки.
 */
const CMP_METHODS = new Set(['includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf'])
function isComparand(node) {
  const p = node.parent
  if (!p) return false
  if (ts.isBinaryExpression(p)) {
    const k = p.operatorToken.kind
    if (k === ts.SyntaxKind.EqualsEqualsEqualsToken || k === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        k === ts.SyntaxKind.EqualsEqualsToken || k === ts.SyntaxKind.ExclamationEqualsToken) return true
  }
  if (ts.isCaseClause(p)) return true
  if (ts.isCallExpression(p) && p.arguments.includes(node) &&
      ts.isPropertyAccessExpression(p.expression) && CMP_METHODS.has(p.expression.name.getText())) return true
  // Індексація мапи рядком: `LABELS['вільно']` — теж ключ, а не підпис.
  if (ts.isElementAccessExpression(p) && p.argumentExpression === node) return true
  return false
}

function insideStyleTag(node) {
  for (let n = node.parent; n; n = n.parent) {
    if (ts.isJsxElement(n) && n.openingElement.tagName.getText() === 'style') return true
  }
  return false
}

/** Шаблон → ключ із позиційними дірками: `${a} м²` → `{0} м²`. */
function templateKey(node) {
  let key = node.head.text
  node.templateSpans.forEach((span, i) => {
    key += `{${i}}` + span.literal.text
  })
  return key
}

function extract(file) {
  const src = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const hits = []

  const push = (node, key, kind) => {
    if (!CYR.test(key)) return
    if (insideNamed(node, DATA_NAMES)) return
    if (insideStyleTag(node)) return
    if (isComparand(node)) return
    const { line } = src.getLineAndCharacterOfPosition(node.getStart())
    hits.push({ key, kind, file, line: line + 1, start: node.getStart(), end: node.getEnd() })
  }

  const visit = (node) => {
    // Ключ обʼєкта — не підпис: `{ 'вільно': 'free' }` ліворуч перекладати не можна.
    if (ts.isPropertyAssignment(node) && node.name === node.initializer) { /* unreachable, для ясності */ }

    if (ts.isStringLiteral(node)) {
      const parent = node.parent
      // Рядок як ІМʼЯ властивості — це ключ мапи, тобто дані.
      const isPropName = ts.isPropertyAssignment(parent) && parent.name === node
      // Імпорт-шлях, JSX-атрибут класу тощо кирилиці не містять — фільтр CYR
      // їх і так відкидає, окремого правила не треба.
      if (!isPropName) push(node, node.text, 'string')
    } else if (ts.isNoSubstitutionTemplateLiteral(node)) {
      push(node, node.text, 'template0')
    } else if (ts.isTemplateExpression(node)) {
      push(node, templateKey(node), 'template')
    } else if (ts.isJsxText(node)) {
      const raw = node.getText()
      const trimmed = raw.trim()
      if (trimmed) push(node, trimmed, 'jsx')
    }
    ts.forEachChild(node, visit)
  }
  visit(src)
  return hits
}

const files = walkFiles('src')
const all = []
for (const f of files) all.push(...extract(f))

if (require.main === module) {
  const byKey = new Map()
  for (const h of all) {
    if (!byKey.has(h.key)) byKey.set(h.key, [])
    byKey.get(h.key).push(h)
  }
  const out = [...byKey.entries()]
    .sort((a, b) => a[0].localeCompare(b[0], 'uk'))
    .map(([key, hits]) => ({ key, kinds: [...new Set(hits.map(h => h.kind))], n: hits.length, files: [...new Set(hits.map(h => h.file))] }))
  fs.writeFileSync(process.argv[2] || 'i18n-keys.json', JSON.stringify(out, null, 1))
  console.error(`унікальних ключів: ${out.length}, входжень: ${all.length}`)
}

module.exports = { extract, walkFiles, CYR, templateKey, DATA_NAMES, insideNamed }
