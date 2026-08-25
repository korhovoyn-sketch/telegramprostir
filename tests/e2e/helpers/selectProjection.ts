/**
 * Розбір PostgREST-параметра `select=` у дерево запитаних полів.
 *
 * Підтримує рівно те, чим користується застосунок: список через кому,
 * `alias:table(вкладені,поля)` і `*`. Кома всередині дужок НЕ розділяє —
 * інакше вбудовані відношення різались би навпіл.
 */
export type SelectNode = { all: boolean; fields: Map<string, SelectNode | null> }

export function parseSelect(sel: string): SelectNode {
  const node: SelectNode = { all: false, fields: new Map() }
  let depth = 0, buf = ''
  const parts: string[] = []
  for (const ch of sel) {
    if (ch === '(') depth++
    if (ch === ')') depth--
    if (ch === ',' && depth === 0) { parts.push(buf); buf = '' } else buf += ch
  }
  if (buf.trim()) parts.push(buf)

  for (const raw of parts) {
    const part = raw.trim()
    if (!part) continue
    if (part === '*') { node.all = true; continue }
    const open = part.indexOf('(')
    if (open === -1) {
      // `alias:column` теж буває — ключ у відповіді це alias.
      node.fields.set(part.split(':')[0].trim(), null)
      continue
    }
    const head = part.slice(0, open).trim()
    const inner = part.slice(open + 1, part.lastIndexOf(')'))
    const alias = head.includes(':') ? head.split(':')[0].trim() : head
    // Агрегати (`collection_properties(count)`) — не проєктуємо, лишаємо як є.
    node.fields.set(alias, /^\s*count\s*$/.test(inner) ? null : parseSelect(inner))
  }
  return node
}

export function project(value: unknown, node: SelectNode): unknown {
  if (Array.isArray(value)) return value.map((v) => project(v, node))
  if (value === null || typeof value !== 'object') return value
  if (node.all && node.fields.size === 0) return value

  const row = value as Record<string, unknown>
  const out: Record<string, unknown> = {}
  // `*` разом із вбудованими: беремо всі скалярні поля рядка, а вбудовані —
  // тільки запитані (саме так поводиться PostgREST).
  if (node.all) for (const [k, v] of Object.entries(row)) if (!Array.isArray(v) || node.fields.has(k)) out[k] = v
  for (const [key, child] of node.fields) {
    if (!(key in row)) continue
    out[key] = child ? project(row[key], child) : row[key]
  }
  return out
}

