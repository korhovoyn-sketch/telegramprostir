/**
 * Мінімальний PostgREST для моків: фільтри рядка запиту і пагінація.
 *
 * Харнес за замовчуванням віддає фікстуру ЦІЛКОМ, тобто не бачить, що
 * клієнт ПИТАВ. Для запитів, де ціна помилки — у самій вибірці (які обʼєкти
 * потрапили в архів, чи дочитано всі сторінки), такий мок структурно сліпий:
 * код, що забув частину `in.(…)`, отримав би повну фікстуру і пройшов.
 *
 * Підтримано рівно те, що шле застосунок: `eq`, `neq`, `in`, `gte`, `lte`,
 * `gt`, `lt`, `is.null`, плюс `offset`/`limit`. `maxRows` моделює серверну
 * межу Supabase (`max_rows`, дефолт 1000): відповідь без пагінації обрізається
 * МОВЧКИ — так само, як на справжньому бекенді.
 */
export function filterRows<T extends Record<string, unknown>>(
  rawUrl: string, rows: T[], opts: { maxRows?: number } = {},
): T[] {
  return queryRows(rawUrl, rows, opts).rows
}

/** Те саме, плюс повна кількість ДО пагінації і зсув — для `Content-Range`. */
export function queryRows<T extends Record<string, unknown>>(
  rawUrl: string, rows: T[], opts: { maxRows?: number } = {},
): { rows: T[]; total: number; offset: number } {
  const url = new URL(rawUrl)
  let out = rows
  for (const [key, raw] of url.searchParams) {
    if (['select', 'order', 'limit', 'offset', 'on_conflict', 'columns'].includes(key)) continue
    const dot = raw.indexOf('.')
    if (dot < 0) continue
    const op = raw.slice(0, dot)
    const val = raw.slice(dot + 1)
    out = out.filter((r) => {
      const v = r[key]
      const s = v == null ? null : String(v)
      switch (op) {
        case 'eq': return s === val
        case 'neq': return s !== val
        case 'gte': return s != null && s >= val
        case 'lte': return s != null && s <= val
        case 'gt': return s != null && s > val
        case 'lt': return s != null && s < val
        case 'is': return val === 'null' ? v == null : s === val
        case 'in': {
          const list = val.replace(/^\(|\)$/g, '').split(',').map((x) => x.replace(/^"|"$/g, ''))
          return s != null && list.includes(s)
        }
        default: return true
      }
    })
  }
  const offset = Number(url.searchParams.get('offset') ?? 0)
  const limitParam = url.searchParams.get('limit')
  const cap = opts.maxRows ?? Infinity
  const limit = Math.min(limitParam == null ? Infinity : Number(limitParam), cap)
  return { rows: out.slice(offset, offset + limit), total: out.length, offset }
}
