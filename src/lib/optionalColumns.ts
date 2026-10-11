/**
 * Колонки, яких може ще не бути в базі, бо їхню міграцію не накочено:
 * `folder_id` (043) і `landlord_name` (064).
 *
 * PostgREST на невідому колонку відповідає 400 на ВЕСЬ запит — і в `select=`,
 * і в `columns=` масової вставки, і в тілі запису. Тож кожен запит, що згадує
 * таку колонку, мусить мати ретрай без неї; інакше фронт, задеплоєний раніше
 * за міграцію, не може нічого зберегти, хоча списки малює нормально (вони
 * ретрай мали). Саме так і було: ретрай стояв лише на ЧИТАННІ.
 *
 * Ретрай знімає ВСІ опційні колонки одразу, а не ту, на яку впав запит:
 * на бекенді без обох міграцій зняття однієї дало б другий 400.
 */
export const OPTIONAL_COLUMNS = ['folder_id', 'landlord_name'] as const

export function isMissingOptionalColumn(e: unknown): boolean {
  const err = e as { code?: string; message?: string } | null
  // 42703 — невідома колонка в select (Postgres); PGRST204 — невідома колонка
  // в тілі чи `columns=` запису (кеш схеми PostgREST). Імʼя в повідомленні —
  // запасний шлях для обох.
  return err?.code === '42703' || err?.code === 'PGRST204'
    || OPTIONAL_COLUMNS.some((c) => new RegExp(`\\b${c}\\b`, 'i').test(err?.message ?? ''))
}

/**
 * Прибирає опційні колонки з рядка `select=` верхнього рівня. Ріже по комах
 * лише на нульовій глибині дужок: вкладений вибір (`photos:property_photos(…)`)
 * лишається цілим.
 */
export function stripOptionalSelect(sel: string): string {
  const parts: string[] = []
  let depth = 0
  let cur = ''
  for (const ch of sel) {
    if (ch === '(') depth++
    else if (ch === ')') depth--
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue }
    cur += ch
  }
  parts.push(cur)
  const optional: readonly string[] = OPTIONAL_COLUMNS
  return parts.filter((p) => !optional.includes(p.trim())).join(',')
}

/**
 * Прибирає опційні КЛЮЧІ з тіла запису. Видаляє ключ цілком, а не ставить
 * `undefined`: supabase-js для масиву будує `columns=` з `Object.keys`, тож
 * ключ зі значенням `undefined` там однаково зʼявився б.
 */
export function stripOptionalKeys<T extends object>(row: T): T {
  const copy = { ...row } as Record<string, unknown>
  for (const c of OPTIONAL_COLUMNS) delete copy[c]
  return copy as T
}

/**
 * Виконує запит, а на «невідому колонку» — ще раз у режимі `pre`, де викликач
 * сам прибирає опційні колонки з `select=` і тіла. Одна спроба ретраю: якщо
 * впало вдруге, це вже інша помилка, і її треба показати.
 */
export async function withOptionalColumns<R extends { error: unknown }>(
  run: (pre: boolean) => PromiseLike<R>,
): Promise<R> {
  const first = await run(false)
  if (first.error && isMissingOptionalColumn(first.error)) return run(true)
  return first
}
