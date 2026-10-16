import { isMissingOptionalColumn } from './optionalColumns'

/**
 * Дочитати ВСІ сторінки вибірки.
 *
 * Supabase обрізає відповідь серверною межею `max_rows` (дефолт 1000) — і
 * робить це МОВЧКИ: ні помилки, ні позначки, просто перші 1000 рядків. Для
 * списку обʼєктів це «не видно хвоста», а для грошей це неправда: «Всього
 * отримано за весь час» без решти платежів, сплачена оренда, що малюється
 * «Прострочено», бо її запис не влізув у вікно.
 *
 * Межа береться з `Content-Range` першої сторінки (`count: 'exact'`), а не з
 * довжини сторінки: якщо сервер налаштований на МЕНШУ межу, ніж ми просимо,
 * «сторінка коротша за запитану» вже не означала б «це кінець». Без лічильника
 * (null) — повертаємось до цієї евристики, бо іншої немає.
 *
 * Сторінки мусять мати СТІЙКИЙ порядок (`.order(…)` з унікальним хвостом,
 * напр. `id`), інакше рядок на межі сторінок можна загубити або подвоїти.
 */
export const PAGE_SIZE = 1000

type Page<T> = { data: T[] | null; error: unknown; count?: number | null }

export async function fetchAllRows<T>(
  page: (from: number, to: number, first: boolean) => PromiseLike<Page<T>>,
): Promise<T[]> {
  const head = await page(0, PAGE_SIZE - 1, true)
  if (head.error) throw head.error
  const out: T[] = [...(head.data ?? [])]
  const total = typeof head.count === 'number' ? head.count : null
  let last = out.length
  while (total != null ? out.length < total : last === PAGE_SIZE) {
    const next = await page(out.length, out.length + PAGE_SIZE - 1, false)
    if (next.error) throw next.error
    const rows = next.data ?? []
    // Порожня сторінка — кінець за будь-яких умов: інакше розбіжність між
    // лічильником і даними (рядок видалили між запитами) крутила б цикл вічно.
    if (rows.length === 0) break
    out.push(...rows)
    last = rows.length
  }
  return out
}

/**
 * Те саме, але з ретраєм без опційних колонок (див. `optionalColumns.ts`).
 * Окремо, а не прапорцем у `fetchAllRows`: невідома колонка падає вже на
 * ПЕРШІЙ сторінці, і повторювати треба весь обхід, а не одну сторінку.
 */
//
// `data: unknown` — свідомо: список колонок тут ДВОВАРІАНТНИЙ (`pre ? A : B`),
// і парсер типів supabase-js на обʼєднанні двох літералів дає ParserError.
// Форму рядка задає викликач через `T`, як і в `fetchAllRows`.
type LoosePage = { data: unknown; error: unknown; count?: number | null }

export async function fetchAllRowsOptional<T>(
  page: (pre: boolean, from: number, to: number, first: boolean) => PromiseLike<LoosePage>,
): Promise<T[]> {
  const run = (pre: boolean) => fetchAllRows<T>((from, to, first) =>
    page(pre, from, to, first) as PromiseLike<Page<T>>)
  try {
    return await run(false)
  } catch (e) {
    if (!isMissingOptionalColumn(e)) throw e
    return run(true)
  }
}
