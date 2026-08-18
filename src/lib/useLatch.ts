import { useRef } from 'react'

/**
 * Тримає останнє НЕнульове значення, поки нове не прийде. Потрібен шитам, чиї
 * дані викликач нулює РАЗОМ із закриттям (`setReq(null)`, `setNewLink(null)`):
 * без латча `ActionSheet` встиг би домалювати кадр вихідної анімації (~300мс)
 * із порожнім заголовком, бо `open` і дані падають в один рендер.
 *
 * Мутація рефа під час рендера — навмисно синхронна: латчу не можна відстати
 * від значення навіть на один кадр, а `useEffect` спрацював би вже ПІСЛЯ
 * першого рендера з `null`.
 */
export function useLatch<T>(value: T | null | undefined): T | null {
  const ref = useRef<T | null>(value ?? null)
  if (value !== null && value !== undefined) ref.current = value
  return ref.current
}
