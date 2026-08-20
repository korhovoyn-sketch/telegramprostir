/**
 * РІШЕННЯ рейт-лімітера, відокремлене від вводу-виводу.
 *
 * Причина розділення практична, а не естетична: edge-функції не мали ЖОДНОГО
 * тесту — і саме там живе вся логіка ідентичності. Прогнати їх цілком звідси
 * неможливо (Deno в пісочниці немає, імпорти йдуть з esm.sh), але рішення
 * лімітера — чиста функція від рядка БД, тож воно перевіряється звичайним
 * юнітом. Модуль СВІДОМО без жодного імпорту, інакше vitest його не візьме.
 */

export interface RateRow {
  count: number
  reset_at: string
}

export type RateDecision =
  | { allow: true; action: 'reset' }        // вікно минуло або рядка немає → почати з 1
  | { allow: true; action: 'increment' }    // у межах ліміту → +1
  | { allow: false; action: 'none' }        // вичерпано або збій → відмовити

/**
 * @param row      те, що повернув SELECT (null = рядка немає)
 * @param failed   чи сам запит завершився помилкою
 * @param nowMs    поточний час
 * @param maxRequests стеля за вікно
 */
export function rateDecision(
  row: RateRow | null | undefined,
  failed: boolean,
  nowMs: number,
  maxRequests: number,
): RateDecision {
  // FAIL CLOSED. `supabase-js` РЕЗОЛВИТЬ збій запиту як `{data:null, error}` і
  // НЕ кидає, тож `try/catch` навколо нього не спрацює ніколи. Без цієї гілки
  // будь-яка невдача (немає таблиці, зміна RLS, 5xx, вичерпаний пул) виглядала
  // б як «рядка немає» → пропуск, тобто рівно навпаки до наміру.
  if (failed) return { allow: false, action: 'none' }

  if (!row) return { allow: true, action: 'reset' }

  // Порівняння за ЧАСОМ, а не лексикографічне: рядок з БД може прийти в іншій
  // роздільності («…Z» проти «…+00:00»), і рядкове `<` тоді бреше.
  const reset = Date.parse(row.reset_at)
  if (!Number.isFinite(reset) || reset <= nowMs) return { allow: true, action: 'reset' }

  if (row.count >= maxRequests) return { allow: false, action: 'none' }
  return { allow: true, action: 'increment' }
}
