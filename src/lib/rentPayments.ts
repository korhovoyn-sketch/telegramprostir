import { basisArea, monthlyRent } from '@/lib/utils'
import type { Property } from '@/types'
import { locale } from './i18n'

/**
 * Спільні для PaymentCalendarScreen/PaymentScheduleScreen/PaymentConfirmScreen:
 * колонки, які інакше розійшлись би copy-paste по трьох файлах, і дві чисті
 * функції без побічних ефектів. Свідомо НЕ хук — жодного стану, жодного
 * власного supabase-виклику: кожна CRUD-операція лишається рівно в одному
 * місці (upsert розкладу — PaymentScheduleScreen, upsert платежу —
 * PaymentConfirmScreen, delete/unpay — PaymentCalendarScreen).
 */

export const RENT_PAYMENT_COLUMNS =
  'id,property_id,owner_id,due_day,notify_days_before,is_active,created_at,updated_at'

export const RENT_PAYMENT_RECORD_COLUMNS =
  'id,property_id,owner_id,due_date,paid_at,amount,status,notes,created_at,updated_at'

// Expected monthly rent for a property. rent_rate alone is WRONG for per_m2
// (it's the $/m² rate) and for per_day (daily) — monthlyRent normalises every
// unit to a month so the confirm-payment default matches the other screens.
export function expectedRent(p: Property): number {
  if (!p.rent_rate) return 0
  // Площа — через `basisArea`, а не сира `area_useful`. Міграція 042 зробила
  // `area_basis` тим, що ВИРІШУЄ, на яку площу множиться $/м²-ставка, і всі
  // інші поверхні (картка, деталь, експорт, /v) її враховують. Тут не
  // враховувалась, тож календар і форма підтвердження друкували ІНШУ суму, ніж
  // решта застосунку, — а вона потрапляє в `rent_payment_records.amount`, тобто
  // стає архівним записом про те, скільки нібито отримали.
  return monthlyRent(basisArea(p.area_useful, p.area_total, p.area_basis), p.rent_rate, p.rent_type)
}

export function fmtDueDate(dateStr: string): string {
  const d = new Date(dateStr + 'T00:00:00')
  return d.toLocaleDateString(locale(), { day: 'numeric', month: 'long' })
}

/**
 * Чи належить платіж на `dueDate` до ЦІЄЇ оренди.
 *
 * Розклад задає лише день місяця, тож календар і блок «Найближчі платежі»
 * генерують дату для поточного місяця незалежно від того, коли оренда почалась.
 * Обʼєкт, зданий 18-го з днем оплати 5-го, одразу показував «Прострочено на 13
 * днів» — за місяць, коли орендаря ще не було. Це найчастіший ПЕРШИЙ сценарій
 * (здав посеред місяця → налаштував розклад), і хибна тривога про гроші в ньому
 * дискредитувала б увесь блок.
 *
 * Межа — лише ПОЧАТОК договору: дата до нього не борг за побудовою. Кінець
 * свідомо НЕ обмежує: обʼєкт, що досі «Зайнято» після кінця договору, — це
 * орендар, який лишився, і платіж за ним справжній. Без дати початку (поле
 * необовʼязкове) обмеження немає — інакше ми ховали б справжній борг.
 * Порівняння рядків коректне: обидва — ISO `YYYY-MM-DD`.
 */
export function isOwedUnderLease(dueDate: string, leaseStart?: string | null): boolean {
  return !leaseStart || dueDate >= leaseStart.slice(0, 10)
}

/** Не глибше року назад: старіший борг — справа архіву й розмови, не календаря. */
export const ARREARS_MONTHS_MAX = 12

/**
 * Дата платежу в місяці зі зсувом `offset` від поточного (ISO `YYYY-MM-DD`).
 * День обмежується довжиною місяця: 31-е в лютому інакше дало б 3 березня.
 */
export function dueDateFor(offset: number, dueDay: number, now: Date = new Date()): string {
  const d = new Date(now.getFullYear(), now.getMonth() + offset, 1)
  const last = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate()
  const day = Math.min(Math.max(1, dueDay), last)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`
}

/**
 * З якого місяця (зсув ≤ 0 від поточного) розклад УЖЕ існував.
 *
 * Календар і «Найближчі платежі» дивились лише від ПОТОЧНОГО місяця вперед, тож
 * неоплачена оренда за вересень 1 жовтня просто ЗНИКАЛА — з календаря, з
 * лічильника «Прострочено» і зі сповіщень, хоча запису про оплату немає. Тобто
 * борг забувався на межі місяця, найгірше з можливого для обліку оренди.
 *
 * Межа знизу — місяць створення розкладу: раніше застосунок оплат не
 * відстежував, і «борг» за ті місяці був би вигадкою (людина могла отримати
 * гроші до того, як завела розклад).
 */
export function trackedFromOffset(scheduleCreatedAt: string | null | undefined, now: Date = new Date()): number {
  if (!scheduleCreatedAt) return 0
  const c = new Date(scheduleCreatedAt)
  if (Number.isNaN(c.getTime())) return 0
  const diff = (c.getFullYear() - now.getFullYear()) * 12 + (c.getMonth() - now.getMonth())
  return Math.max(-ARREARS_MONTHS_MAX, Math.min(0, diff))
}
