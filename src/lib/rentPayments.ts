import { basisArea, monthlyRent } from '@/lib/utils'
import type { Property } from '@/types'

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
  return d.toLocaleDateString('uk-UA', { day: 'numeric', month: 'long' })
}
