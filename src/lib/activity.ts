import { STATUS_LABELS, formatPrice, rentUnitLabel } from '@/lib/utils'
import { locale, tr } from '@/lib/i18n'
import type { DbActivity } from '@/types'

/**
 * Подія журналу змін (073) → рядок для людини.
 *
 * Сервер пише ФАКТИ (`kind` + `details`), а текст будується тут: так мова
 * інтерфейсу міняється без міграції, а старі події перечитуються новою мовою.
 *
 * Без дієслів у минулому часі від імені людини («Олена здала…»): українське
 * дієслово вимагає роду, а його ми не знаємо. Подія — безособова («Здано в
 * оренду: ТОВ Х»), а ХТО — окремо, в підписі рядка.
 */
export type ActivityTone = 'ok' | 'warn' | 'err' | 'info' | 'plain'
export type ActivityIcon =
  | 'plus' | 'trash' | 'edit' | 'move' | 'user' | 'status' | 'money' | 'calendar' | 'file' | 'photo'

export interface ActivityView {
  icon: ActivityIcon
  tone: ActivityTone
  title: string
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null)
const num = (v: unknown): number | null => {
  const n = typeof v === 'string' ? Number(v) : v
  return typeof n === 'number' && Number.isFinite(n) ? n : null
}

/** «за серпень 2026» — місяць ПЕРІОДУ платежу, а не день запису.
 *  Пробіл перед «р.» нерозривний: ICU ставить звичайний, і на 375px «р.»
 *  відривалось на окремий рядок. */
function periodOf(dueDate: unknown): string {
  const d = str(dueDate)
  if (!d) return '—'
  const date = new Date(`${d.slice(0, 10)}T00:00:00`)
  return Number.isNaN(date.getTime())
    ? d
    : date.toLocaleDateString(locale(), { month: 'long', year: 'numeric' }).replace(/ р\.$/, ' р.')
}

function rateOf(t: Record<string, unknown> | null, currency?: string): string {
  const rate = num(t?.rent_rate)
  return rate == null ? '—' : `${formatPrice(rate, currency)}${rentUnitLabel(str(t?.rent_type))}`
}

function statusOf(s: unknown): string {
  const key = str(s)
  return (key && STATUS_LABELS()[key]) || key || '—'
}

export function describeActivity(a: Pick<DbActivity, 'kind' | 'details'>, currency?: string): ActivityView {
  const d = a.details ?? {}
  const money = (v: unknown) => {
    const n = num(v)
    return n == null ? '—' : formatPrice(n, currency)
  }

  switch (a.kind) {
    case 'property_created':
      return { icon: 'plus', tone: 'info', title: tr('Створено обʼєкт') }
    case 'property_deleted':
      return { icon: 'trash', tone: 'err', title: tr('Видалено обʼєкт') }
    case 'property_renamed':
      return { icon: 'edit', tone: 'plain', title: tr('Перейменовано: «{0}» → «{1}»', str(d.from) ?? '—', str(d.to) ?? '—') }
    case 'property_moved':
      return d.direction === 'out'
        ? { icon: 'move', tone: 'plain', title: tr('Переміщено в базу «{0}»', str(d.db) ?? '—') }
        : { icon: 'move', tone: 'plain', title: tr('Переміщено з бази «{0}»', str(d.db) ?? '—') }
    case 'property_rented': {
      const tenant = str(d.tenant)
      return { icon: 'user', tone: 'ok', title: tenant ? tr('Здано в оренду: {0}', tenant) : tr('Здано в оренду') }
    }
    case 'property_vacated': {
      const tenant = str(d.tenant)
      return { icon: 'user', tone: 'warn', title: tenant ? tr('Звільнено, орендар був: {0}', tenant) : tr('Обʼєкт звільнено') }
    }
    case 'property_status':
      return { icon: 'status', tone: 'plain', title: tr('Статус: {0} → {1}', statusOf(d.from), statusOf(d.to)) }
    case 'tenant_changed':
      return { icon: 'user', tone: 'plain', title: tr('Орендар: {0} → {1}', str(d.from) ?? '—', str(d.to) ?? '—') }
    case 'terms_changed': {
      const from = (d.from ?? null) as Record<string, unknown> | null
      const to = (d.to ?? null) as Record<string, unknown> | null
      if (from?.rent_rate !== to?.rent_rate || from?.rent_type !== to?.rent_type) {
        return { icon: 'money', tone: 'info', title: tr('Ставка: {0} → {1}', rateOf(from, currency), rateOf(to, currency)) }
      }
      for (const key of ['area_total', 'area_useful'] as const) {
        if (from?.[key] !== to?.[key]) {
          const fmt = (v: unknown) => (num(v) == null ? '—' : String(num(v)))
          return { icon: 'edit', tone: 'plain', title: tr('Площа: {0} → {1} м²', fmt(from?.[key]), fmt(to?.[key])) }
        }
      }
      if (from?.utilities_rate !== to?.utilities_rate) {
        return { icon: 'money', tone: 'plain', title: tr('Експлуатаційні: {0} → {1}', money(from?.utilities_rate), money(to?.utilities_rate)) }
      }
      return { icon: 'edit', tone: 'plain', title: tr('Змінено базу розрахунку площі') }
    }
    case 'payment_received':
      return { icon: 'money', tone: 'ok', title: tr('Отримано {0} за {1}', money(d.amount), periodOf(d.due_date)) }
    case 'payment_edited':
      return num(d.from) === num(d.to)
        ? { icon: 'edit', tone: 'plain', title: tr('Змінено дату надходження за {0}', periodOf(d.due_date)) }
        : { icon: 'edit', tone: 'warn', title: tr('Виправлено надходження за {0}: {1} → {2}', periodOf(d.due_date), money(d.from), money(d.to)) }
    case 'payment_deleted':
      return { icon: 'trash', tone: 'err', title: tr('Видалено надходження {0} за {1}', money(d.amount), periodOf(d.due_date)) }
    case 'payment_cancelled':
      return { icon: 'trash', tone: 'err', title: tr('Скасовано платіж за {0}: {1}', periodOf(d.due_date), money(d.amount)) }
    case 'due_changed':
      return num(d.from) == null
        ? { icon: 'edit', tone: 'warn', title: tr('Сума за {0}: {1}', periodOf(d.due_date), money(d.to)) }
        : { icon: 'edit', tone: 'warn', title: tr('Сума за {0}: {1} → {2}', periodOf(d.due_date), money(d.from), money(d.to)) }
    case 'schedule_set':
      return d.active === false
        ? { icon: 'calendar', tone: 'plain', title: tr('Розклад платежів призупинено') }
        : { icon: 'calendar', tone: 'info', title: tr('Розклад платежів: {0}-го числа', String(num(d.due_day) ?? '—')) }
    case 'schedule_deleted':
      return { icon: 'calendar', tone: 'err', title: tr('Видалено розклад платежів') }
    case 'file_added':
      return { icon: 'file', tone: 'info', title: tr('Додано документ «{0}»', str(d.name) ?? '—') }
    case 'file_deleted':
      return { icon: 'file', tone: 'err', title: tr('Видалено документ «{0}»', str(d.name) ?? '—') }
    case 'photo_deleted':
      return { icon: 'photo', tone: 'err', title: tr('Видалено фото') }
    default:
      // Новий вид події від новішого сервера — не падати й не мовчати.
      return { icon: 'edit', tone: 'plain', title: tr('Зміна') }
  }
}
