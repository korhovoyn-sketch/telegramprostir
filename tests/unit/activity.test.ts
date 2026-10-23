import { describe, it, expect } from 'vitest'
import { describeActivity } from '@/lib/activity'

/**
 * Журнал змін (073): сервер пише ФАКТИ, текст будується тут. Перевіряємо те,
 * що в цьому тексті може збрехати: не ту суму, не той місяць, не ту зміну.
 */
const view = (kind: string, details: Record<string, unknown>) => describeActivity({ kind, details }, 'USD')

describe('describeActivity', () => {
  it('гроші — місяць ПЕРІОДУ платежу, а не день запису', () => {
    expect(view('payment_received', { due_date: '2026-08-05', amount: 1000 }).title)
      .toMatch(/^Отримано \$1[\s ,]?000 за серпень 2026/)
  })

  it('«р.» не відривається від року: пробіл перед ним нерозривний', () => {
    // ICU ставить звичайний пробіл, і на 375px «р.» стояло окремим рядком.
    const t = view('payment_received', { due_date: '2026-08-05', amount: 1000 }).title
    expect(t).toMatch(/2026\u00a0р\.$/)
    expect(t).not.toMatch(/2026 р\./)
  })

  it('виправлення: сума змінилась — «було → стало»; змінилась лише дата — так і сказано', () => {
    expect(view('payment_edited', { due_date: '2026-09-05', from: 1000, to: 1500 }).title).toMatch(/1[\s ,]?000 → \$1[\s ,]?500/)
    expect(view('payment_edited', { due_date: '2026-09-05', from: 1000, to: 1000 }).title).toMatch(/^Змінено дату надходження/)
  })

  it('зміна умов називає те, що СПРАВДІ змінилось', () => {
    const base = { rent_rate: 18, rent_type: 'per_m2', area_total: 120, area_useful: 100, utilities_rate: 2, area_basis: 'total' }
    expect(view('terms_changed', { from: base, to: { ...base, rent_rate: 20 } }).title).toMatch(/^Ставка: \$18\/м² → \$20\/м²/)
    expect(view('terms_changed', { from: base, to: { ...base, area_total: 130 } }).title).toBe('Площа: 120 → 130 м²')
    expect(view('terms_changed', { from: base, to: { ...base, utilities_rate: 3 } }).title).toMatch(/^Експлуатаційні:/)
    expect(view('terms_changed', { from: base, to: { ...base, area_basis: 'useful' } }).title).toBe('Змінено базу розрахунку площі')
  })

  it('звільнення називає ПОПЕРЕДНЬОГО орендаря; без імені — не «undefined»', () => {
    expect(view('property_vacated', { tenant: 'ТОВ Ромашка' }).title).toBe('Звільнено, орендар був: ТОВ Ромашка')
    expect(view('property_vacated', {}).title).toBe('Обʼєкт звільнено')
    expect(view('property_rented', { tenant: null }).title).toBe('Здано в оренду')
  })

  it('статус — підписами, а не службовими значеннями', () => {
    expect(view('property_status', { from: 'free', to: 'for_sale' }).title).toBe('Статус: Вільно → Продаж')
  })

  it('сума за період: перша — без «було», зміна — з ним', () => {
    expect(view('due_changed', { due_date: '2026-08-05', from: null, to: 960 }).title).toMatch(/^Сума за серпень 2026[^→]*960$/)
    expect(view('due_changed', { due_date: '2026-08-05', from: 1920, to: 960 }).title).toMatch(/→/)
  })

  it('невідомий вид події від новішого сервера — «Зміна», а не падіння', () => {
    expect(view('something_new', {}).title).toBe('Зміна')
  })

  it('жодного дієслова з родом від імені людини — хто, стоїть окремо', () => {
    for (const k of ['property_created', 'property_deleted', 'payment_cancelled', 'file_added', 'photo_deleted']) {
      expect(view(k, { due_date: '2026-08-05', amount: 1, name: 'x' }).title)
        .not.toMatch(/створив|створила|видалив|видалила|скасував|скасувала|додав|додала/i)
    }
  })
})
