import { describe, it, expect } from 'vitest'
import { dueDateFor, isOwedUnderLease, owedFrom, tenantOnDate, trackedFromOffset, ARREARS_MONTHS_MAX, type TenancySpan } from '@/lib/rentPayments'

/**
 * Правила, від яких залежить, чи покаже застосунок БОРГ.
 *
 * Дві помилки цього класу були живими одночасно, і обидві — про гроші:
 *  1. платіж за місяць ДО початку договору рахувався простроченим (здав 18-го
 *     з оплатою 5-го → одразу «Прострочено на 13 днів»);
 *  2. неоплачений платіж за МИНУЛИЙ місяць 1-го числа зникав із календаря,
 *     лічильника й сповіщень — борг забувався на межі місяця.
 * Тут — чисті функції, на яких тепер стоять і календар, і «Найближчі платежі».
 */
const OCT_10 = new Date(2026, 9, 10, 1, 30) // 01:30 локально — найгірший час доби для UTC-зсувів

describe('dueDateFor', () => {
  it('дата в місяці зі зсувом, у локальному календарі', () => {
    expect(dueDateFor(0, 5, OCT_10)).toBe('2026-10-05')
    expect(dueDateFor(-1, 5, OCT_10)).toBe('2026-09-05')
    expect(dueDateFor(3, 5, OCT_10)).toBe('2027-01-05')
  })
  it('день обмежується довжиною місяця (31-е в лютому — не 3 березня)', () => {
    expect(dueDateFor(4, 31, OCT_10)).toBe('2027-02-28')
  })
})

describe('trackedFromOffset — звідки рахується заборгованість', () => {
  it('розклад, заведений цього місяця, боргу за минулі місяці не дає', () => {
    expect(trackedFromOffset('2026-10-02T09:00:00Z', OCT_10)).toBe(0)
  })
  it('розклад тримісячної давності — три місяці назад', () => {
    expect(trackedFromOffset('2026-07-20T09:00:00Z', OCT_10)).toBe(-3)
  })
  it('не глибше року', () => {
    expect(trackedFromOffset('2020-01-01T00:00:00Z', OCT_10)).toBe(-ARREARS_MONTHS_MAX)
  })
  it('невідома чи бита дата — лише поточний місяць, а не вигаданий борг', () => {
    expect(trackedFromOffset(null, OCT_10)).toBe(0)
    expect(trackedFromOffset('не-дата', OCT_10)).toBe(0)
  })
})

describe('isOwedUnderLease', () => {
  it('платіж до початку договору — не борг', () => {
    expect(isOwedUnderLease('2026-10-05', '2026-10-18')).toBe(false)
  })
  it('платіж у день початку і пізніше — борг', () => {
    expect(isOwedUnderLease('2026-10-18', '2026-10-18')).toBe(true)
    expect(isOwedUnderLease('2026-11-05', '2026-10-18')).toBe(true)
  })
  // Антивакуум: без дати початку (поле необовʼязкове) обмеження немає — інакше
  // правило «ховало б усе» і перші два кейси проходили б на зламаному коді.
  it('без дати початку обмеження немає', () => {
    expect(isOwedUnderLease('2026-10-05', null)).toBe(true)
    expect(isOwedUnderLease('2026-10-05', undefined)).toBe(true)
  })
})

const P = 'p-1'
const SPANS: TenancySpan[] = [
  { property_id: P, tenant_name: 'ФОП Іванов', started_at: '2025-06-01T00:00:00.000Z', ended_at: '2025-12-20T12:00:00.000Z' },
  { property_id: P, tenant_name: 'ТОВ «Ромашка»', started_at: '2026-09-10T09:00:00.000Z', ended_at: null },
  { property_id: 'p-2', tenant_name: 'Чужий', started_at: '2020-01-01T00:00:00.000Z', ended_at: null },
]

describe('owedFrom — з якої дати платежі обʼєкта є боргом ЦІЄЇ оренди', () => {
  it('дата договору — головне джерело', () => {
    expect(owedFrom('2026-08-01', P, SPANS)).toBe('2026-08-01')
  })
  it('без дати договору — фактичний початок ВІДКРИТОЇ оренди, а не закритої й не чужої', () => {
    expect(owedFrom(null, P, SPANS)).toBe('2026-09-10')
  })
  it('без архіву оренд межі немає — сховати борг за вигаданою датою гірше', () => {
    expect(owedFrom(null, P, null)).toBeNull()
    expect(owedFrom(undefined, 'p-3', SPANS)).toBeNull()
  })
})

describe('tenantOnDate — хто платив за дату', () => {
  it('платіж періоду попередньої оренди — її орендар, а не поточний', () => {
    expect(tenantOnDate(P, '2025-11-05', SPANS, undefined)).toBe('ФОП Іванов')
    expect(tenantOnDate(P, '2026-10-05', SPANS, undefined)).toBe('ТОВ «Ромашка»')
  })
  it('межа закриття відкрита справа: день звільнення вже не належить оренді', () => {
    expect(tenantOnDate(P, '2025-12-20', SPANS, undefined)).toBeNull()
    expect(tenantOnDate(P, '2025-12-19', SPANS, undefined)).toBe('ФОП Іванов')
  })
  it('простій між орендами — нікого не підписуємо', () => {
    expect(tenantOnDate(P, '2026-03-05', SPANS, undefined)).toBeNull()
  })
  it('без архіву — поточний орендар лише від початку його договору', () => {
    const cur = { status: 'occupied', tenant_name: 'ТОВ «Ромашка»', lease_start_date: '2026-01-01' }
    expect(tenantOnDate(P, '2026-02-05', null, cur)).toBe('ТОВ «Ромашка»')
    expect(tenantOnDate(P, '2025-11-05', null, cur)).toBeNull()
    expect(tenantOnDate(P, '2026-02-05', null, { ...cur, status: 'free' })).toBeNull()
  })
})
