import { describe, it, expect } from 'vitest'
import { dueDateFor, isOwedUnderLease, trackedFromOffset, ARREARS_MONTHS_MAX } from '@/lib/rentPayments'

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
