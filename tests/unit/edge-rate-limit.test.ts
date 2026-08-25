import { describe, it, expect } from 'vitest'
import { rateDecision } from '../../supabase/functions/_shared/rateLimit'

/**
 * ПЕРШИЙ ТЕСТ EDGE-ФУНКЦІЙ У ЦЬОМУ РЕПО.
 *
 * Рев'ю назвало їх найбільшою непокритою поверхнею — і справедливо: там уся
 * логіка ідентичності, а перевіряв її нуль тестів. Прогнати функцію цілком
 * звідси не можна (немає Deno, імпорти з esm.sh), тому рішення лімітера
 * винесене в чистий модуль без імпортів, і тестується саме воно.
 */
describe('rateDecision', () => {
  const NOW = Date.parse('2026-08-20T12:00:00.000Z')
  const MAX = 20

  it('ЗБІЙ ЗАПИТУ = ВІДМОВА, а не пропуск', () => {
    // Головний інваріант. supabase-js резолвить збій як {data:null,error},
    // тож без явної гілки «немає рядка» і «база лягла» нерозрізненні.
    expect(rateDecision(null, true, NOW, MAX)).toEqual({ allow: false, action: 'none' })
    expect(rateDecision({ count: 1, reset_at: '2026-08-20T12:01:00Z' }, true, NOW, MAX).allow).toBe(false)
  })

  it('рядка немає — пускаємо і починаємо вікно', () => {
    expect(rateDecision(null, false, NOW, MAX)).toEqual({ allow: true, action: 'reset' })
    expect(rateDecision(undefined, false, NOW, MAX).action).toBe('reset')
  })

  it('вікно минуло — новий відлік', () => {
    const row = { count: 99, reset_at: '2026-08-20T11:59:59Z' }
    expect(rateDecision(row, false, NOW, MAX)).toEqual({ allow: true, action: 'reset' })
  })

  it('у межах ліміту — інкремент', () => {
    const row = { count: 19, reset_at: '2026-08-20T12:00:30Z' }
    expect(rateDecision(row, false, NOW, MAX)).toEqual({ allow: true, action: 'increment' })
  })

  it('стеля досягнута — відмова', () => {
    const row = { count: 20, reset_at: '2026-08-20T12:00:30Z' }
    expect(rateDecision(row, false, NOW, MAX).allow).toBe(false)
    expect(rateDecision({ count: 21, reset_at: '2026-08-20T12:00:30Z' }, false, NOW, MAX).allow).toBe(false)
  })

  it('порівняння за ЧАСОМ, не лексикографічне', () => {
    // Той самий момент у двох записах. Рядкове `<` дало б різні відповіді.
    const z = { count: 5, reset_at: '2026-08-20T12:00:30Z' }
    const off = { count: 5, reset_at: '2026-08-20T12:00:30+00:00' }
    expect(rateDecision(z, false, NOW, MAX)).toEqual(rateDecision(off, false, NOW, MAX))
  })

  it('зіпсована дата не відкриває шлюз назавжди', () => {
    // Найтихіший спосіб зламати лімітер — рядок, що не парситься. Він мусить
    // трактуватись як «вікно минуло» (лічильник почнеться з 1), а не як
    // «нескінченне вікно з count, що ніколи не росте».
    const bad = { count: 999, reset_at: 'не-дата' }
    expect(rateDecision(bad, false, NOW, MAX)).toEqual({ allow: true, action: 'reset' })
  })
})
