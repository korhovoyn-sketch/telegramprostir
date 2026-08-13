import { describe, it, expect, beforeEach, vi } from 'vitest'
import { offlineGuard } from '../../src/lib/offline'
import { useAppStore } from '../../src/store/appStore'
import { extractDbToken } from '../../src/screens/QRScannerScreen'

// Два дешеві гарди на речі, що стоять на вході в застосунок.
//
// `offlineGuard` викликається з ~40 місць (кожна деструктивна дія бази, шаринг,
// команда, аплоуд, експорт, платежі), а покритий був рівно одним e2e. Сам
// хелпер не мав жодного тесту — тобто зламавши його, ми б мовчки зняли захист
// із усіх сорока.
//
// `extractDbToken` — розбір QR-коду. Перевірити його e2e неможливо (потрібна
// жива камера), тож юніт тут єдиний реальний спосіб.

describe('offlineGuard', () => {
  beforeEach(() => {
    useAppStore.setState({ isOnline: true, toast: null })
  })

  it('онлайн — пропускає і не показує тост', () => {
    expect(offlineGuard()).toBe(false)
    expect(useAppStore.getState().toast).toBeNull()
  })

  it('офлайн — блокує і показує помилку', () => {
    useAppStore.setState({ isOnline: false })
    expect(offlineGuard()).toBe(true)
    const toast = useAppStore.getState().toast
    expect(toast?.type).toBe('error')
    expect(toast?.title).toBe('Немає інтернету')
  })

  it('свій підпис доходить до користувача', () => {
    // Виклики передають контекст («Експорт недоступний офлайн»), і він мусить
    // бути видимим — інакше всі сорок місць кажуть те саме загальне.
    useAppStore.setState({ isOnline: false })
    offlineGuard('Експорт недоступний офлайн')
    expect(useAppStore.getState().toast?.subtitle).toBe('Експорт недоступний офлайн')
  })

  it('без підпису — дефолт про збереження', () => {
    useAppStore.setState({ isOnline: false })
    offlineGuard()
    expect(useAppStore.getState().toast?.subtitle).toBe('Збереження недоступне офлайн')
  })
})

describe('extractDbToken — чотири форми того самого посилання', () => {
  const TOKEN = 'aabbccddeeff001122334455'

  it('deep link t.me із startapp', () => {
    expect(extractDbToken(`https://t.me/prostir_bot/prostir?startapp=db_${TOKEN}`)).toBe(TOKEN)
  })

  it('deep link зі старим параметром start', () => {
    expect(extractDbToken(`https://t.me/prostir_bot?start=db_${TOKEN}`)).toBe(TOKEN)
  })

  it('публічна сторінка /v?db=', () => {
    expect(extractDbToken(`https://prostir.vercel.app/v/?db=${TOKEN}`)).toBe(TOKEN)
  })

  it('сирий префікс db_ без URL', () => {
    expect(extractDbToken(`db_${TOKEN}`)).toBe(TOKEN)
  })

  it('голий hex-токен із пробілами по краях', () => {
    // Користувач вставляє з буфера — пробіли неминучі.
    expect(extractDbToken(`  ${TOKEN}  `)).toBe(TOKEN)
  })

  it('чужий QR не приймається', () => {
    expect(extractDbToken('https://example.com/whatever')).toBeNull()
    expect(extractDbToken('просто текст')).toBeNull()
    expect(extractDbToken('')).toBeNull()
  })

  it('надто короткий hex не вважається токеном', () => {
    // 24 символи — довжина share_token; коротше означає, що це щось інше,
    // і мовчки підставити його в RPC гірше, ніж чесно відмовити.
    expect(extractDbToken('aabbcc')).toBeNull()
  })
})
