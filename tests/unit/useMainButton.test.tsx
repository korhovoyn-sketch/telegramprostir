import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useMainButton } from '@/hooks/useMainButton'

// Прод-краш, який тут пінується: нижня смуга Telegram кидає СИНХРОННО на
// невалідному параметрі (`WebAppBottomButtonParamInvalid`), а з ефекту виняток
// летить у ErrorBoundary. Найгостріший випадок — порожній/пробільний `text`:
// плейсхолдер для схованої другорядної кнопки завалював екран створення об'єкта.

interface BtnState { text: string; visible: boolean; params: Record<string, unknown>; active: boolean }

function makeButton(state: BtnState, handlers: (() => void)[]) {
  const badText = (t: unknown) => typeof t !== 'string' || t.trim() === ''
  return {
    setText: vi.fn((t: string) => {
      // Рівно так строго, як клієнт Telegram.
      if (badText(t)) throw new Error('WebAppBottomButtonParamInvalid')
      state.text = t
    }),
    setParams: vi.fn((p: Record<string, unknown>) => {
      if ('text' in p && badText(p.text)) throw new Error('WebAppBottomButtonParamInvalid')
      Object.assign(state.params, p)
      if (typeof p.text === 'string') state.text = p.text
      if (typeof p.is_visible === 'boolean') state.visible = p.is_visible
    }),
    show: vi.fn(() => { state.visible = true }),
    hide: vi.fn(() => { state.visible = false }),
    enable: vi.fn(() => { state.active = true }),
    disable: vi.fn(() => { state.active = false }),
    showProgress: vi.fn(),
    hideProgress: vi.fn(),
    onClick: vi.fn((fn: () => void) => { handlers.push(fn) }),
    offClick: vi.fn((fn: () => void) => {
      const i = handlers.indexOf(fn)
      if (i >= 0) handlers.splice(i, 1)
    }),
  }
}

let main: BtnState
let sec: BtnState
let mainHandlers: (() => void)[]
let secHandlers: (() => void)[]

function install({ withSecondary = true } = {}) {
  main = { text: '', visible: false, params: {}, active: false }
  sec = { text: '', visible: false, params: {}, active: false }
  mainHandlers = []
  secHandlers = []
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(window as any).Telegram = {
    WebApp: {
      initData: 'signed',
      MainButton: makeButton(main, mainHandlers),
      SecondaryButton: withSecondary ? makeButton(sec, secHandlers) : undefined,
      setBottomBarColor: vi.fn(),
    },
  }
}

beforeEach(() => install())
// eslint-disable-next-line @typescript-eslint/no-explicit-any
afterEach(() => { delete (window as any).Telegram })

describe('useMainButton', () => {
  it('без другорядної дії НЕ надсилає параметрів SecondaryButton — лише ховає', () => {
    const { result } = renderHook(() => useMainButton({
      text: 'Додати об\'єкт', visible: true, onClick: () => {},
    }))

    expect(result.current.available).toBe(true)
    expect(result.current.secondaryAvailable).toBe(false)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sb = (window as any).Telegram.WebApp.SecondaryButton
    expect(sb.setParams, 'плейсхолдерний підпис і був причиною краша').not.toHaveBeenCalled()
    expect(sb.hide).toHaveBeenCalled()
    expect(sec.visible).toBe(false)
    expect(main.text).toBe('Додати об\'єкт')
    expect(main.visible).toBe(true)
  })

  it('із другорядною дією малює пару кнопок ліворуч', () => {
    const { result } = renderHook(() => useMainButton({
      text: 'Зберегти зміни', visible: true, barColor: '#5480dc', onClick: () => {},
      secondary: { text: 'Видалити', destructive: true, onClick: () => {} },
    }))

    expect(result.current.secondaryAvailable).toBe(true)
    expect(sec.text).toBe('Видалити')
    expect(sec.visible).toBe(true)
    expect(sec.params.position).toBe('left')
    // Заливка = колір смуги: підпис на смузі, а не друга суцільна кнопка.
    expect(sec.params.color).toBe('#5480dc')
  })

  it('виняток від Telegram НЕ пробивається наверх (інакше — ErrorBoundary)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tg = (window as any).Telegram.WebApp
    for (const k of ['setText', 'setParams', 'show', 'hide', 'enable', 'disable'] as const) {
      tg.MainButton[k] = vi.fn(() => { throw new Error('WebAppBottomButtonParamInvalid') })
      tg.SecondaryButton[k] = vi.fn(() => { throw new Error('WebAppBottomButtonParamInvalid') })
    }

    expect(() => renderHook(() => useMainButton({
      text: 'Зберегти', visible: true, onClick: () => {},
      secondary: { text: 'Видалити', onClick: () => {} },
    }))).not.toThrow()
  })

  it('порожній підпис головної кнопки не валить екран', () => {
    expect(() => renderHook(() => useMainButton({
      text: '', visible: true, onClick: () => {},
    }))).not.toThrow()
  })

  it('unmount відписує хендлери і ховає обидві кнопки — щоб не протекли далі', () => {
    const { unmount } = renderHook(() => useMainButton({
      text: 'Зберегти зміни', visible: true, onClick: () => {},
      secondary: { text: 'Видалити', onClick: () => {} },
    }))
    expect(mainHandlers).toHaveLength(1)
    expect(secHandlers).toHaveLength(1)

    unmount()
    expect(mainHandlers, 'хендлер лишився б на наступному екрані').toHaveLength(0)
    expect(secHandlers).toHaveLength(0)
    expect(main.visible).toBe(false)
    expect(sec.visible).toBe(false)
  })

  it('тап кличе АКТУАЛЬНИЙ обробник, а не той, що був на першому рендері', () => {
    const first = vi.fn()
    const second = vi.fn()
    const { rerender } = renderHook(
      ({ cb }: { cb: () => void }) => useMainButton({ text: 'Зберегти', visible: true, onClick: cb }),
      { initialProps: { cb: first } },
    )
    rerender({ cb: second })

    mainHandlers[0]()
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)
    expect(mainHandlers, 'ре-рендер не мусить перепідписувати').toHaveLength(1)
  })

  it('клієнт без SecondaryButton: пара недоступна, DOM-фолбек лишається потрібним', () => {
    install({ withSecondary: false })
    const { result } = renderHook(() => useMainButton({
      text: 'Зберегти зміни', visible: true, onClick: () => {},
      secondary: { text: 'Видалити', onClick: () => {} },
    }))
    expect(result.current.available).toBe(true)
    expect(result.current.secondaryAvailable, 'кошик у хедері мусить лишитись').toBe(false)
  })

  it('поза Telegram (порожній initData) нативна кнопка не активується', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(window as any).Telegram.WebApp.initData = ''
    const { result } = renderHook(() => useMainButton({
      text: 'Зберегти', visible: true, onClick: () => {},
    }))
    expect(result.current.available, 'DOM .mbtn мусить лишитись єдиною кнопкою').toBe(false)
  })

  it('disabled-стан сірий, а не яскраво-зелений', () => {
    renderHook(() => useMainButton({
      text: 'Зберегти', visible: true, enabled: false, onClick: () => {},
    }))
    // Кастомний колір переживає disable(), тож його треба гасити вручну.
    expect(main.params.color).toBe('#3A4149')
    expect(main.active).toBe(false)
  })
})
