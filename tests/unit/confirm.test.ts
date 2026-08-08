import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { confirmAction } from '@/lib/confirm'
import { useAppStore } from '@/store/appStore'

// Підтвердження незворотної дії має ОДНУ семантику на всіх платформах:
// Promise<boolean>, де відмова — це false, а не «нічого не сталося». Найтонше
// місце — свайп-закриття нативного попапа: Telegram віддає null.

function installTg(opts: { popup?: 'ok' | 'cancel' | null | 'throw'; initData?: string } = {}) {
  const calls: unknown[] = []
  const webApp: Record<string, unknown> = {
    initData: opts.initData ?? 'signed',
    HapticFeedback: { impactOccurred() {}, notificationOccurred() {}, selectionChanged() {} },
  }
  if (opts.popup !== undefined) {
    webApp.showPopup = (params: unknown, cb?: (id: string | null) => void) => {
      calls.push(params)
      if (opts.popup === 'throw') throw new Error('WebAppMethodUnsupported')
      setTimeout(() => cb?.(opts.popup as string | null), 0)
    }
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(window as any).Telegram = { WebApp: webApp }
  return calls
}

const OPTS = {
  title: 'Видалити об\'єкт?',
  message: 'Об\'єкт "Офіс 101" буде видалено. Це незворотно.',
  confirmLabel: 'Видалити',
  destructive: true,
}

beforeEach(() => { useAppStore.setState({ confirmRequest: null }) })
// eslint-disable-next-line @typescript-eslint/no-explicit-any
afterEach(() => { delete (window as any).Telegram; vi.useRealTimers() })

describe('confirmAction — нативний попап', () => {
  it('«Видалити» → true, і попап отримує деструктивну кнопку + кнопку скасування', async () => {
    const calls = installTg({ popup: 'ok' })
    await expect(confirmAction(OPTS)).resolves.toBe(true)

    expect(calls).toHaveLength(1)
    const p = calls[0] as { title: string; message: string; buttons: { id: string; type: string; text?: string }[] }
    expect(p.title).toBe(OPTS.title)
    expect(p.message).toBe(OPTS.message)
    expect(p.buttons[0]).toMatchObject({ id: 'ok', type: 'destructive', text: 'Видалити' })
    expect(p.buttons[1]).toMatchObject({ id: 'cancel' })
    // Своєї модалки не просимо — інакше було б два діалоги.
    expect(useAppStore.getState().confirmRequest).toBeNull()
  })

  it('закриття свайпом (null) = відмова', async () => {
    installTg({ popup: null })
    await expect(confirmAction(OPTS)).resolves.toBe(false)
  })

  it('кнопка «Скасувати» = відмова', async () => {
    installTg({ popup: 'cancel' })
    await expect(confirmAction(OPTS)).resolves.toBe(false)
  })

  it('не-деструктивна дія просить звичайну кнопку, не червону', async () => {
    const calls = installTg({ popup: 'ok' })
    await confirmAction({ ...OPTS, destructive: false })
    const p = calls[0] as { buttons: { type: string }[] }
    expect(p.buttons[0].type).toBe('default')
  })

  it('старий клієнт кидає на showPopup → тихий фолбек на свою модалку', async () => {
    installTg({ popup: 'throw' })
    const promise = confirmAction(OPTS)

    const req = await vi.waitFor(() => {
      const r = useAppStore.getState().confirmRequest
      expect(r, 'фолбек мусить попросити модалку').not.toBeNull()
      return r!
    })
    expect(req.title).toBe(OPTS.title)
    useAppStore.getState().answerConfirm(true)
    await expect(promise).resolves.toBe(true)
  })
})

describe('confirmAction — фолбек-модалка', () => {
  it('без showPopup просить модалку з ТИМ САМИМ текстом', async () => {
    installTg({})
    const promise = confirmAction(OPTS)

    const req = useAppStore.getState().confirmRequest
    expect(req).not.toBeNull()
    // Формулювання не має розходитись між платформами.
    expect(req!.title).toBe(OPTS.title)
    expect(req!.message).toBe(OPTS.message)
    expect(req!.confirmLabel).toBe('Видалити')

    useAppStore.getState().answerConfirm(false)
    await expect(promise).resolves.toBe(false)
  })

  it('поза Telegram (порожній initData) нативний шлях НЕ вибирається', async () => {
    // Об'єкт SDK може існувати в браузері, але попап не відкриється — і колбек
    // не прийде НІКОЛИ, тобто проміс завис би назавжди.
    const calls = installTg({ popup: 'ok', initData: '' })
    const promise = confirmAction(OPTS)
    expect(calls).toHaveLength(0)
    expect(useAppStore.getState().confirmRequest).not.toBeNull()

    useAppStore.getState().answerConfirm(true)
    await expect(promise).resolves.toBe(true)
  })

  it('відповідь знімає запит зі стору — модалка не лишається висіти', async () => {
    installTg({})
    const promise = confirmAction(OPTS)
    useAppStore.getState().answerConfirm(true)
    await promise
    expect(useAppStore.getState().confirmRequest).toBeNull()
  })
})
