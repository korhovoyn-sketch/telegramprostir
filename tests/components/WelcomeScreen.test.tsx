import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, act } from '@testing-library/react'

const loginViaTelegram = vi.fn()
let loadingState = false

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({ loginViaTelegram, loading: loadingState }),
}))
vi.mock('@/hooks/useTelegram', () => ({
  useTelegram: () => ({
    tg: { initData: 'mock_init' },
    user: { id: 1, first_name: 'Test' },
  }),
}))

import WelcomeScreen from '@/screens/WelcomeScreen'
import { useAppStore } from '@/store/appStore'

describe('WelcomeScreen', () => {
  beforeEach(() => {
    loginViaTelegram.mockClear()
    loadingState = false
    useAppStore.setState({ user: null, screenParams: { fromLogout: true }, toast: null })
  })

  it('idle: renders the login button WITHOUT a position:relative override (anti-squish guard)', () => {
    render(<WelcomeScreen />)
    const btn = screen.getByRole('button', { name: /Увійти через Telegram/i })
    expect(btn).toBeInTheDocument()
    expect(btn.className).toContain('mbtn')
    // The bug we fixed: position:relative pushes the button out of the
    // overflow:hidden .scr on small screens. It must stay on the CSS default.
    expect(btn.style.position).not.toBe('relative')
  })

  it('idle: wraps scrollable content in a .body so the fixed button never overlaps content', () => {
    const { container } = render(<WelcomeScreen />)
    expect(container.querySelector('.body')).toBeTruthy()
  })

  it('loading: shows the first auth step message and a "do not close" hint, not a frozen button', () => {
    loadingState = true
    render(<WelcomeScreen />)
    expect(screen.getByText(/Підключаємось до Telegram/i)).toBeInTheDocument()
    expect(screen.getByText(/Не закривайте додаток/i)).toBeInTheDocument()
  })

  it('loading: surfaces a retry button after the 25s timeout', () => {
    vi.useFakeTimers()
    loadingState = true
    try {
      render(<WelcomeScreen />)
      expect(screen.queryByRole('button', { name: /Спробувати ще раз/i })).toBeNull()
      act(() => { vi.advanceTimersByTime(26_000) })
      expect(screen.getByRole('button', { name: /Спробувати ще раз/i })).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })
})
