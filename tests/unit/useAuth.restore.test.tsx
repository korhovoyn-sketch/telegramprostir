import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'

// Background refresh path (refreshSessionSilently) touches these; keep them benign.
vi.mock('@/lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: null } }),
      setSession: vi.fn().mockResolvedValue({ data: { session: null } }),
    },
    from: () => ({
      select: () => ({ eq: () => ({ single: () => Promise.resolve({ data: null, error: null }) }) }),
    }),
  },
  getSessionUngated: vi.fn().mockResolvedValue({ data: { session: null } }),
}))

import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'

const TG_ID = 111222333

describe('useAuth.restoreSession — Fast Path 0 (anti-spinner)', () => {
  beforeEach(() => {
    localStorage.clear()
    useAppStore.setState({ user: null })
  })

  it('restores the cached profile from localStorage using initDataUnsafe identity, without a network login', async () => {
    installTelegramMock({ user: { id: TG_ID, first_name: 'Test', username: 'tester' } })
    const cached = makeUser({ tg_id: TG_ID, first_name: 'Cached' })
    localStorage.setItem('ps_user', JSON.stringify(cached))

    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    const { result } = renderHook(() => useAuth())
    let restored: boolean | undefined
    await act(async () => { restored = await result.current.restoreSession() })

    expect(restored).toBe(true)
    await waitFor(() => expect(useAppStore.getState().user?.tg_id).toBe(TG_ID))
    expect(useAppStore.getState().user?.first_name).toBe('Cached')
    // The whole point: no Edge Function / REST login was needed.
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })
})
