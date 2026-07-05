import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'

// restoreSession() wraps a one-shot module singleton, so the mismatch scenario
// lives in its own file to get a fresh singleton (Vitest isolates per file).
vi.mock('@/lib/supabase', () => ({
  USER_COLUMNS: 'id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at,updated_at',
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

describe('useAuth.restoreSession — identity mismatch', () => {
  beforeEach(() => {
    localStorage.clear()
    useAppStore.setState({ user: null })
  })

  it('ignores a cached profile whose tg_id does not match the Telegram identity', async () => {
    installTelegramMock({ user: { id: 111222333, first_name: 'Test' } })
    localStorage.setItem('ps_user', JSON.stringify(makeUser({ tg_id: 999999 })))

    const { result } = renderHook(() => useAuth())
    let restored: boolean | undefined
    await act(async () => { restored = await result.current.restoreSession() })

    // No live session and no matching cache => restore reports no session.
    expect(restored).toBe(false)
    expect(useAppStore.getState().user).toBeNull()
  })
})
