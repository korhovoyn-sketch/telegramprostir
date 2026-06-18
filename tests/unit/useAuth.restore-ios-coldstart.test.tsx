import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'

// restoreSession() wraps a one-shot module singleton, so this scenario lives in
// its own file to get a fresh singleton (Vitest isolates per file).
//
// Reproduces the reported "splash stuck at 58%" bug: on iOS, Telegram's WebView
// wipes localStorage on a cold start — taking GoTrueClient's persisted session
// with it — while the CloudStorage profile/session mirror survives. Fast Path 0
// must still resolve instantly from the CloudStorage-cached profile instead of
// falling through to the slow CloudStorage-session + setSession() restore path.
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

describe('useAuth.restoreSession — Fast Path 0 on iOS cold start (CloudStorage only)', () => {
  beforeEach(() => {
    localStorage.clear()
    useAppStore.setState({ user: null })
  })

  it('restores the cached profile from CloudStorage when localStorage and the live session are both empty', async () => {
    const cached = makeUser({ tg_id: TG_ID, first_name: 'CloudCached' })
    installTelegramMock({
      user: { id: TG_ID, first_name: 'Test', username: 'tester' },
      cloudStorageSeed: { ps_user_cs: JSON.stringify(cached) },
    })
    // localStorage is empty — simulates the iOS wipe. No JSON to parse there.
    expect(localStorage.getItem('ps_user')).toBeNull()

    const { result } = renderHook(() => useAuth())
    let restored: boolean | undefined
    await act(async () => { restored = await result.current.restoreSession() })

    expect(restored).toBe(true)
    await waitFor(() => expect(useAppStore.getState().user?.tg_id).toBe(TG_ID))
    expect(useAppStore.getState().user?.first_name).toBe('CloudCached')
  })
})
