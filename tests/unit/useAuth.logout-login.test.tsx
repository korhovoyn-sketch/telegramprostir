import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'

// Regression: logging in immediately after logout used to hang and surface a
// false "no internet" error. Root cause — logout's global signOut() made a
// network POST that held Supabase's auth lock, deadlocking the next login's
// setSession(). Fix: signOut({scope:'local'}) (no network) + login awaits it.

const { signOut, setSession } = vi.hoisted(() => ({
  signOut: vi.fn(),
  setSession: vi.fn().mockResolvedValue({ data: { session: {} }, error: null }),
}))

vi.mock('@/lib/supabase', () => ({
  USER_COLUMNS: 'id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at,updated_at',
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: null } }),
      setSession,
      signOut,
      onAuthStateChange: () => ({ data: { subscription: { unsubscribe() {} } } }),
    },
    from: () => ({ select: () => ({ eq: () => ({ single: () => Promise.resolve({ data: null, error: null }) }) }) }),
  },
  getSessionUngated: vi.fn().mockResolvedValue({ data: { session: null } }),
}))

import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'

const TG_ID = 111222333
const USER = makeUser({ tg_id: TG_ID, first_name: 'Test', role: 'owner' })

beforeEach(() => {
  localStorage.clear()
  vi.stubEnv('NEXT_PUBLIC_SUPABASE_URL', 'http://localhost:9999')
  vi.stubEnv('NEXT_PUBLIC_SUPABASE_ANON_KEY', 'test-anon-key')
  useAppStore.setState({ user: USER, screen: 'profile', screenParams: {}, history: [] })
  signOut.mockReset()
  setSession.mockClear()
})

describe('useAuth logout → login', () => {
  it('logout signs out with local scope (no network POST that holds the auth lock)', () => {
    signOut.mockResolvedValue({ error: null })
    installTelegramMock({ user: { id: TG_ID, first_name: 'Test' } })
    const { result } = renderHook(() => useAuth())

    act(() => { result.current.logout() })

    expect(signOut).toHaveBeenCalledWith({ scope: 'local' })
    expect(useAppStore.getState().user).toBeNull()
    expect(useAppStore.getState().screen).toBe('welcome')
  })

  it('a login right after logout waits for signOut to release the lock before setSession', async () => {
    // signOut resolves only when we let it — proving login awaits it.
    let releaseSignOut: () => void = () => {}
    signOut.mockReturnValue(new Promise<{ error: null }>((res) => {
      releaseSignOut = () => res({ error: null })
    }))

    installTelegramMock({ user: { id: TG_ID, first_name: 'Test' } })
    const { result } = renderHook(() => useAuth())

    // Edge Function login succeeds with a well-formed token triple
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify({ access_token: 'aaa.bbb.ccc', refresh_token: 'r', user: USER, is_new: false }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ))

    act(() => { result.current.logout() })      // starts the pending signOut

    let loginDone = false
    act(() => { result.current.loginViaTelegram('init').then(() => { loginDone = true }) })

    // Give the fetch microtasks a chance; setSession must NOT have run yet
    // because the signOut promise is still pending (login is blocked on it).
    await new Promise(r => setTimeout(r, 50))
    expect(setSession).not.toHaveBeenCalled()

    // Release signOut → login proceeds to setSession and completes
    releaseSignOut()
    await vi.waitFor(() => expect(setSession).toHaveBeenCalledOnce())
    await vi.waitFor(() => expect(loginDone).toBe(true))
  })
})
