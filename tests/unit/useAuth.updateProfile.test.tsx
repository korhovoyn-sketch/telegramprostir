import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { makeUser } from '../mocks/fixtures'

// Mutable hooks shared with the mocked supabase module.
const h = vi.hoisted(() => ({
  getUser: vi.fn(),
  updatePayload: vi.fn(),
  singleResult: { data: null as unknown, error: null as unknown },
}))

vi.mock('@/lib/supabase', () => ({
  supabase: {
    auth: {
      getUser: h.getUser,
      getSession: vi.fn().mockResolvedValue({ data: { session: null } }),
      setSession: vi.fn(),
    },
    from: () => ({
      update: (payload: Record<string, unknown>) => {
        h.updatePayload(payload)
        return { eq: () => ({ select: () => ({ single: () => Promise.resolve(h.singleResult) }) }) }
      },
      select: () => ({ eq: () => ({ single: () => Promise.resolve(h.singleResult) }) }),
    }),
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'

describe('useAuth.updateProfile', () => {
  beforeEach(() => {
    h.getUser.mockResolvedValue({ data: { user: { email: '111222333@telegram.propspace.app' } } })
    h.updatePayload.mockClear()
    h.singleResult = { data: makeUser({ role: 'realtor' }), error: null }
    useAppStore.setState({ user: null, toast: null })
  })

  it('strips plan/id/tg_id before writing to the DB (A04 self-escalation guard)', async () => {
    const { result } = renderHook(() => useAuth())
    await act(async () => {
      await result.current.updateProfile({
        role: 'realtor', plan: 'pro', id: 'attacker', tg_id: 999, email: 'a@b.co',
      } as never)
    })
    const payload = h.updatePayload.mock.calls[0][0]
    expect(payload).not.toHaveProperty('plan')
    expect(payload).not.toHaveProperty('id')
    expect(payload).not.toHaveProperty('tg_id')
    expect(payload).toHaveProperty('role', 'realtor')
    expect(payload).toHaveProperty('email', 'a@b.co')
    expect(payload).toHaveProperty('updated_at')
  })

  it('returns true and shows a success toast on success (silent=false)', async () => {
    const { result } = renderHook(() => useAuth())
    let ret: boolean | undefined
    await act(async () => { ret = await result.current.updateProfile({ email: 'x@y.co' }) })
    expect(ret).toBe(true)
    expect(useAppStore.getState().toast?.type).toBe('success')
  })

  it('returns true WITHOUT a toast when silent=true (onboarding)', async () => {
    const { result } = renderHook(() => useAuth())
    let ret: boolean | undefined
    await act(async () => { ret = await result.current.updateProfile({ role: 'owner' }, true) })
    expect(ret).toBe(true)
    expect(useAppStore.getState().toast).toBeNull()
  })

  it('returns false and shows an error toast when the DB errors', async () => {
    h.singleResult = { data: null, error: { message: 'db down' } }
    const { result } = renderHook(() => useAuth())
    let ret: boolean | undefined
    await act(async () => { ret = await result.current.updateProfile({ email: 'x@y.co' }) })
    expect(ret).toBe(false)
    expect(useAppStore.getState().toast?.type).toBe('error')
  })

  it('returns false when there is no authenticated session', async () => {
    h.getUser.mockResolvedValue({ data: { user: null } })
    const { result } = renderHook(() => useAuth())
    let ret: boolean | undefined
    await act(async () => { ret = await result.current.updateProfile({ email: 'x@y.co' }) })
    expect(ret).toBe(false)
  })
})
