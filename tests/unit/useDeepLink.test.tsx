import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'

// useDeepLink fires once per mount (guarded by a `handled` ref), keyed off `user`
// and window.Telegram.WebApp.initDataUnsafe.start_param. Each scenario needs a
// fresh hook instance and a fresh mock, so every it() re-installs the Telegram
// mock and re-renders the hook.

const { rpcMock, fromMock, upsertMock } = vi.hoisted(() => ({
  rpcMock: vi.fn(),
  fromMock: vi.fn(),
  upsertMock: vi.fn(),
}))

vi.mock('@/lib/supabase', () => ({
  supabase: {
    rpc: rpcMock,
    from: fromMock,
  },
}))

import { useDeepLink } from '@/hooks/useDeepLink'
import { useAppStore } from '@/store/appStore'

const OWNER = makeUser({ id: 'owner-uuid', tg_id: 111222333, role: 'owner' })
const REALTOR = makeUser({ id: 'realtor-uuid', tg_id: 222333444, role: 'realtor' })

function freshUserQuery(user = OWNER) {
  return { select: () => ({ eq: () => ({ single: () => Promise.resolve({ data: user, error: null }) }) }) }
}

beforeEach(() => {
  rpcMock.mockReset()
  fromMock.mockReset()
  upsertMock.mockReset()
  useAppStore.setState({ user: null, screen: 'splash', screenParams: {}, history: [] })
})

describe('useDeepLink — db_ database share links', () => {
  it('owner tapping their own share link resets history and opens db-objects', async () => {
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'db-1', owner_id: OWNER.id, share_expires_at: null }], error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'db_TOKEN1' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('db-objects'))
    expect(useAppStore.getState().screenParams.dbId).toBe('db-1')
    expect(rpcMock).toHaveBeenCalledWith('lookup_shared_db', { p_token: 'TOKEN1' })
  })

  it('a realtor opening someone else\'s share link subscribes and opens realtor-database', async () => {
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'db-1', owner_id: OWNER.id, share_expires_at: null }], error: null })
    const upsert = vi.fn().mockResolvedValue({ error: null })
    fromMock.mockImplementation((table: string) => {
      if (table === 'realtor_subscriptions') return { upsert }
      return freshUserQuery()
    })
    installTelegramMock({ user: { id: REALTOR.tg_id, first_name: 'Realtor' }, startParam: 'db_TOKEN1' })
    useAppStore.setState({ user: REALTOR })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('realtor-database'))
    expect(upsert).toHaveBeenCalledWith(
      { realtor_id: REALTOR.id, db_id: 'db-1' },
      { onConflict: 'realtor_id,db_id' }
    )
  })

  it('an expired share link shows an error toast and does not navigate to db-objects', async () => {
    const pastDate = new Date(Date.now() - 86400000).toISOString()
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'db-1', owner_id: OWNER.id, share_expires_at: pastDate }], error: null })
    installTelegramMock({ user: { id: REALTOR.tg_id, first_name: 'Realtor' }, startParam: 'db_TOKEN1' })
    useAppStore.setState({ user: REALTOR })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.type).toBe('error'))
    expect(useAppStore.getState().screen).not.toBe('db-objects')
  })

  it('an unknown token shows an error toast', async () => {
    rpcMock.mockResolvedValueOnce({ data: [], error: null })
    installTelegramMock({ user: { id: REALTOR.tg_id, first_name: 'Realtor' }, startParam: 'db_BADTOKEN' })
    useAppStore.setState({ user: REALTOR })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.title).toBe('Базу не знайдено'))
  })
})

describe('useDeepLink — prop_ property share links', () => {
  it('opens property-detail for a valid token', async () => {
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'prop-1', db_id: 'db-1' }], error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'prop_TOKEN2' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('property-detail'))
    expect(useAppStore.getState().screenParams).toMatchObject({ propertyId: 'prop-1', dbId: 'db-1' })
  })

  it('shows an error toast when the property is not found', async () => {
    rpcMock.mockResolvedValueOnce({ data: [], error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'prop_BADTOKEN' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.title).toBe('Об\'єкт не знайдено'))
  })
})

describe('useDeepLink — col_ collection share links', () => {
  it('opens the editable collections screen when the current user owns the collection', async () => {
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'col-1', realtor_id: OWNER.id }], error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'col_TOKEN3' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('collections'))
  })

  it('opens the read-only shared-collection screen for a non-owner', async () => {
    rpcMock.mockResolvedValueOnce({ data: [{ id: 'col-1', realtor_id: 'someone-else' }], error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'col_TOKEN3' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('shared-collection'))
  })
})

describe('useDeepLink — guest_ invite links', () => {
  it('claims a valid invite and opens the shared property', async () => {
    rpcMock.mockResolvedValueOnce({ data: { property_id: 'prop-1', db_id: 'db-1' }, error: null })
    fromMock.mockImplementation(() => freshUserQuery(makeUser({ ...OWNER, role: 'guest' })))
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'guest_TOKEN4' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().screen).toBe('property-detail'))
    expect(useAppStore.getState().screenParams.propertyId).toBe('prop-1')
    expect(useAppStore.getState().user?.role).toBe('guest')
  })

  it('shows a specific message when the invite was revoked', async () => {
    rpcMock.mockResolvedValueOnce({ data: { error: 'revoked' }, error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'guest_TOKEN5' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.subtitle).toBe('Запрошення відкликано власником'))
  })

  it('shows a specific message when the owner taps their own invite link', async () => {
    rpcMock.mockResolvedValueOnce({ data: { error: 'cannot_claim_own_link' }, error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'guest_TOKEN6' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.subtitle).toBe('Не можна прийняти власне запрошення'))
  })

  it('shows a specific message when the invite was already claimed by someone else', async () => {
    rpcMock.mockResolvedValueOnce({ data: { error: 'already_claimed' }, error: null })
    installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' }, startParam: 'guest_TOKEN7' })
    useAppStore.setState({ user: OWNER })

    renderHook(() => useDeepLink())

    await waitFor(() => expect(useAppStore.getState().toast?.subtitle).toBe('Це запрошення вже використано'))
  })
})
