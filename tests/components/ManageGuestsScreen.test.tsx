import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { installTelegramMock } from '../mocks/telegram'
import { makeUser } from '../mocks/fixtures'
import type { GuestLink } from '@/types'

// ManageGuestsScreen loads guest_links via supabase.from('guest_links').select().eq().order(),
// and revokes via .update({ status: 'revoked' }).eq('id', id). The revoke flow now requires
// confirming in a Modal (handleRevoke is no longer called directly from the list button) —
// this guards against the "one mistaken tap permanently revokes guest access" regression.

const { updateEq, fromMock } = vi.hoisted(() => ({
  updateEq: vi.fn(),
  fromMock: vi.fn(),
}))

vi.mock('@/lib/supabase', () => ({
  supabase: { from: fromMock },
}))

import ManageGuestsScreen from '@/screens/ManageGuestsScreen'
import { useAppStore } from '@/store/appStore'

const OWNER = makeUser({ id: 'owner-uuid', role: 'owner' })

function makeGuestLink(overrides: Partial<GuestLink> = {}): GuestLink {
  return {
    id: 'link-1',
    owner_id: OWNER.id,
    property_id: 'prop-1',
    db_id: null,
    invite_token: 'tok123',
    label: 'Орендар, кв. 5',
    guest_user_id: null,
    status: 'active',
    claimed_at: null,
    created_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

function installSupabaseMock(links: GuestLink[]) {
  updateEq.mockReset().mockResolvedValue({ error: null })
  fromMock.mockReset().mockImplementation((table: string) => {
    if (table !== 'guest_links') throw new Error(`unexpected table ${table}`)
    return {
      select: () => ({
        eq: () => ({
          order: () => Promise.resolve({ data: links, error: null }),
        }),
      }),
      update: () => ({ eq: updateEq }),
    }
  })
}

beforeEach(() => {
  installTelegramMock({ user: { id: OWNER.tg_id, first_name: 'Test' } })
  useAppStore.setState({ user: OWNER, screen: 'manage-guests', screenParams: { propertyId: 'prop-1' }, history: [] })
})

describe('ManageGuestsScreen — revoke confirmation', () => {
  it('does not revoke immediately — tapping "Відкликати" opens a confirmation modal first', async () => {
    const link = makeGuestLink()
    installSupabaseMock([link])
    const user = userEvent.setup()
    render(<ManageGuestsScreen />)

    await waitFor(() => expect(screen.getByText('Орендар, кв. 5')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: /Відкликати/i }))

    expect(await screen.findByText('Відкликати доступ?')).toBeInTheDocument()
    expect(updateEq).not.toHaveBeenCalled()
  })

  it('cancelling the modal leaves the guest link untouched', async () => {
    const link = makeGuestLink()
    installSupabaseMock([link])
    const user = userEvent.setup()
    render(<ManageGuestsScreen />)

    await waitFor(() => expect(screen.getByText('Орендар, кв. 5')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /Відкликати/i }))

    const modal = (await screen.findByText('Відкликати доступ?')).closest('.modal') as HTMLElement
    await user.click(within(modal).getByRole('button', { name: 'Скасувати' }))

    await waitFor(() => expect(screen.queryByText('Відкликати доступ?')).not.toBeInTheDocument())
    expect(updateEq).not.toHaveBeenCalled()
  })

  it('confirming in the modal revokes the link and updates its status badge', async () => {
    const link = makeGuestLink()
    installSupabaseMock([link])
    const user = userEvent.setup()
    render(<ManageGuestsScreen />)

    await waitFor(() => expect(screen.getByText('Орендар, кв. 5')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /Відкликати/i }))

    const modal = (await screen.findByText('Відкликати доступ?')).closest('.modal') as HTMLElement
    await user.click(within(modal).getByRole('button', { name: 'Відкликати' }))

    await waitFor(() => expect(updateEq).toHaveBeenCalledWith('id', link.id))
    await waitFor(() => expect(screen.getByText('Відкликано')).toBeInTheDocument())
    expect(screen.queryByText('Відкликати доступ?')).not.toBeInTheDocument()
  })
})
