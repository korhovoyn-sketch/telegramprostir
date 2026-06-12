import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const updateProfile = vi.fn()
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ updateProfile }) }))

import RoleSelectScreen from '@/screens/RoleSelectScreen'
import { useAppStore } from '@/store/appStore'

describe('RoleSelectScreen', () => {
  beforeEach(() => {
    updateProfile.mockReset()
    useAppStore.setState({ screen: 'role-select', screenParams: {}, history: [] })
  })

  it('saves the role silently and advances to profile-setup on success', async () => {
    updateProfile.mockResolvedValue(true)
    const user = userEvent.setup()
    render(<RoleSelectScreen />)

    await user.click(screen.getByText('Власник'))
    await user.click(screen.getByRole('button', { name: /Продовжити/i }))

    expect(updateProfile).toHaveBeenCalledWith({ role: 'owner' }, true)
    await waitFor(() => expect(useAppStore.getState().screen).toBe('profile-setup'))
  })

  it('does NOT navigate when the role save fails', async () => {
    updateProfile.mockResolvedValue(false)
    const user = userEvent.setup()
    render(<RoleSelectScreen />)

    await user.click(screen.getByText('Ріелтор'))
    await user.click(screen.getByRole('button', { name: /Продовжити/i }))

    expect(updateProfile).toHaveBeenCalledWith({ role: 'realtor' }, true)
    await waitFor(() => {})
    expect(useAppStore.getState().screen).toBe('role-select')
  })

  it('ignores the continue press until a role is chosen', async () => {
    const user = userEvent.setup()
    render(<RoleSelectScreen />)
    await user.click(screen.getByRole('button', { name: /Продовжити/i }))
    expect(updateProfile).not.toHaveBeenCalled()
  })
})
