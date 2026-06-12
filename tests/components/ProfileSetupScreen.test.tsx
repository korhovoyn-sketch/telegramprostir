import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { makeUser } from '../mocks/fixtures'

const updateProfile = vi.fn()
vi.mock('@/hooks/useAuth', () => ({ useAuth: () => ({ updateProfile, loading: false }) }))

import ProfileSetupScreen from '@/screens/ProfileSetupScreen'
import { useAppStore } from '@/store/appStore'

describe('ProfileSetupScreen', () => {
  beforeEach(() => {
    updateProfile.mockReset()
    useAppStore.setState({
      user: makeUser({ role: 'owner', email: undefined, phone: undefined }),
      screen: 'profile-setup', screenParams: {}, history: [], toast: null,
    })
  })

  it('renders both the continue and skip buttons', () => {
    render(<ProfileSetupScreen />)
    expect(screen.getByRole('button', { name: /Почати роботу/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Пропустити/i })).toBeInTheDocument()
  })

  it('rejects an invalid email with a toast and does not save or navigate', async () => {
    const user = userEvent.setup()
    render(<ProfileSetupScreen />)
    await user.type(screen.getByPlaceholderText(/you@email.com/i), 'not-an-email')
    await user.click(screen.getByRole('button', { name: /Почати роботу/i }))

    await waitFor(() => expect(useAppStore.getState().toast?.type).toBe('error'))
    expect(updateProfile).not.toHaveBeenCalled()
    expect(useAppStore.getState().screen).toBe('profile-setup')
  })

  it('skip navigates to the owner home (empty-state) without saving', async () => {
    const user = userEvent.setup()
    render(<ProfileSetupScreen />)
    await user.click(screen.getByRole('button', { name: /Пропустити/i }))
    expect(updateProfile).not.toHaveBeenCalled()
    await waitFor(() => expect(useAppStore.getState().screen).toBe('empty-state'))
  })

  it('saves valid contacts silently and proceeds', async () => {
    updateProfile.mockResolvedValue(true)
    const user = userEvent.setup()
    render(<ProfileSetupScreen />)
    await user.type(screen.getByPlaceholderText(/you@email.com/i), 'good@mail.co')
    await user.click(screen.getByRole('button', { name: /Почати роботу/i }))

    expect(updateProfile).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'good@mail.co' }), true,
    )
    await waitFor(() => expect(useAppStore.getState().screen).toBe('empty-state'))
  })
})
