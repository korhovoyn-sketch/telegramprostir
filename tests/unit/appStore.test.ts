import { describe, it, expect, beforeEach } from 'vitest'
import { useAppStore } from '@/store/appStore'

function reset() {
  useAppStore.setState({
    screen: 'splash', screenParams: {}, history: [], navKey: 0,
    navDirection: 'root', lastDbId: null,
  })
}

describe('appStore navigation', () => {
  beforeEach(reset)

  it('navigate pushes current screen onto history and sets forward direction', () => {
    useAppStore.setState({ screen: 'db-list' })
    useAppStore.getState().navigate('db-objects', { dbId: 'db-1' })
    const s = useAppStore.getState()
    expect(s.screen).toBe('db-objects')
    expect(s.navDirection).toBe('forward')
    expect(s.history.at(-1)?.screen).toBe('db-list')
    expect(s.lastDbId).toBe('db-1')
  })

  it('navKey increments on every navigate', () => {
    const start = useAppStore.getState().navKey
    useAppStore.getState().navigate('profile')
    useAppStore.getState().navigate('notifications')
    expect(useAppStore.getState().navKey).toBe(start + 2)
  })

  it('history is capped at 12 entries', () => {
    for (let i = 0; i < 20; i++) useAppStore.getState().navigate('db-objects', { n: i })
    expect(useAppStore.getState().history.length).toBe(12)
  })

  it('navigateRoot clears history and sets root direction', () => {
    useAppStore.getState().navigate('db-objects')
    useAppStore.getState().navigateRoot('db-list')
    const s = useAppStore.getState()
    expect(s.history).toHaveLength(0)
    expect(s.navDirection).toBe('root')
  })

  it('back returns false on empty history', () => {
    expect(useAppStore.getState().back()).toBe(false)
  })

  it('back pops to the previous screen and sets back direction', () => {
    useAppStore.setState({ screen: 'db-list' })
    useAppStore.getState().navigate('db-objects')
    const ok = useAppStore.getState().back()
    expect(ok).toBe(true)
    expect(useAppStore.getState().screen).toBe('db-list')
    expect(useAppStore.getState().navDirection).toBe('back')
  })

  it('back never returns to auth screens (welcome/role-select/splash)', () => {
    // Simulate a history that includes auth screens beneath a real screen
    useAppStore.setState({
      screen: 'db-list',
      history: [
        { screen: 'splash', params: {} },
        { screen: 'welcome', params: {} },
        { screen: 'role-select', params: {} },
      ],
    })
    // All history entries are auth screens => back has nowhere safe to go
    expect(useAppStore.getState().back()).toBe(false)
  })
})
