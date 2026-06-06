'use client'

import { create } from 'zustand'
import type { User, Toast, ScreenName, ScreenParams, Database, Notification } from '@/types'

interface NavEntry {
  screen: ScreenName
  params: ScreenParams
}

interface AppState {
  screen: ScreenName
  screenParams: ScreenParams
  history: NavEntry[]
  navKey: number
  navDirection: 'forward' | 'back' | 'root'
  user: User | null
  toast: Toast | null
  databases: Database[]
  notifications: Notification[]
  unreadCount: number
  isOnline: boolean
  lastDbId: string | null

  navigate: (screen: ScreenName, params?: ScreenParams) => void
  /** Replace current screen and clear history stack (use after deep link or fresh auth) */
  navigateRoot: (screen: ScreenName, params?: ScreenParams) => void
  back: () => boolean
  setUser: (user: User | null) => void
  showToast: (toast: Toast) => void
  hideToast: () => void
  setDatabases: (dbs: Database[]) => void
  setNotifications: (notifs: Notification[]) => void
  markAllRead: () => void
  setOnline: (online: boolean) => void
}

// Module-level timer so we can clear it across calls without storing in Zustand state
let _toastTimer: ReturnType<typeof setTimeout> | null = null

export const useAppStore = create<AppState>((set, get) => ({
  screen: 'splash',
  screenParams: {},
  history: [],
  navKey: 0,
  navDirection: 'root' as const,
  user: null,
  toast: null,
  databases: [],
  notifications: [],
  unreadCount: 0,
  isOnline: true,
  lastDbId: null,

  navigate: (screen, params = {}) => {
    const { screen: current, screenParams: currentParams, history, navKey } = get()
    const nextLastDbId = (params as ScreenParams).dbId as string | undefined
    set({
      screen,
      screenParams: params,
      // Cap stack at 12 to prevent unbounded growth
      history: [...history, { screen: current, params: currentParams }].slice(-12),
      navKey: navKey + 1,
      navDirection: 'forward',
      ...(nextLastDbId ? { lastDbId: nextLastDbId } : {}),
    })
  },

  navigateRoot: (screen, params = {}) => {
    set({ screen, screenParams: params, history: [], navKey: get().navKey + 1, navDirection: 'root' })
  },

  back: () => {
    const { history, navKey } = get()
    if (history.length === 0) return false
    // Filter out auth screens that should never appear when pressing Back
    const AUTH_SCREENS: ScreenName[] = ['splash', 'welcome', 'role-select']
    const filtered = history.filter(e => !AUTH_SCREENS.includes(e.screen))
    if (filtered.length === 0) return false
    const prev = filtered[filtered.length - 1]
    set({
      screen: prev.screen,
      screenParams: prev.params,
      history: filtered.slice(0, -1),
      navKey: navKey + 1,
      navDirection: 'back',
    })
    return true
  },

  setUser: (user) => set({ user }),

  showToast: (toast) => {
    if (_toastTimer) clearTimeout(_toastTimer)
    set({ toast })
    _toastTimer = setTimeout(() => {
      set({ toast: null })
      _toastTimer = null
    }, 3500)
  },

  hideToast: () => {
    if (_toastTimer) { clearTimeout(_toastTimer); _toastTimer = null }
    set({ toast: null })
  },

  setOnline: (online) => set({ isOnline: online }),

  setDatabases: (databases) => set({ databases }),

  setNotifications: (notifications) => {
    const unreadCount = notifications.filter((n) => !n.is_read).length
    set({ notifications, unreadCount })
  },

  markAllRead: () => {
    const { notifications } = get()
    set({
      notifications: notifications.map((n) => ({ ...n, is_read: true })),
      unreadCount: 0,
    })
  },
}))
