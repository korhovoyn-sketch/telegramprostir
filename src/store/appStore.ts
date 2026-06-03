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
  user: User | null
  toast: Toast | null
  databases: Database[]
  notifications: Notification[]
  unreadCount: number
  isOnline: boolean

  navigate: (screen: ScreenName, params?: ScreenParams) => void
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
  user: null,
  toast: null,
  databases: [],
  notifications: [],
  unreadCount: 0,
  isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,

  navigate: (screen, params = {}) => {
    const { screen: current, screenParams: currentParams, history } = get()
    set({
      screen,
      screenParams: params,
      history: [...history, { screen: current, params: currentParams }],
    })
  },

  back: () => {
    const { history } = get()
    if (history.length === 0) return false
    const prev = history[history.length - 1]
    set({
      screen: prev.screen,
      screenParams: prev.params,
      history: history.slice(0, -1),
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
