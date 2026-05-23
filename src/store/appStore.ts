'use client'

import { create } from 'zustand'
import type { User, Toast, ScreenName, ScreenParams, Database, Property, Notification } from '@/types'

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

  navigate: (screen: ScreenName, params?: ScreenParams) => void
  back: () => boolean
  setUser: (user: User | null) => void
  showToast: (toast: Toast) => void
  hideToast: () => void
  setDatabases: (dbs: Database[]) => void
  setNotifications: (notifs: Notification[]) => void
  markAllRead: () => void
}

export const useAppStore = create<AppState>((set, get) => ({
  screen: 'splash',
  screenParams: {},
  history: [],
  user: null,
  toast: null,
  databases: [],
  notifications: [],
  unreadCount: 0,

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
    set({ toast })
    setTimeout(() => set({ toast: null }), 3500)
  },

  hideToast: () => set({ toast: null }),

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
