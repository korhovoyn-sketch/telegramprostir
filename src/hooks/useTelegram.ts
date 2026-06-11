'use client'

import { useEffect, useState } from 'react'

interface TelegramUser {
  id: number
  first_name: string
  last_name?: string
  username?: string
  language_code?: string
  is_premium?: boolean
}

interface TelegramWebApp {
  ready: () => void
  expand: () => void
  close: () => void
  initData: string
  initDataUnsafe: {
    user?: TelegramUser
    start_param?: string
  }
  colorScheme: 'light' | 'dark'
  themeParams: Record<string, string>
  BackButton: {
    show: () => void
    hide: () => void
    onClick: (fn: () => void) => void
    offClick: (fn: () => void) => void
  }
  MainButton: {
    text: string
    show: () => void
    hide: () => void
    enable: () => void
    disable: () => void
    showProgress: (leaveActive?: boolean) => void
    hideProgress: () => void
    onClick: (fn: () => void) => void
    offClick: (fn: () => void) => void
  }
  HapticFeedback: {
    impactOccurred: (style: 'light' | 'medium' | 'heavy' | 'rigid' | 'soft') => void
    notificationOccurred: (type: 'error' | 'success' | 'warning') => void
    selectionChanged: () => void
  }
  CloudStorage?: {
    setItem: (key: string, value: string, callback?: (err: Error | null, stored?: boolean) => void) => void
    getItem: (key: string, callback: (err: Error | null, value?: string) => void) => void
    removeItem: (key: string, callback?: (err: Error | null, removed?: boolean) => void) => void
  }
  enableClosingConfirmation: () => void
  disableClosingConfirmation: () => void
  showPopup: (params: { title?: string; message: string; buttons?: { type: string; text?: string }[] }) => void
  openLink: (url: string) => void
  openTelegramLink: (url: string) => void
  sendData: (data: string) => void
  switchInlineQuery: (query: string, choose_chat_types?: string[]) => void
  version: string
  platform: string
  isExpanded: boolean
}

declare global {
  interface Window {
    Telegram?: {
      WebApp: TelegramWebApp
    }
  }
}

export function useTelegram() {
  const [tg, setTg] = useState<TelegramWebApp | null>(null)
  const [user, setUser] = useState<TelegramUser | null>(null)
  const [isReady, setIsReady] = useState(false)

  useEffect(() => {
    let cancelled = false

    function init(webApp: TelegramWebApp) {
      try {
        webApp.ready()
        webApp.expand()
        setTg(webApp)
        setUser(webApp.initDataUnsafe?.user ?? null)
      } catch {
        // Older TMA versions may throw on ready()/expand() — still mark as ready
      } finally {
        setIsReady(true)
      }
    }

    // The Telegram SDK loads via a deferred external <script>, so it may not be
    // present on first mount. Poll briefly for it instead of giving up immediately —
    // otherwise initData is empty and login fails inside Telegram.
    const existing = window.Telegram?.WebApp
    if (existing) {
      init(existing)
      return
    }

    const start = Date.now()
    const pollId = setInterval(() => {
      if (cancelled) return
      const webApp = window.Telegram?.WebApp
      if (webApp) {
        clearInterval(pollId)
        init(webApp)
      } else if (Date.now() - start > 4000) {
        // SDK never loaded (opened outside Telegram) — unblock the splash anyway
        clearInterval(pollId)
        setIsReady(true)
      }
    }, 50)

    return () => {
      cancelled = true
      clearInterval(pollId)
    }
  }, [])

  function haptic(style: 'light' | 'medium' | 'heavy' = 'light') {
    tg?.HapticFeedback.impactOccurred(style)
  }

  function hapticSuccess() {
    tg?.HapticFeedback.notificationOccurred('success')
  }

  function hapticError() {
    tg?.HapticFeedback.notificationOccurred('error')
  }

  return { tg, user, isReady, haptic, hapticSuccess, hapticError }
}
