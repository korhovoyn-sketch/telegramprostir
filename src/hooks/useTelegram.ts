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
    const webApp = window.Telegram?.WebApp
    if (webApp) {
      webApp.ready()
      webApp.expand()
      setTg(webApp)
      setUser(webApp.initDataUnsafe?.user ?? null)
      setIsReady(true)
    } else {
      setIsReady(true)
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
