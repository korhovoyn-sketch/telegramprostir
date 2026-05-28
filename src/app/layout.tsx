'use client'

import './globals.css'
import { useEffect } from 'react'
import Toast from '@/components/ui/Toast'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      const tg = window.Telegram.WebApp
      tg.ready()
      tg.expand()
      ;(tg as unknown as Record<string, (c: string) => void>).setHeaderColor?.('#1a0533')
      ;(tg as unknown as Record<string, (c: string) => void>).setBackgroundColor?.('#1a0533')
    }
  }, [])

  return (
    <html lang="uk">
      <head>
        <script src="https://telegram.org/js/telegram-web-app.js"></script>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
        <meta name="theme-color" content="#1a0533" />
        <title>PropSpace</title>
      </head>
      <body>
        <div id="app-root">
          {children}
          <Toast />
        </div>
      </body>
    </html>
  )
}
