'use client'

import './globals.css'
import { useEffect } from 'react'
import Toast from '@/components/ui/Toast'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    if (typeof window !== 'undefined' && window.Telegram?.WebApp) {
      const tg = window.Telegram.WebApp as unknown as Record<string, (c: string) => void>
      tg.setHeaderColor?.('#1a0533')
      tg.setBackgroundColor?.('#1a0533')
    }

    // Global error capture — logs structured data without exposing PII.
    // Replace console.error with Sentry.captureException when DSN is configured.
    const handleError = (event: ErrorEvent) => {
      console.error('[GlobalError]', {
        message: event.message,
        filename: event.filename,
        line: event.lineno,
        col: event.colno,
      })
    }
    const handleRejection = (event: PromiseRejectionEvent) => {
      console.error('[UnhandledRejection]', String(event.reason))
    }
    window.addEventListener('error', handleError)
    window.addEventListener('unhandledrejection', handleRejection)
    return () => {
      window.removeEventListener('error', handleError)
      window.removeEventListener('unhandledrejection', handleRejection)
    }
  }, [])

  return (
    <html lang="uk">
      <head>
        <script src="https://telegram.org/js/telegram-web-app.js" defer></script>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover, interactive-widget=resizes-content" />
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
