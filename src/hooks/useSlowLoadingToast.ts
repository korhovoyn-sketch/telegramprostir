'use client'

import { useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { tr } from '@/lib/i18n'

// Surfaces a one-time toast when a load takes unusually long, so a slow
// connection doesn't read as a frozen app on the first screen after login.
export function useSlowLoadingToast(loading: boolean, delayMs = 4000): void {
  const showToast = useAppStore((s) => s.showToast)

  useEffect(() => {
    if (!loading) return
    const t = setTimeout(() => {
      showToast({
        type: 'info',
        title: tr('Повільне зʼєднання'),
        subtitle: tr('Завантаження триває довше, ніж зазвичай...'),
      })
    }, delayMs)
    return () => clearTimeout(t)
  }, [loading, delayMs, showToast])
}
