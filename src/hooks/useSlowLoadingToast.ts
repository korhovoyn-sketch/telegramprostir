'use client'

import { useEffect } from 'react'
import { useAppStore } from '@/store/appStore'

// Surfaces a one-time toast when a load takes unusually long, so a slow
// connection doesn't read as a frozen app on the first screen after login.
export function useSlowLoadingToast(loading: boolean, delayMs = 4000): void {
  const showToast = useAppStore((s) => s.showToast)

  useEffect(() => {
    if (!loading) return
    const t = setTimeout(() => {
      showToast({
        type: 'info',
        title: 'Повільне з\'єднання',
        subtitle: 'Завантаження триває довше, ніж зазвичай...',
      })
    }, delayMs)
    return () => clearTimeout(t)
  }, [loading, delayMs, showToast])
}
