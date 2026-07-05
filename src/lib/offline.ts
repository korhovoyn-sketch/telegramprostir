import { useAppStore } from '@/store/appStore'

/**
 * Offline guard for event handlers / async actions (NOT render). When the app
 * is offline it shows the standard "Немає інтернету" error toast and returns
 * `true` (caller should `return` early); otherwise returns `false`. Reads the
 * store via getState() so it needs no hook wiring — call it directly:
 *
 *   if (offlineGuard()) return
 *   if (offlineGuard('Експорт недоступний офлайн')) return
 *
 * Replaces the inline `if (!isOnline) { showToast(...); return }` block that was
 * copy-pasted across ~24 sites.
 */
export function offlineGuard(subtitle = 'Збереження недоступне офлайн'): boolean {
  const { isOnline, showToast } = useAppStore.getState()
  if (!isOnline) {
    showToast({ type: 'error', title: 'Немає інтернету', subtitle })
    return true
  }
  return false
}
