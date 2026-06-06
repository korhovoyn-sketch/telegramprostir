'use client'

import { useEffect } from 'react'
import dynamic from 'next/dynamic'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useDeepLink } from '@/hooks/useDeepLink'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import SplashScreen from '@/screens/SplashScreen'

const screenFallback = (
  <div className="scr bg-purple" style={{ alignItems: 'center', justifyContent: 'center' }}>
    <div className="loader" />
  </div>
)

const WelcomeScreen = dynamic(() => import('@/screens/WelcomeScreen'), { loading: () => screenFallback })
const RoleSelectScreen = dynamic(() => import('@/screens/RoleSelectScreen'), { loading: () => screenFallback })
const ProfileSetupScreen = dynamic(() => import('@/screens/ProfileSetupScreen'), { loading: () => screenFallback })
const EmptyStateScreen = dynamic(() => import('@/screens/EmptyStateScreen'), { loading: () => screenFallback })
const DatabaseListScreen = dynamic(() => import('@/screens/DatabaseListScreen'), { loading: () => screenFallback })
const CreateDatabaseScreen = dynamic(() => import('@/screens/CreateDatabaseScreen'), { loading: () => screenFallback })
const DatabaseObjectsScreen = dynamic(() => import('@/screens/DatabaseObjectsScreen'), { loading: () => screenFallback })
const PropertyFormScreen = dynamic(() => import('@/screens/PropertyFormScreen'), { loading: () => screenFallback })
const PropertyDetailScreen = dynamic(() => import('@/screens/PropertyDetailScreen'), { loading: () => screenFallback })
const SharingAnalyticsScreen = dynamic(() => import('@/screens/SharingAnalyticsScreen'), { loading: () => screenFallback })
const ExportScreen = dynamic(() => import('@/screens/ExportScreen'), { loading: () => screenFallback })
const RealtorDashboardScreen = dynamic(() => import('@/screens/RealtorDashboardScreen'), { loading: () => screenFallback })
const RealtorDatabaseScreen = dynamic(() => import('@/screens/RealtorDatabaseScreen'), { loading: () => screenFallback })
const CollectionsScreen = dynamic(() => import('@/screens/CollectionsScreen'), { loading: () => screenFallback })
const ProfileScreen = dynamic(() => import('@/screens/ProfileScreen'), { loading: () => screenFallback })
const NotificationsScreen = dynamic(() => import('@/screens/NotificationsScreen'), { loading: () => screenFallback })
const ErrorScreen = dynamic(() => import('@/screens/ErrorScreen'), { loading: () => screenFallback })
const SuccessScreen = dynamic(() => import('@/screens/SuccessScreen'), { loading: () => screenFallback })
const PhotoUploadScreen = dynamic(() => import('@/screens/PhotoUploadScreen'), { loading: () => screenFallback })
const PhotoGalleryScreen = dynamic(() => import('@/screens/PhotoGalleryScreen'), { loading: () => screenFallback })
const QRScannerScreen = dynamic(() => import('@/screens/QRScannerScreen'), { loading: () => screenFallback })
const GuestDatabaseScreen = dynamic(() => import('@/screens/GuestDatabaseScreen'), { loading: () => screenFallback })
const SharedCollectionScreen = dynamic(() => import('@/screens/SharedCollectionScreen'), { loading: () => screenFallback })

export default function Page() {
  const screen = useAppStore((s) => s.screen)
  const historyLength = useAppStore((s) => s.history.length)
  const back = useAppStore((s) => s.back)
  const isOnline = useAppStore((s) => s.isOnline)
  const setOnline = useAppStore((s) => s.setOnline)
  const showToast = useAppStore((s) => s.showToast)
  const { setupAuthListener } = useAuth()
  useDeepLink()

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    tg.ready()
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tgAny = tg as any
      tgAny.setHeaderColor?.('#0a0a14')
      tgAny.setBackgroundColor?.('#0a0a14')
      // Prevent accidental app close via vertical swipe on scroll-heavy screens (TMA 7.7+)
      tgAny.disableVerticalSwipes?.()
    } catch { /* older TMA versions may not support these APIs */ }
    if (tg.colorScheme) {
      document.documentElement.dataset.tgTheme = tg.colorScheme
    }
    tg.expand()

    // Sync app height with Telegram's viewport (handles keyboard appear/hide and restore)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tgAny = tg as any
    function applyViewportHeight() {
      const vh = tgAny.viewportHeight
      if (vh && vh > 0) {
        document.documentElement.style.setProperty('--tg-vh', `${vh}px`)
      }
    }
    // Re-expand and re-measure when the app is restored from a minimized state.
    // Named handler so the cleanup below removes the same reference (an inline
    // arrow here would leak and re-stack a listener on every remount).
    function onActivated() {
      tg!.expand()
      applyViewportHeight()
    }
    applyViewportHeight()
    tgAny.onEvent?.('viewportChanged', applyViewportHeight)
    tgAny.onEvent?.('activated', onActivated)

    return () => {
      tgAny.offEvent?.('viewportChanged', applyViewportHeight)
      tgAny.offEvent?.('activated', onActivated)
    }
  }, [])

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    if (historyLength > 0) {
      tg.BackButton.show()
    } else {
      tg.BackButton.hide()
    }
    tg.BackButton.onClick(back)
    return () => { tg.BackButton.offClick(back) }
  }, [historyLength, back])

  // Wire JWT auto-refresh and SIGNED_OUT redirect
  useEffect(() => {
    const subscription = setupAuthListener()
    return () => subscription.unsubscribe()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Network status monitoring
  useEffect(() => {
    const handleOffline = () => {
      setOnline(false)
      window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('warning')
    }
    const handleOnline = () => {
      setOnline(true)
      showToast({ type: 'success', title: 'З\'єднання відновлено' })
    }
    window.addEventListener('offline', handleOffline)
    window.addEventListener('online', handleOnline)
    return () => {
      window.removeEventListener('offline', handleOffline)
      window.removeEventListener('online', handleOnline)
    }
  }, [setOnline, showToast])

  function renderScreen() {
    switch (screen) {
      case 'splash': return <SplashScreen />
      case 'welcome': return <WelcomeScreen />
      case 'role-select': return <RoleSelectScreen />
      case 'profile-setup': return <ProfileSetupScreen />
      case 'empty-state': return <EmptyStateScreen />
      case 'db-list': return <DatabaseListScreen />
      case 'create-db': return <CreateDatabaseScreen />
      case 'edit-db': return <CreateDatabaseScreen />
      case 'db-objects': return <DatabaseObjectsScreen />
      case 'property-form': return <PropertyFormScreen />
      case 'property-detail': return <PropertyDetailScreen />
      case 'sharing-analytics': return <SharingAnalyticsScreen />
      case 'export': return <ExportScreen />
      case 'realtor-dashboard': return <RealtorDashboardScreen />
      case 'realtor-database': return <RealtorDatabaseScreen />
      case 'collections': return <CollectionsScreen />
      case 'profile': return <ProfileScreen />
      case 'notifications': return <NotificationsScreen />
      case 'error': return <ErrorScreen />
      case 'success': return <SuccessScreen />
      case 'photo-upload': return <PhotoUploadScreen />
      case 'photo-gallery': return <PhotoGalleryScreen />
      case 'qr-scanner': return <QRScannerScreen />
      case 'guest-database': return <GuestDatabaseScreen />
      case 'shared-collection': return <SharedCollectionScreen />
      default: return <SplashScreen />
    }
  }

  return (
    <ErrorBoundary>
      {!isOnline && (
        <div className="offline-banner">
          <span>📡</span>
          Немає інтернету — дані можуть бути застарілими
        </div>
      )}
      {renderScreen()}
    </ErrorBoundary>
  )
}
