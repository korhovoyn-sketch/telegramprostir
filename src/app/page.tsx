'use client'

import { useEffect } from 'react'
import dynamic from 'next/dynamic'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { useDeepLink } from '@/hooks/useDeepLink'
import { useNotifications } from '@/hooks/useNotifications'
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
const GuestHomeScreen = dynamic(() => import('@/screens/GuestHomeScreen'), { loading: () => screenFallback })
const ManageGuestsScreen = dynamic(() => import('@/screens/ManageGuestsScreen'), { loading: () => screenFallback })
const SharedCollectionScreen = dynamic(() => import('@/screens/SharedCollectionScreen'), { loading: () => screenFallback })
const PaymentCalendarScreen = dynamic(() => import('@/screens/PaymentCalendarScreen'), { loading: () => screenFallback })

export default function Page() {
  const screen = useAppStore((s) => s.screen)
  const navKey = useAppStore((s) => s.navKey)
  const navDirection = useAppStore((s) => s.navDirection)
  const historyLength = useAppStore((s) => s.history.length)
  const back = useAppStore((s) => s.back)
  const isOnline = useAppStore((s) => s.isOnline)
  const setOnline = useAppStore((s) => s.setOnline)
  const showToast = useAppStore((s) => s.showToast)
  const userId = useAppStore((s) => s.user?.id)
  const { setupAuthListener } = useAuth()
  const { loadNotifications } = useNotifications()
  useDeepLink()

  // TG SDK setup — runs once on mount
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    tg.ready()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tgAny = tg as any
    try {
      tgAny.setHeaderColor?.('#040408')
      tgAny.setBackgroundColor?.('#040408')
      tgAny.disableVerticalSwipes?.()
    } catch { /* older TMA versions may not support these APIs */ }
    if (tg.colorScheme) {
      document.documentElement.dataset.tgTheme = tg.colorScheme
    }

    // Keyboard height comes from two independent signals and we take the max:
    // - Telegram viewportChanged (works on Android where the webview resizes)
    // - visualViewport (works on iOS where the keyboard overlays the webview and
    //   Telegram's stable/current heights move together, reading as 0)
    let tgKbH = 0
    let vvKbH = 0
    function applyKeyboardHeight() {
      document.documentElement.style.setProperty('--keyboard-h', `${Math.max(tgKbH, vvKbH)}px`)
    }
    function applyViewportHeight() {
      const stable = tgAny.viewportStableHeight ?? tgAny.viewportHeight ?? 0
      const current = tgAny.viewportHeight ?? stable
      if (stable > 0) document.documentElement.style.setProperty('--tg-vh', `${stable}px`)
      tgKbH = Math.max(0, Math.round(stable - current))
      applyKeyboardHeight()
    }
    function onActivated() {
      tg!.expand()
      applyViewportHeight()
    }
    applyViewportHeight()
    tgAny.onEvent?.('viewportChanged', applyViewportHeight)
    tgAny.onEvent?.('activated', onActivated)

    function applyKeyboardFromVV() {
      const vv = window.visualViewport
      if (!vv) return
      vvKbH = Math.max(0, Math.round(window.innerHeight - vv.height - vv.offsetTop))
      applyKeyboardHeight()
    }
    window.visualViewport?.addEventListener('resize', applyKeyboardFromVV)
    window.visualViewport?.addEventListener('scroll', applyKeyboardFromVV)

    return () => {
      tgAny.offEvent?.('viewportChanged', applyViewportHeight)
      tgAny.offEvent?.('activated', onActivated)
      window.visualViewport?.removeEventListener('resize', applyKeyboardFromVV)
      window.visualViewport?.removeEventListener('scroll', applyKeyboardFromVV)
    }
  }, [])

  // BackButton: register handler once (back is a stable Zustand function)
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    tg.BackButton.onClick(back)
    return () => tg.BackButton.offClick(back)
  }, [back])

  // BackButton: show/hide independently of handler registration
  useEffect(() => {
    const tg = window.Telegram?.WebApp
    if (!tg) return
    if (historyLength > 0) tg.BackButton.show()
    else tg.BackButton.hide()
  }, [historyLength])

  // Wire JWT auto-refresh and SIGNED_OUT redirect
  useEffect(() => {
    const subscription = setupAuthListener()
    return () => subscription.unsubscribe()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Populate notification badge as soon as the user is known — without this
  // the unreadCount in the TabBar/header dots stays 0 until the user explicitly
  // opens the Notifications screen in the same session.
  useEffect(() => {
    if (userId) loadNotifications()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId])

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
      case 'guest-home': return <GuestHomeScreen />
      case 'manage-guests': return <ManageGuestsScreen />
      case 'shared-collection': return <SharedCollectionScreen />
      case 'payment-calendar': return <PaymentCalendarScreen />
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
      <div key={navKey} className={`nav-wrap nav-${navDirection}`}>
        {renderScreen()}
      </div>
    </ErrorBoundary>
  )
}
