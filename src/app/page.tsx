'use client'

import { useEffect } from 'react'
import dynamic from 'next/dynamic'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { ErrorBoundary } from '@/components/ErrorBoundary'

const SplashScreen = dynamic(() => import('@/screens/SplashScreen'))
const WelcomeScreen = dynamic(() => import('@/screens/WelcomeScreen'))
const RoleSelectScreen = dynamic(() => import('@/screens/RoleSelectScreen'))
const ProfileSetupScreen = dynamic(() => import('@/screens/ProfileSetupScreen'))
const EmptyStateScreen = dynamic(() => import('@/screens/EmptyStateScreen'))
const DatabaseListScreen = dynamic(() => import('@/screens/DatabaseListScreen'))
const CreateDatabaseScreen = dynamic(() => import('@/screens/CreateDatabaseScreen'))
const DatabaseObjectsScreen = dynamic(() => import('@/screens/DatabaseObjectsScreen'))
const PropertyFormScreen = dynamic(() => import('@/screens/PropertyFormScreen'))
const PropertyDetailScreen = dynamic(() => import('@/screens/PropertyDetailScreen'))
const SharingAnalyticsScreen = dynamic(() => import('@/screens/SharingAnalyticsScreen'))
const ExportScreen = dynamic(() => import('@/screens/ExportScreen'))
const RealtorDashboardScreen = dynamic(() => import('@/screens/RealtorDashboardScreen'))
const RealtorDatabaseScreen = dynamic(() => import('@/screens/RealtorDatabaseScreen'))
const CollectionsScreen = dynamic(() => import('@/screens/CollectionsScreen'))
const ProfileScreen = dynamic(() => import('@/screens/ProfileScreen'))
const NotificationsScreen = dynamic(() => import('@/screens/NotificationsScreen'))
const ErrorScreen = dynamic(() => import('@/screens/ErrorScreen'))
const SuccessScreen = dynamic(() => import('@/screens/SuccessScreen'))
const PhotoUploadScreen = dynamic(() => import('@/screens/PhotoUploadScreen'))
const PhotoGalleryScreen = dynamic(() => import('@/screens/PhotoGalleryScreen'))
const QRScannerScreen = dynamic(() => import('@/screens/QRScannerScreen'))

export default function Page() {
  const screen = useAppStore((s) => s.screen)
  const historyLength = useAppStore((s) => s.history.length)
  const back = useAppStore((s) => s.back)
  const { setupAuthListener } = useAuth()

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
      default: return <SplashScreen />
    }
  }

  return <ErrorBoundary>{renderScreen()}</ErrorBoundary>
}
