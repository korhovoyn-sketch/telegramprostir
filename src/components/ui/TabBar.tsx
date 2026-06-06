'use client'

import { useAppStore } from '@/store/appStore'
import { IconDatabase, IconBookmark, IconBell, IconUser, IconChartBar } from '@/components/Icons'
import type { ScreenName } from '@/types'

interface Tab {
  id: string
  label: string
  screen: ScreenName
  icon: React.ReactNode
  onPress?: () => void
}

const REALTOR_TABS: Tab[] = [
  { id: 'realtor-dashboard', label: 'Бази', screen: 'realtor-dashboard', icon: <IconDatabase size={22} /> },
  { id: 'collections', label: 'Підбірки', screen: 'collections', icon: <IconBookmark size={22} /> },
  { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: <IconBell size={22} /> },
  { id: 'profile', label: 'Профіль', screen: 'profile', icon: <IconUser size={22} /> },
]

export default function TabBar() {
  const { screen, navigateRoot, user, unreadCount, lastDbId, showToast } = useAppStore()

  const OWNER_TABS: Tab[] = [
    { id: 'db-list', label: 'Бази', screen: 'db-list', icon: <IconDatabase size={22} /> },
    {
      id: 'analytics',
      label: 'Аналітика',
      screen: 'sharing-analytics',
      icon: <IconChartBar size={22} />,
      onPress: () => {
        if (lastDbId) {
          navigateRoot('sharing-analytics', { dbId: lastDbId })
        } else {
          showToast({ type: 'info', title: 'Відкрийте базу спочатку', subtitle: 'Аналітика доступна після відкриття бази' })
          navigateRoot('db-list')
        }
      },
    },
    { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: <IconBell size={22} /> },
    { id: 'profile', label: 'Профіль', screen: 'profile', icon: <IconUser size={22} /> },
  ]

  const tabs = user?.role === 'realtor' ? REALTOR_TABS : OWNER_TABS

  const activeId = tabs.find(t => t.screen === screen)?.id ?? tabs[0].id

  return (
    <div className="tabbar">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`tab ${activeId === tab.id ? 'on' : ''}`}
          onClick={() => tab.onPress ? tab.onPress() : navigateRoot(tab.screen)}
          style={{ background: 'none', border: 'none' }}
        >
          <div style={{ position: 'relative', display: 'inline-flex' }}>
            {tab.icon}
            {tab.id === 'notifications' && unreadCount > 0 && (
              <span style={{
                position: 'absolute',
                top: -4,
                right: -4,
                width: 17,
                height: 17,
                borderRadius: '50%',
                background: 'var(--err)',
                border: '1.5px solid var(--bg)',
                fontSize: 10,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
              }}>
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </div>
          <span className="tab-l">{tab.label}</span>
        </button>
      ))}
    </div>
  )
}
