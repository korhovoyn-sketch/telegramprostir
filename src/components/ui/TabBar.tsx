'use client'

import { useAppStore } from '@/store/appStore'
import { IconDatabase, IconChartBar, IconBell, IconUser } from '@/components/Icons'
import type { ScreenName } from '@/types'

interface Tab {
  id: string
  label: string
  screen: ScreenName
  icon: React.ReactNode
}

const OWNER_TABS: Tab[] = [
  { id: 'db-list', label: 'Бази', screen: 'db-list', icon: <IconDatabase size={22} /> },
  { id: 'analytics', label: 'Аналітика', screen: 'sharing-analytics', icon: <IconChartBar size={22} /> },
  { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: <IconBell size={22} /> },
  { id: 'profile', label: 'Профіль', screen: 'profile', icon: <IconUser size={22} /> },
]

const REALTOR_TABS: Tab[] = [
  { id: 'realtor-dashboard', label: 'Бази', screen: 'realtor-dashboard', icon: <IconDatabase size={22} /> },
  { id: 'collections', label: 'Підбірки', screen: 'collections', icon: <IconChartBar size={22} /> },
  { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: <IconBell size={22} /> },
  { id: 'profile', label: 'Профіль', screen: 'profile', icon: <IconUser size={22} /> },
]

export default function TabBar() {
  const { screen, navigate, user, unreadCount } = useAppStore()

  const tabs = user?.role === 'realtor' ? REALTOR_TABS : OWNER_TABS

  const activeId = tabs.find(t => t.screen === screen)?.id ?? tabs[0].id

  return (
    <div className="tabbar">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`tab ${activeId === tab.id ? 'on' : ''}`}
          onClick={() => navigate(tab.screen)}
          style={{ background: 'none', border: 'none' }}
        >
          <div style={{ position: 'relative', display: 'inline-flex' }}>
            {tab.icon}
            {tab.id === 'notifications' && unreadCount > 0 && (
              <span style={{
                position: 'absolute',
                top: -4,
                right: -4,
                width: 16,
                height: 16,
                borderRadius: '50%',
                background: '#FF3B30',
                border: '1.5px solid #06051a',
                fontSize: 9,
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
