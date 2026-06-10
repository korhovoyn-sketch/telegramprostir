'use client'

import { useAppStore } from '@/store/appStore'
import { IconTabHome, IconTabBookmark, IconTabBell, IconTabUser } from '@/components/Icons'
import type { ScreenName } from '@/types'

interface Tab {
  id: string
  label: string
  screen: ScreenName
  icon: (active: boolean) => React.ReactNode
}

const REALTOR_TABS: Tab[] = [
  { id: 'realtor-dashboard', label: 'Бази', screen: 'realtor-dashboard', icon: (a) => <IconTabHome size={26} active={a} /> },
  { id: 'collections', label: 'Підбірки', screen: 'collections', icon: (a) => <IconTabBookmark size={26} active={a} /> },
  { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: (a) => <IconTabBell size={26} active={a} /> },
  { id: 'profile', label: 'Профіль', screen: 'profile', icon: (a) => <IconTabUser size={26} active={a} /> },
]

const OWNER_TABS: Tab[] = [
  { id: 'db-list', label: 'Бази', screen: 'db-list', icon: (a) => <IconTabHome size={26} active={a} /> },
  { id: 'notifications', label: 'Сповіщення', screen: 'notifications', icon: (a) => <IconTabBell size={26} active={a} /> },
  { id: 'profile', label: 'Профіль', screen: 'profile', icon: (a) => <IconTabUser size={26} active={a} /> },
]

export default function TabBar() {
  const { screen, navigateRoot, user, unreadCount } = useAppStore()

  const tabs = user?.role === 'realtor' ? REALTOR_TABS : OWNER_TABS

  const activeId = tabs.find(t => t.screen === screen)?.id ?? tabs[0].id

  return (
    <div className="tabbar">
      {tabs.map((tab) => {
        const active = activeId === tab.id
        return (
          <button
            key={tab.id}
            className={`tab ${active ? 'on' : ''}`}
            data-t={tab.id}
            aria-label={tab.label}
            onClick={() => navigateRoot(tab.screen)}
            style={{ background: 'none', border: 'none' }}
          >
            <div className="tab-ic">
              <div style={{ position: 'relative', display: 'inline-flex' }}>
                {tab.icon(active)}
                {tab.id === 'notifications' && unreadCount > 0 && (
                  <span style={{
                    position: 'absolute',
                    top: -4,
                    right: -4,
                    width: 17,
                    height: 17,
                    borderRadius: '50%',
                    background: 'var(--err)',
                    border: '1.5px solid rgba(16,13,36,.9)',
                    fontSize: 10,
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#fff',
                    zIndex: 1,
                  }}>
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </div>
            </div>
            <span className="tab-l">{tab.label}</span>
          </button>
        )
      })}
    </div>
  )
}
