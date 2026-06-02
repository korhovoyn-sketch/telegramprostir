'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import TabBar from '@/components/ui/TabBar'
import Toggle from '@/components/ui/Toggle'
import { IconMail, IconPhone, IconLanguage, IconCurrencyDollar, IconMoon, IconLogout, IconCrown } from '@/components/Icons'
import { getInitials } from '@/lib/utils'

export default function ProfileScreen() {
  const { user, databases, showToast } = useAppStore()
  const { logout, updateProfile } = useAuth()

  const [pushEnabled, setPushEnabled] = useState(() => {
    if (typeof window === 'undefined') return true
    return localStorage.getItem('pref_push') !== 'false'
  })
  const [weeklyReport, setWeeklyReport] = useState(() => {
    if (typeof window === 'undefined') return true
    return localStorage.getItem('pref_weekly') !== 'false'
  })
  const [newViews, setNewViews] = useState(() => {
    if (typeof window === 'undefined') return true
    return localStorage.getItem('pref_views') !== 'false'
  })

  function handlePushToggle(v: boolean) {
    setPushEnabled(v)
    localStorage.setItem('pref_push', String(v))
  }

  function handleWeeklyToggle(v: boolean) {
    setWeeklyReport(v)
    localStorage.setItem('pref_weekly', String(v))
  }

  function handleNewViewsToggle(v: boolean) {
    setNewViews(v)
    localStorage.setItem('pref_views', String(v))
  }

  if (!user) return null

  const initials = getInitials(user.first_name, user.last_name)
  const totalProps = databases.reduce((s, d) => s + (d._property_count ?? 0), 0)
  const roleLabel = user.role === 'owner' ? 'Власник' : 'Ріелтор'

  return (
    <div className="scr bg-violet">
      <div className="hdr">
        <div className="hdr-sp" />
        <div className="hdr-t">Профіль</div>
        <div className="hdr-sp" />
      </div>

      <div className="body">
        {/* Profile card */}
        <div className="profile-c glass-s" style={{ margin: '0 12px 12px' }}>
          <div className="profile-av">{initials}</div>
          <div className="profile-mn">
            <div className="profile-n">{user.first_name} {user.last_name}</div>
            <div className="profile-r">
              {user.tg_username && <span>@{user.tg_username}</span>}
              <span className="bdg bdg-info">{roleLabel}</span>
            </div>
          </div>
          <button className="profile-edit">✏️</button>
        </div>

        {/* Stats */}
        {user.role === 'owner' && (
          <div className="profile-stats">
            <div className="pstat glass-s">
              <div className="pstat-n">{databases.length}</div>
              <div className="pstat-l">Баз</div>
            </div>
            <div className="pstat glass-s">
              <div className="pstat-n">{totalProps}</div>
              <div className="pstat-l">Об&apos;єктів</div>
            </div>
            <div className="pstat glass-s">
              <div className="pstat-n">{user.plan === 'pro' ? '♾' : 'Free'}</div>
              <div className="pstat-l">Тариф</div>
            </div>
          </div>
        )}

        {/* Pro card */}
        {user.plan !== 'pro' && (
          <div className="pro-card">
            <div className="pro-ic">
              <IconCrown size={18} />
            </div>
            <div className="pro-mn">
              <div className="pro-t">PropSpace Pro</div>
              <div className="pro-s">Експорт у LUN, розширена аналітика</div>
            </div>
            <span style={{ fontSize: 14, color: '#FFD700' }}>→</span>
          </div>
        )}

        {/* Contacts */}
        <div className="over">Контакти</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <IconMail size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Email</span>
            <input className="fr-i" type="email" placeholder="Не вказано" defaultValue={user.email ?? ''} onBlur={async e => { try { await updateProfile({ email: e.target.value }) } catch { showToast({ type: 'error', title: 'Помилка збереження email' }) } }} />
          </div>
          <div className="fr">
            <IconPhone size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Телефон</span>
            <input className="fr-i" type="tel" placeholder="Не вказано" defaultValue={user.phone ?? ''} onBlur={async e => { try { await updateProfile({ phone: e.target.value }) } catch { showToast({ type: 'error', title: 'Помилка збереження телефону' }) } }} />
          </div>
        </div>

        {/* Settings */}
        <div className="over">Налаштування</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <IconLanguage size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Мова</span>
            <div className="fr-seg" style={{ maxWidth: 130 }}>
              {(['uk', 'en'] as const).map(lang => (
                <div
                  key={lang}
                  className={`fr-seg-b ${(user.language_code ?? 'uk') === lang ? 'on' : ''}`}
                  onClick={() => updateProfile({ language_code: lang })}
                >
                  {lang === 'uk' ? 'Укр' : 'Eng'}
                </div>
              ))}
            </div>
          </div>
          <div className="fr">
            <IconCurrencyDollar size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Валюта</span>
            <div className="fr-seg" style={{ maxWidth: 180 }}>
              {(['USD', 'UAH', 'EUR'] as const).map(cur => (
                <div
                  key={cur}
                  className={`fr-seg-b ${(user.currency ?? 'USD') === cur ? 'on' : ''}`}
                  onClick={() => updateProfile({ currency: cur })}
                >
                  {cur}
                </div>
              ))}
            </div>
          </div>
          <div className="fr">
            <IconMoon size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Тема</span>
            <span style={{ flex: 1, textAlign: 'right', color: 'var(--t3)', fontSize: 14 }}>Темна</span>
          </div>
        </div>

        {/* Notifications */}
        <div className="over">Сповіщення</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l">Telegram Push</span>
            <Toggle value={pushEnabled} onChange={handlePushToggle} />
          </div>
          <div className="fr">
            <span className="fr-l">Щотижневий звіт</span>
            <Toggle value={weeklyReport} onChange={handleWeeklyToggle} />
          </div>
          <div className="fr">
            <span className="fr-l">Нові перегляди</span>
            <Toggle value={newViews} onChange={handleNewViewsToggle} />
          </div>
        </div>

        {/* Support */}
        <div className="over">Підтримка</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr" style={{ cursor: 'pointer' }}>
            <span className="fr-l">Допомога</span>
            <span className="chev">›</span>
          </div>
          <div className="fr" style={{ cursor: 'pointer' }}>
            <span className="fr-l">Написати нам</span>
            <span className="chev">›</span>
          </div>
        </div>

        {/* Legal */}
        <div className="over">Правові документи</div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr" style={{ cursor: 'pointer' }}>
            <span className="fr-l">Умови використання</span>
            <span className="chev">›</span>
          </div>
          <div className="fr" style={{ cursor: 'pointer' }}>
            <span className="fr-l">Конфіденційність</span>
            <span className="chev">›</span>
          </div>
        </div>

        {/* Logout */}
        <div className="logout" onClick={logout}>
          <IconLogout size={16} />
          {' '}Вийти з акаунту
        </div>

        <div style={{ textAlign: 'center', fontSize: 11, color: 'var(--t4)', paddingBottom: 80 }}>
          PropSpace v1.0.0
        </div>
      </div>

      <TabBar />
    </div>
  )
}
