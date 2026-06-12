'use client'

import { useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import TabBar from '@/components/ui/TabBar'
import Toggle from '@/components/ui/Toggle'
import Modal from '@/components/ui/Modal'
import { IconMail, IconPhone, IconLanguage, IconCurrencyDollar, IconLogout, GlassCrown, IconBell, IconBellRing, IconChartLine, IconEye, IconMessage, IconAdjustments } from '@/components/Icons'
import { TG_BOT } from '@/lib/telegram'
import { getInitials, scrollFocusedIntoView } from '@/lib/utils'

export default function ProfileScreen() {
  const { user, databases } = useAppStore()
  const { logout, updateProfile } = useAuth()

  const [pushEnabled, setPushEnabled] = useState(user?.notification_push ?? true)
  const [weeklyReport, setWeeklyReport] = useState(user?.notification_weekly ?? true)
  const [newViews, setNewViews] = useState(user?.notification_views ?? true)
  const [showLogoutModal, setShowLogoutModal] = useState(false)
  const [savingLang, setSavingLang] = useState(false)
  const [savingCur, setSavingCur] = useState(false)
  const emailRef = useRef<HTMLInputElement>(null)
  const phoneRef = useRef<HTMLInputElement>(null)

  async function handlePushToggle(v: boolean) {
    setPushEnabled(v)
    const ok = await updateProfile({ notification_push: v })
    if (!ok) setPushEnabled(!v)
  }

  async function handleWeeklyToggle(v: boolean) {
    setWeeklyReport(v)
    const ok = await updateProfile({ notification_weekly: v })
    if (!ok) setWeeklyReport(!v)
  }

  async function handleNewViewsToggle(v: boolean) {
    setNewViews(v)
    const ok = await updateProfile({ notification_views: v })
    if (!ok) setNewViews(!v)
  }

  async function handleLangChange(lang: 'uk' | 'en') {
    if ((user?.language_code ?? 'uk') === lang) return
    setSavingLang(true)
    await updateProfile({ language_code: lang })
    setSavingLang(false)
  }

  async function handleCurrencyChange(cur: 'USD' | 'UAH' | 'EUR') {
    if ((user?.currency ?? 'USD') === cur) return
    setSavingCur(true)
    await updateProfile({ currency: cur })
    setSavingCur(false)
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

      <div className="body" onFocusCapture={scrollFocusedIntoView}>
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

        {/* Pro card — upgrade flow not yet available; shown as a teaser, not a button */}
        {user.plan !== 'pro' && (
          <div className="pro-card" style={{ cursor: 'default' }}>
            <GlassCrown size={32} />
            <div className="pro-mn">
              <div className="pro-t">prostir Pro</div>
              <div className="pro-s">Розширені можливості у розробці</div>
            </div>
            <span className="bdg bdg-info">Скоро</span>
          </div>
        )}

        {/* Contacts */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconMail size={13} color="#7AB3FF" />Контакти</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <IconMail size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Email</span>
            <input ref={emailRef} className="fr-i" type="email" placeholder="Не вказано" defaultValue={user.email ?? ''} onBlur={async e => { const val = e.target.value; if (val === (user.email ?? '')) return; const ok = await updateProfile({ email: val }); if (!ok && emailRef.current) emailRef.current.value = user.email ?? '' }} />
          </div>
          <div className="fr">
            <IconPhone size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Телефон</span>
            <input ref={phoneRef} className="fr-i" type="tel" placeholder="Не вказано" defaultValue={user.phone ?? ''} onBlur={async e => { const val = e.target.value; if (val === (user.phone ?? '')) return; const ok = await updateProfile({ phone: val }); if (!ok && phoneRef.current) phoneRef.current.value = user.phone ?? '' }} />
          </div>
        </div>

        {/* Settings */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconAdjustments size={13} color="#a78bfa" />Налаштування</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <IconLanguage size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Мова</span>
            <div className="fr-seg" style={{ maxWidth: 130, opacity: savingLang ? 0.5 : 1, pointerEvents: savingLang ? 'none' : 'auto' }}>
              {(['uk', 'en'] as const).map(lang => (
                <div
                  key={lang}
                  className={`fr-seg-b ${(user.language_code ?? 'uk') === lang ? 'on' : ''}`}
                  onClick={() => handleLangChange(lang)}
                >
                  {savingLang && (user.language_code ?? 'uk') !== lang ? '...' : lang === 'uk' ? 'Укр' : 'Eng'}
                </div>
              ))}
            </div>
          </div>
          <div className="fr">
            <IconCurrencyDollar size={15} color="var(--t3)" />
            <span className="fr-l" style={{ marginLeft: 6 }}>Валюта</span>
            <div className="fr-seg" style={{ maxWidth: 180, opacity: savingCur ? 0.5 : 1, pointerEvents: savingCur ? 'none' : 'auto' }}>
              {(['USD', 'UAH', 'EUR'] as const).map(cur => (
                <div
                  key={cur}
                  className={`fr-seg-b ${(user.currency ?? 'USD') === cur ? 'on' : ''}`}
                  onClick={() => handleCurrencyChange(cur)}
                >
                  {cur}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBell size={13} color="#fbbf24" />Сповіщення</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconBellRing size={14} color="var(--t3)" />Telegram Push</span>
            <Toggle value={pushEnabled} onChange={handlePushToggle} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconChartLine size={14} color="var(--t3)" />Щотижневий звіт</span>
            <Toggle value={weeklyReport} onChange={handleWeeklyToggle} />
          </div>
          <div className="fr">
            <span className="fr-l" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconEye size={14} color="var(--t3)" />Нові перегляди</span>
            <Toggle value={newViews} onChange={handleNewViewsToggle} />
          </div>
        </div>

        {/* Support */}
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconMessage size={13} color="#7AB3FF" />Підтримка</span></div>
        <div className="fg glass-s" style={{ margin: '0 12px 16px' }}>
          <div
            className="fr" style={{ cursor: 'pointer' }}
            onClick={() => window.Telegram?.WebApp?.openTelegramLink(`https://t.me/${TG_BOT}`)}
          >
            <span className="fr-l">Написати нам</span>
            <span className="chev">›</span>
          </div>
        </div>

        {/* Logout */}
        <div className="logout" onClick={() => setShowLogoutModal(true)}>
          <IconLogout size={16} />
          {' '}Вийти з акаунту
        </div>

        <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--t4)', paddingBottom: 80 }}>
          prostir v1.0.0
        </div>
      </div>

      <TabBar />

      {showLogoutModal && (
        <Modal
          title="Вийти з акаунту?"
          subtitle="Для повторного входу знадобиться Telegram"
          onClose={() => setShowLogoutModal(false)}
          actions={[
            { label: 'Вийти', variant: 'danger', onClick: logout },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowLogoutModal(false) },
          ]}
        />
      )}
    </div>
  )
}
