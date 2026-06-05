'use client'

import { useState, useEffect } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { IconMail, IconPhone, IconTelegram } from '@/components/Icons'
import { scrollFocusedIntoView } from '@/lib/utils'

export default function ProfileSetupScreen() {
  const user = useAppStore((s) => s.user)
  const navigate = useAppStore((s) => s.navigate)
  const { updateProfile, loading } = useAuth()

  const [email, setEmail] = useState(user?.email ?? '')
  const [phone, setPhone] = useState(user?.phone ?? '')

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    tg?.enableClosingConfirmation()
    return () => { tg?.disableClosingConfirmation() }
  }, [])

  async function handleContinue() {
    if (email || phone) {
      await updateProfile({ email: email || undefined, phone: phone || undefined })
    }
    navigate(user?.role === 'owner' ? 'empty-state' : 'realtor-dashboard')
  }

  function skip() {
    navigate(user?.role === 'owner' ? 'empty-state' : 'realtor-dashboard')
  }

  return (
    <div className="scr bg-purple" onFocusCapture={scrollFocusedIntoView}>
      <div style={{ padding: 'calc(24px + var(--safe-top)) 0 0', textAlign: 'center' }}>
        <div style={{
          display: 'inline-block',
          padding: '5px 14px',
          background: 'var(--glass-1)',
          border: 'var(--bd)',
          borderRadius: 'var(--r-pill)',
          fontSize: 11,
          color: 'var(--t3)',
          fontWeight: 600,
          letterSpacing: '.06em',
          textTransform: 'uppercase',
          marginBottom: 16,
        }}>
          Крок 2 з 2
        </div>
        <div className="display" style={{ textAlign: 'center' }}>Контакти</div>
        <div className="subt" style={{ textAlign: 'center', marginBottom: 24 }}>
          Необов&apos;язково — для сповіщень і звітів
        </div>
      </div>

      {/* Telegram data (locked) */}
      <div style={{ margin: '0 12px 16px' }}>
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconTelegram size={13} color="#7AB3FF" />Дані Telegram</span></div>
        <div className="fg glass-s">
          <div className="fr">
            <span className="fr-l">Ім&apos;я</span>
            <span style={{ flex: 1, textAlign: 'right', color: 'var(--t3)', fontSize: 14 }}>
              {user?.first_name} {user?.last_name}
            </span>
            <span style={{ fontSize: 11, color: 'var(--t4)', marginLeft: 6 }}>🔒</span>
          </div>
          {user?.tg_username && (
            <div className="fr">
              <span className="fr-l">Username</span>
              <span style={{ flex: 1, textAlign: 'right', color: 'var(--t3)', fontSize: 14 }}>
                @{user.tg_username}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Optional contacts */}
      <div style={{ margin: '0 12px 16px' }}>
        <div className="over"><span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><IconPhone size={13} color="#4ade80" />Додаткові контакти</span></div>
        <div className="fg glass-s">
          <div className="fr">
            <IconMail size={16} color="var(--t3)" />
            <span className="fr-l">Email</span>
            <input
              className="fr-i"
              type="email"
              placeholder="you@email.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="fr">
            <IconPhone size={16} color="var(--t3)" />
            <span className="fr-l">Телефон</span>
            <input
              className="fr-i"
              type="tel"
              placeholder="+380 67 000 0000"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
          </div>
        </div>
      </div>

      <button
        className={`mbtn success ${loading ? 'is-loading' : ''}`}
        onClick={handleContinue}
        disabled={loading}
      >
        {!loading && 'Почати роботу →'}
      </button>

      <button
        onClick={skip}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--t3)',
          fontSize: 13,
          padding: '12px',
          width: '100%',
          textAlign: 'center',
          position: 'absolute',
          bottom: 'calc(78px + var(--safe-bottom))',
        }}
      >
        Пропустити →
      </button>
    </div>
  )
}
