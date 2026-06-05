'use client'

import { useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useAuth } from '@/hooks/useAuth'
import { IconBuildingSkyscraper, IconUser } from '@/components/Icons'
import type { UserRole } from '@/types'

export default function RoleSelectScreen() {
  const [role, setRole] = useState<UserRole | null>(null)
  const [loading, setLoading] = useState(false)
  const { updateProfile } = useAuth()
  const navigate = useAppStore((s) => s.navigate)

  async function handleContinue() {
    if (!role) return
    setLoading(true)
    await updateProfile({ role })
    setLoading(false)
    navigate('profile-setup')
  }

  return (
    <div className="scr bg-purple">
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
          Крок 1 з 2
        </div>
        <div className="display" style={{ textAlign: 'center' }}>Хто ти?</div>
        <div className="subt" style={{ textAlign: 'center', marginBottom: 8 }}>
          Обери роль — це визначить набір функцій
        </div>
      </div>

      <div style={{ padding: '16px var(--g3) 0' }}>
        {/* Owner card */}
        <div
          className={`glass${role === 'owner' ? '-d' : '-s'}`}
          style={{
            borderRadius: 'var(--r-lg)',
            padding: 20,
            marginBottom: 12,
            cursor: 'pointer',
            border: role === 'owner' ? '.5px solid rgba(120,180,255,.55)' : undefined,
            background: role === 'owner' ? 'rgba(34,158,217,.18)' : undefined,
            boxShadow: role === 'owner' ? '0 0 0 2px rgba(34,158,217,.18) inset' : undefined,
            transition: 'all .18s var(--ease)',
          }}
          onClick={() => setRole('owner')}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
            <div style={{
              width: 48,
              height: 48,
              borderRadius: 'var(--r-md)',
              background: 'linear-gradient(135deg,#7AB3FF,#5B7FE8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 6px 18px rgba(122,179,255,.36)',
            }}>
              <IconBuildingSkyscraper size={22} color="#fff" />
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--t1)', letterSpacing: '-.01em' }}>
                Власник
              </div>
              <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>
                Я здаю / продаю нерухомість
              </div>
            </div>
            {role === 'owner' && (
              <div style={{ marginLeft: 'auto', width: 24, height: 24, borderRadius: '50%', background: '#7AB3FF', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <span style={{ fontSize: 14, color: 'var(--t1)' }}>✓</span>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {['Створюй бази і об\'єкти', 'Ділись QR з ріелторами', 'Переглядай аналітику'].map((f) => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--t2)' }}>
                <span style={{ color: '#34C759', fontSize: 12 }}>✓</span>
                {f}
              </div>
            ))}
          </div>
        </div>

        {/* Realtor card */}
        <div
          className={`glass${role === 'realtor' ? '-d' : '-s'}`}
          style={{
            borderRadius: 'var(--r-lg)',
            padding: 20,
            cursor: 'pointer',
            border: role === 'realtor' ? '.5px solid rgba(255,122,184,.55)' : undefined,
            background: role === 'realtor' ? 'rgba(255,80,180,.14)' : undefined,
            boxShadow: role === 'realtor' ? '0 0 0 2px rgba(255,80,180,.14) inset' : undefined,
            transition: 'all .18s var(--ease)',
          }}
          onClick={() => setRole('realtor')}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
            <div style={{
              width: 48,
              height: 48,
              borderRadius: 'var(--r-md)',
              background: 'linear-gradient(135deg,#FF7AB8,#C42378)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 6px 18px rgba(196,35,120,.36)',
            }}>
              <IconUser size={22} color="#fff" />
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--t1)', letterSpacing: '-.01em' }}>
                Ріелтор
              </div>
              <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>
                Я працюю з клієнтами
              </div>
            </div>
            {role === 'realtor' && (
              <div style={{ marginLeft: 'auto', width: 24, height: 24, borderRadius: '50%', background: '#FF7AB8', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <span style={{ fontSize: 14, color: 'var(--t1)' }}>✓</span>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {['Підписуйся на бази власників', 'Створюй підбірки для клієнтів', 'Зберігай обрані об\'єкти'].map((f) => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--t2)' }}>
                <span style={{ color: '#FF7AB8', fontSize: 12 }}>✓</span>
                {f}
              </div>
            ))}
          </div>
        </div>
      </div>

      <button
        className={`mbtn ${!role || loading ? 'disabled' : ''} ${loading ? 'is-loading' : ''}`}
        onClick={handleContinue}
        disabled={!role || loading}
      >
        {!loading && 'Продовжити →'}
      </button>
    </div>
  )
}
