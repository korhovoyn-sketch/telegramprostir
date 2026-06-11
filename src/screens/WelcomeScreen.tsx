'use client'

import { useState, useEffect, useRef } from 'react'
import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'
import { useTelegram } from '@/hooks/useTelegram'
import ProxMascot from '@/components/ProxMascot'
import { IconTelegram, IconShield, IconBolt, NeonIconChip } from '@/components/Icons'

export default function WelcomeScreen() {
  const { loginViaTelegram, loading } = useAuth()
  const { showToast, screenParams, user, navigateRoot } = useAppStore()
  const { tg, user: tgUser } = useTelegram()
  const [diagLoading, setDiagLoading] = useState(false)
  const autoLoginAttempted = useRef(false)

  // SplashScreen abandons restoreSession after its timeout, but the restore keeps
  // running and may set the user seconds later. Without this watcher the user
  // would be stuck on Welcome with a valid session until they restart the app.
  useEffect(() => {
    if (!user) return
    const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
    if (startParam?.startsWith('db_') || startParam?.startsWith('prop_') || startParam?.startsWith('col_')) return
    if (!user.role) {
      navigateRoot('role-select')
    } else {
      navigateRoot(user.role === 'owner' ? 'db-list' : 'realtor-dashboard')
    }
  }, [user, navigateRoot])

  // Silent auto-login: attempt immediately if Telegram initData is available.
  // This runs here (not in SplashScreen) so the user sees a proper loading UI
  // instead of a frozen progress bar when the Edge Function is cold.
  // Skip when the user explicitly logged out — they want to stay on this screen.
  useEffect(() => {
    if (autoLoginAttempted.current) return
    if (!tg?.initData) return
    if (screenParams.fromLogout) return
    if (useAppStore.getState().user) return
    autoLoginAttempted.current = true
    loginViaTelegram(tg.initData)
  }, [tg, loginViaTelegram, screenParams.fromLogout])

  async function handleLogin() {
    if (!tg?.initData) {
      showToast({ type: 'error', title: 'Потрібен Telegram', subtitle: 'Відкрийте додаток через Telegram Mini App' })
      return
    }
    await loginViaTelegram(tg.initData)
  }

  async function handleDiag() {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    if (!supabaseUrl) {
      showToast({ type: 'error', title: 'NEXT_PUBLIC_SUPABASE_URL не вказано', subtitle: 'Перевірте налаштування Vercel' })
      return
    }
    setDiagLoading(true)
    try {
      const res = await fetch(`${supabaseUrl}/functions/v1/telegram-auth`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${anonKey ?? ''}`,
          'apikey': anonKey ?? '',
        },
      })
      const data = await res.json()
      if (data.ok) {
        showToast({ type: 'success', title: '✓ Підключення OK', subtitle: 'Edge Function і БД налаштовані' })
      } else {
        const checks = data.checks ?? {}
        const bad = (Object.entries(checks) as [string, boolean][])
          .filter(([, v]) => !v)
          .map(([k]) => k)
        showToast({
          type: 'error',
          title: 'Проблема конфігурації',
          subtitle: bad.length
            ? `Не налаштовано: ${bad.join(', ')}`
            : 'Edge Function недоступна',
        })
      }
    } catch {
      showToast({ type: 'error', title: 'Edge Function недоступна', subtitle: 'Перевірте, що функцію задеплоєно у Supabase' })
    } finally {
      setDiagLoading(false)
    }
  }

  const greeting = tgUser?.first_name ? `Привіт, ${tgUser.first_name}!` : 'Привіт!'

  return (
    <div className="scr bg-welcome">
      {/* Mascot section */}
      <div className="sticker-wrap">
        <div className="shimmer-ring" />
        <div className="glow-orb" style={{ background: 'radial-gradient(circle,rgba(120,80,255,.6),transparent 70%)' }} />
        <div className="sticker">
          <ProxMascot mood="happy" size={140} />
        </div>
      </div>

      <div className="heading">{greeting}<br />Я — Прокс</div>
      <div className="subtext">
        Твій AI-асистент для <b>управління нерухомістю</b> у Telegram.
        Бази, об&apos;єкти, аналітика — все в одному місці.
      </div>

      {/* Features */}
      <div className="features-list">
        <div className="feature">
          <NeonIconChip color="cyan" size={40}><IconTelegram size={20} color="#fff" /></NeonIconChip>
          <div>
            <div className="feature-t">Вхід через Telegram</div>
            <div className="feature-s">Без паролів — автоматична авторизація</div>
          </div>
        </div>
        <div className="feature">
          <NeonIconChip color="teal" size={40}><IconShield size={20} color="#fff" /></NeonIconChip>
          <div>
            <div className="feature-t">Безпека даних</div>
            <div className="feature-s">HMAC підпис, RLS, шифрування</div>
          </div>
        </div>
        <div className="feature">
          <NeonIconChip color="purple" size={40}><IconBolt size={20} color="#fff" /></NeonIconChip>
          <div>
            <div className="feature-t">Швидкий старт</div>
            <div className="feature-s">Три кроки до першої бази</div>
          </div>
        </div>
      </div>

      {/* Login button */}
      <button
        className={`mbtn ${loading ? 'is-loading' : ''}`}
        onClick={handleLogin}
        disabled={loading}
        style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', margin: '24px 12px 0', width: 'calc(100% - 24px)' }}
      >
        {!loading && <IconTelegram size={18} />}
        {!loading && 'Вхід через Telegram'}
        {loading && <span style={{ fontSize: 13, opacity: 0.8 }}>Авторизуємось...</span>}
      </button>

      <div style={{ textAlign: 'center', fontSize: 13, color: 'var(--t3)', padding: '12px 24px 8px', lineHeight: 1.5 }}>
        Натискаючи «Вхід», ви погоджуєтесь з Умовами використання та Політикою конфіденційності
      </div>

      <button
        onClick={handleDiag}
        disabled={diagLoading}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--t4)',
          fontSize: 11,
          cursor: 'pointer',
          padding: '4px 16px 32px',
          opacity: diagLoading ? 0.5 : 1,
        }}
      >
        {diagLoading ? 'Перевірка...' : '⚙ Діагностика підключення'}
      </button>
    </div>
  )
}
