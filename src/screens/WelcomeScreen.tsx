'use client'

import { useState, useEffect, useRef } from 'react'
import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'
import { useTelegram } from '@/hooks/useTelegram'
import ProxMascot from '@/components/ProxMascot'
import { IconTelegram, GlassTelegram, GlassShield, GlassBolt } from '@/components/Icons'

const AUTH_STEPS = [
  'Підключаємось до Telegram...',
  'Перевіряємо дані...',
  'Завантажуємо профіль...',
  'Налаштовуємо середовище...',
]

export default function WelcomeScreen() {
  const { loginViaTelegram, loading } = useAuth()
  const { showToast, screenParams, user, navigateRoot } = useAppStore()
  const { tg, user: tgUser } = useTelegram()
  const [diagLoading, setDiagLoading] = useState(false)
  const [stepIdx, setStepIdx] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const autoLoginAttempted = useRef(false)
  const loadStartRef = useRef<number>(0)

  // Track loading start time and cycle through auth step messages
  useEffect(() => {
    if (!loading) { setStepIdx(0); setElapsed(0); return }
    loadStartRef.current = Date.now()
    setStepIdx(0)
    const stepTimer = setInterval(() => {
      setStepIdx(i => Math.min(i + 1, AUTH_STEPS.length - 1))
    }, 4000)
    const elapsedTimer = setInterval(() => {
      setElapsed(Date.now() - loadStartRef.current)
    }, 500)
    return () => { clearInterval(stepTimer); clearInterval(elapsedTimer) }
  }, [loading])

  // Navigate when user is set (from restore finishing after splash timed out)
  useEffect(() => {
    if (!user) return
    const startParam = window.Telegram?.WebApp?.initDataUnsafe?.start_param
    if (startParam?.startsWith('db_') || startParam?.startsWith('prop_') || startParam?.startsWith('col_') || startParam?.startsWith('guest_')) return
    if (!user.role) {
      navigateRoot('role-select')
    } else if (user.role === 'owner') {
      navigateRoot('db-list')
    } else if (user.role === 'realtor') {
      navigateRoot('realtor-dashboard')
    } else {
      navigateRoot('guest-home')
    }
  }, [user, navigateRoot])

  // Silent auto-login: 200 ms grace so an in-flight restore can finish first
  useEffect(() => {
    if (autoLoginAttempted.current) return
    if (!tg?.initData) return
    if (screenParams.fromLogout) return
    if (useAppStore.getState().user) return
    autoLoginAttempted.current = true
    const delay = setTimeout(() => {
      if (useAppStore.getState().user) return
      loginViaTelegram(tg!.initData)
    }, 200)
    return () => clearTimeout(delay)
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
        headers: { 'Authorization': `Bearer ${anonKey ?? ''}`, 'apikey': anonKey ?? '' },
      })
      const data = await res.json()
      if (data.ok) {
        showToast({ type: 'success', title: '✓ Підключення OK', subtitle: 'Edge Function і БД налаштовані' })
      } else {
        const checks = data.checks ?? {}
        const bad = (Object.entries(checks) as [string, boolean][])
          .filter(([, v]) => !v).map(([k]) => k)
        showToast({
          type: 'error',
          title: 'Проблема конфігурації',
          subtitle: bad.length ? `Не налаштовано: ${bad.join(', ')}` : 'Edge Function недоступна',
        })
      }
    } catch {
      showToast({ type: 'error', title: 'Edge Function недоступна', subtitle: 'Перевірте, що функцію задеплоєно у Supabase' })
    } finally {
      setDiagLoading(false)
    }
  }

  const greeting = tgUser?.first_name ? `Привіт, ${tgUser.first_name}!` : 'Привіт!'

  // ── Auth loading screen ─────────────────────────────────────────────────────
  if (loading) {
    const showRetry = elapsed > 25000
    return (
      <div className="scr bg-welcome" style={{ alignItems: 'center', justifyContent: 'center', gap: 0 }}>
        {/* Glow behind mascot */}
        <div style={{
          position: 'absolute', width: 280, height: 280, borderRadius: '50%',
          background: 'radial-gradient(circle,rgba(120,80,255,.45),transparent 70%)',
          filter: 'blur(32px)', animation: 'glowPulse 3s ease-in-out infinite',
        }} />

        <div style={{ position: 'relative', marginBottom: 24 }}>
          <ProxMascot mood="neutral" size={110} />
        </div>

        <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--t1)', marginBottom: 8, textAlign: 'center', letterSpacing: '-.01em' }}>
          Авторизація
        </div>
        <div style={{
          fontSize: 14, color: 'var(--t3)', textAlign: 'center',
          padding: '0 40px', marginBottom: 28, lineHeight: 1.5,
          minHeight: 22, transition: 'opacity .3s ease',
        }}>
          {AUTH_STEPS[stepIdx]}
        </div>

        {/* Animated dots */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 32 }}>
          {AUTH_STEPS.map((_, i) => (
            <div key={i} style={{
              width: i === stepIdx ? 20 : 8,
              height: 8, borderRadius: 4,
              background: i === stepIdx ? 'var(--accent)' : 'var(--glass-3)',
              transition: 'all .35s var(--ease)',
            }} />
          ))}
        </div>

        {showRetry ? (
          <div style={{ textAlign: 'center', padding: '0 32px' }}>
            <div style={{ fontSize: 13, color: 'var(--t3)', marginBottom: 16, lineHeight: 1.5 }}>
              Авторизація займає довше, ніж зазвичай.{'\n'}Перевірте підключення до інтернету.
            </div>
            <button
              onClick={handleLogin}
              style={{
                padding: '12px 32px', borderRadius: 'var(--r-pill)',
                background: 'var(--glass-2)', border: 'var(--bd)',
                color: 'var(--t1)', fontSize: 14, fontWeight: 600,
                cursor: 'pointer', letterSpacing: '.01em',
              }}
            >
              Спробувати ще раз
            </button>
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--t4)', textAlign: 'center' }}>
            Не закривайте додаток
          </div>
        )}
      </div>
    )
  }

  // ── Welcome / idle screen ────────────────────────────────────────────────────
  return (
    <div className="scr bg-welcome">
      <div className="body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingBottom: 'calc(var(--btn-h) + 60px + var(--safe-bottom))' }}>
        {/* Mascot */}
        <div className="sticker-wrap">
          <div className="shimmer-ring" />
          <div className="glow-orb" style={{ background: 'radial-gradient(circle,rgba(120,80,255,.6),transparent 70%)' }} />
          <div className="sticker">
            <ProxMascot mood="happy" size={140} />
          </div>
        </div>

        <div className="heading" style={{ textAlign: 'center' }}>{greeting}<br />Я — Прокс</div>
        <div className="subtext" style={{ textAlign: 'center' }}>
          Твій AI-асистент для <b>управління нерухомістю</b> у Telegram.
          Бази, об&apos;єкти, аналітика — все в одному місці.
        </div>

        {/* Feature cards */}
        <div className="features-list" style={{ width: '100%' }}>
          <div className="feature">
            <GlassTelegram size={32} />
            <div>
              <div className="feature-t">Вхід через Telegram</div>
              <div className="feature-s">Без паролів — миттєва авторизація</div>
            </div>
          </div>
          <div className="feature">
            <GlassShield size={32} />
            <div>
              <div className="feature-t">Безпека даних</div>
              <div className="feature-s">HMAC підпис, RLS, шифрування</div>
            </div>
          </div>
          <div className="feature">
            <GlassBolt size={32} />
            <div>
              <div className="feature-t">Швидкий старт</div>
              <div className="feature-s">Три кроки до першої бази</div>
            </div>
          </div>
        </div>

        <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--t4)', padding: '10px 28px 6px', lineHeight: 1.5 }}>
          Натискаючи «Увійти», ви погоджуєтесь з{' '}
          <span style={{ color: 'var(--t3)' }}>Умовами використання</span> та{' '}
          <span style={{ color: 'var(--t3)' }}>Політикою конфіденційності</span>
        </div>

        <button
          onClick={handleDiag}
          disabled={diagLoading}
          style={{
            background: 'none', border: 'none', color: 'var(--t4)',
            fontSize: 11, cursor: 'pointer', padding: '4px 16px 8px',
            opacity: diagLoading ? 0.5 : 1,
          }}
        >
          {diagLoading ? 'Перевірка...' : '⚙ Діагностика підключення'}
        </button>
      </div>

      {/* CTA — always visible at bottom */}
      <button className="mbtn" onClick={handleLogin}>
        <IconTelegram size={18} />
        Увійти через Telegram
      </button>
    </div>
  )
}
