'use client'

import { useState } from 'react'
import { useAuth } from '@/hooks/useAuth'
import { useTelegram } from '@/hooks/useTelegram'
import ProxMascot from '@/components/ProxMascot'
import { IconTelegram, IconShield, IconBolt } from '@/components/Icons'

export default function WelcomeScreen() {
  const { loginViaTelegram, loading } = useAuth()
  const { tg, user: tgUser } = useTelegram()

  async function handleLogin() {
    if (!tg?.initData) {
      console.warn('Telegram WebApp not available — dev mode')
      return
    }
    await loginViaTelegram(tg.initData)
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
          <div className="feature-ic" style={{ background: 'rgba(34,158,217,.32)' }}>
            <IconTelegram size={18} color="#fff" />
          </div>
          <div>
            <div className="feature-t">Вхід через Telegram</div>
            <div className="feature-s">Без паролів — автоматична авторизація</div>
          </div>
        </div>
        <div className="feature">
          <div className="feature-ic" style={{ background: 'rgba(52,199,89,.28)' }}>
            <IconShield size={18} color="#fff" />
          </div>
          <div>
            <div className="feature-t">Безпека даних</div>
            <div className="feature-s">HMAC підпис, RLS, шифрування</div>
          </div>
        </div>
        <div className="feature">
          <div className="feature-ic" style={{ background: 'rgba(168,124,255,.32)' }}>
            <IconBolt size={18} color="#fff" />
          </div>
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
      </button>

      <div style={{ textAlign: 'center', fontSize: 11, color: 'var(--t4)', padding: '12px 24px 32px' }}>
        Натискаючи «Вхід», ви погоджуєтесь з Умовами використання та Політикою конфіденційності
      </div>
    </div>
  )
}
