'use client'

import { useState, useEffect, useRef } from 'react'
import { useAuth } from '@/hooks/useAuth'
import { useAppStore } from '@/store/appStore'
import { useTelegram } from '@/hooks/useTelegram'
import { isDeepLinkStartParam } from '@/lib/telegram'
import ProxMascot from '@/components/ProxMascot'
import { IconTelegram, GlassTelegram, GlassShield, GlassBolt, IconAdjustments } from '@/components/Icons'
import { tr } from '@/lib/i18n'
import { tx } from '@/lib/tx'

const AUTH_STEPS = () => ([
  tr('Підключаємось до Telegram...'),
  tr('Перевіряємо дані...'),
  tr('Завантажуємо профіль...'),
  tr('Налаштовуємо середовище...'),
])

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
      setStepIdx(i => Math.min(i + 1, AUTH_STEPS().length - 1))
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
    if (isDeepLinkStartParam(startParam)) return
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

  // Silent auto-login: 200 ms grace so an in-flight restore can finish first.
  // Deps МУСЯТЬ бути стабільними значеннями (рядок initData, не обʼєкт tg, і
  // колбек через ref): attempted-гард ставиться ДО таймера, тож будь-який
  // повторний запуск ефекту в 200мс-вікні (нова ідентичність tg/loginViaTelegram
  // від паралельного ре-рендеру) скасовував таймер у cleanup і впирався в гард —
  // автологін мовчки вмирав, користувач застрягав на Welcome. У dev це маскував
  // StrictMode, наживо било повільні пристрої.
  const loginRef = useRef(loginViaTelegram)
  loginRef.current = loginViaTelegram
  const initData = tg?.initData
  useEffect(() => {
    if (autoLoginAttempted.current) return
    if (!initData) return
    if (screenParams.fromLogout) return
    if (useAppStore.getState().user) return
    autoLoginAttempted.current = true
    const delay = setTimeout(() => {
      if (useAppStore.getState().user) return
      loginRef.current(initData)
    }, 200)
    return () => clearTimeout(delay)
  }, [initData, screenParams.fromLogout])

  async function handleLogin() {
    if (!tg?.initData) {
      showToast({ type: 'error', title: tr('Потрібен Telegram'), subtitle: tr('Відкрийте додаток через Telegram Mini App') })
      return
    }
    await loginViaTelegram(tg.initData)
  }

  async function handleDiag() {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    if (!supabaseUrl) {
      showToast({ type: 'error', title: tr('NEXT_PUBLIC_SUPABASE_URL не вказано'), subtitle: tr('Перевірте налаштування Vercel') })
      return
    }
    setDiagLoading(true)
    try {
      // БЕЗ заголовків — і це не прибирання зайвого, а умова досяжності.
      // `Authorization`/`apikey` не входять у CORS-safelist, тож із ними
      // браузер спершу робить preflight, а він пінився на ALLOWED_ORIGIN —
      // тобто саме тоді, коли діагностика потрібна, до неї не доходило.
      // Функція задеплоєна з `--no-verify-jwt`, і воркфлоу секретів ходить
      // сюди голим curl, тож ключ їй не потрібен: без заголовків це простий
      // запит без preflight узагалі.
      const res = await fetch(`${supabaseUrl}/functions/v1/telegram-auth`, { method: 'GET' })
      const data = await res.json()
      // РОЗБІЖНІСТЬ ORIGIN — окрема гілка, бо решта прапорців каже «змінну
      // задано», а ця — «задано ПРАВИЛЬНО»: хибний ALLOWED_ORIGIN інакше
      // читався як здоровий (усі перевірки true, тост «Конфігурація OK»,
      // а вхід мертвий).
      //
      // ГЕЙТ НА `allowed_origin === true` ОБОВʼЯЗКОВИЙ. Коли змінної немає
      // ВЗАГАЛІ, `origin_match` теж `false` (null !== origin) — і без гейта
      // ця гілка виходила раніше за список відсутніх змінних, тобто ковтала
      // решту діагнозів. Гірше, текст був би неправдивий саме там:
      // `corsHeadersFor` при незаданій змінній відбиває Origin, тобто CORS
      // НЕ блокує, а POST падає з читабельним CONFIG_ERROR — незадану змінну
      // має називати список нижче, а не це повідомлення.
      if (data.checks?.allowed_origin === true && data.checks?.origin_match === false) {
        showToast({
          type: 'error',
          title: tr('ALLOWED_ORIGIN не збігається'),
          subtitle: tr('У Supabase задано {0}, а застосунок відкрито з {1}. Вхід блокує CORS, поки вони різні.',
            String(data.allowed_origin_value ?? '—'), window.location.origin),
        })
        return
      }
      if (data.ok) {
        showToast({ type: 'success', title: tr('Конфігурація OK'), subtitle: tr('Змінні, БД, токен бота і origin перевірені.') })
      } else {
        const ENV_VAR_NAMES: Record<string, string> = {
          allowed_origin: 'ALLOWED_ORIGIN',
          bot_token: 'TELEGRAM_BOT_TOKEN',
          supabase_url: 'SUPABASE_URL',
          service_key: 'SUPABASE_SERVICE_ROLE_KEY',
          anon_key: 'SUPABASE_ANON_KEY',
          db: tr('зʼєднання з БД'),
        }
        const checks = data.checks ?? {}
        // ВІДСУТНЄ і ХИБНЕ — різні діагнози, і змішувати їх не можна:
        // `bot_token_valid:false` означає, що змінна ЗАДАНА, просто Telegram
        // її не приймає. У списку «не налаштовано» вона читалась би як
        // порожня, а порада «додайте її» вела б у глухий кут — той самий
        // клас, через який цей прапорець узагалі зʼявився.
        const missing = (Object.entries(checks) as [string, boolean][])
          .filter(([k, v]) => !v && k in ENV_VAR_NAMES).map(([k]) => ENV_VAR_NAMES[k])
        const parts: string[] = []
        if (missing.length) parts.push(tr('Не налаштовано в Supabase → Edge Functions → Secrets: {0}', missing.join(', ')))
        if (checks.bot_token_valid === false) parts.push(tr('TELEGRAM_BOT_TOKEN задано, але Telegram його не приймає — перевірте значення.'))
        showToast({
          type: 'error',
          title: tr('Проблема конфігурації'),
          subtitle: parts.length ? parts.join(' ') : tr('Edge Function недоступна'),
        })
      }
    } catch {
      showToast({ type: 'error', title: tr('Edge Function недоступна'), subtitle: tr('Перевірте, що функцію задеплоєно у Supabase') })
    } finally {
      setDiagLoading(false)
    }
  }

  const greeting = tgUser?.first_name ? tr('Привіт, {0}!', tgUser.first_name) : tr('Привіт!')

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

        <div style={{ fontSize: 'var(--fs-t3)', fontWeight: 'var(--fw-bold)', color: 'var(--t1)', marginBottom: 8, textAlign: 'center', letterSpacing: '-.01em' }}>
          {tr('Авторизація')}
        </div>
        <div style={{
          fontSize: 'var(--fs-note)', color: 'var(--t3)', textAlign: 'center',
          padding: '0 40px', marginBottom: 28, lineHeight: 1.5,
          minHeight: 22, transition: 'opacity .3s ease',
        }}>
          {AUTH_STEPS()[stepIdx]}
        </div>

        {/* Animated dots */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 32 }}>
          {AUTH_STEPS().map((_, i) => (
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
            <div style={{ fontSize: 'var(--fs-foot)', color: 'var(--t3)', marginBottom: 16, lineHeight: 1.5 }}>
              {tr('Авторизація займає довше, ніж зазвичай.\nПеревірте підключення до інтернету.')}
            </div>
            <button
              onClick={handleLogin}
              style={{
                padding: '12px 32px', borderRadius: 'var(--r-pill)',
                background: 'var(--glass-2)', border: 'var(--bd)',
                color: 'var(--t1)', fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)',
                cursor: 'pointer', letterSpacing: '.01em',
              }}
            >
              {tr('Спробувати ще раз')}
            </button>
          </div>
        ) : (
          <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t4)', textAlign: 'center' }}>
            {tr('Не закривайте додаток')}
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

        <div className="heading" style={{ textAlign: 'center' }}>{greeting}<br />{tr('Я — Прокс')}</div>
        <div className="subtext" style={{ textAlign: 'center' }}>
          {tx('Твій AI-асистент для {0} у Telegram. Бази, обʼєкти, аналітика — все в одному місці.', <b>{tr('управління нерухомістю')}</b>)}
        </div>

        {/* Feature cards */}
        <div className="features-list">
          <div className="feature">
            <GlassTelegram size={32} />
            <div>
              <div className="feature-t">{tr('Вхід через Telegram')}</div>
              <div className="feature-s">{tr('Без паролів — миттєва авторизація')}</div>
            </div>
          </div>
          <div className="feature">
            <GlassShield size={32} />
            <div>
              <div className="feature-t">{tr('Безпека даних')}</div>
              <div className="feature-s">{tr('HMAC підпис, RLS, шифрування')}</div>
            </div>
          </div>
          <div className="feature">
            <GlassBolt size={32} />
            <div>
              <div className="feature-t">{tr('Швидкий старт')}</div>
              <div className="feature-s">{tr('Три кроки до першої бази')}</div>
            </div>
          </div>
        </div>

        {/* СТОЇТЬ ВИЩЕ ЗА РЯДОК ЗГОДИ, і це замір, а не смак: плаваюча «Увійти»
            (`position:fixed`) накривала нижні ~4px цієї кнопки на 360×740,
            щойно її зону дотику підняли до 46px (683.8 проти 680). Текст
            згоди сусідство зі скримом терпить, ДІЯ — ні.
            Клас, а не інлайновий стиль: зонди ключуються класом із фолбеком на
            тег, тож доти кнопка була безіменною і її 28px не бачив ніхто — той
            самий урок, що вже оплачений на «Пропустити →». Неактивність
            показує КОЛІР, а не `opacity`. */}
        <button className="diag-btn" onClick={handleDiag} disabled={diagLoading} aria-busy={diagLoading}>
          {diagLoading ? tr('Перевірка...') : <><IconAdjustments size={14} /> {tr('Діагностика підключення')}</>}
        </button>
        <div style={{ textAlign: 'center', fontSize: 'var(--fs-cap1)', color: 'var(--t3)', padding: '10px 28px 6px', lineHeight: 1.5 }}>
          {tx('Натискаючи «Увійти», ви погоджуєтесь з {0} та {1}',
            <a href="/terms/" target="_blank" rel="noopener noreferrer" className="legal-a">{tr('Умовами використання')}</a>,
            <a href="/privacy/" target="_blank" rel="noopener noreferrer" className="legal-a">{tr('Політикою конфіденційності')}</a>)}
        </div>
      </div>

      {/* CTA — always visible at bottom */}
      <button className="mbtn" onClick={handleLogin}>
        <IconTelegram size={18} />
        {tr('Увійти через Telegram')}
      </button>
    </div>
  )
}
