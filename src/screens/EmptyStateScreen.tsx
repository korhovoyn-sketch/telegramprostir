'use client'

import { useAppStore } from '@/store/appStore'
import ProxMascot from '@/components/ProxMascot'
import { GlassDbIcon, GlassPhoto, GlassShare } from '@/components/Icons'

export default function EmptyStateScreen() {
  const { navigate, user } = useAppStore()
  const isRealtor = user?.role === 'realtor'

  if (isRealtor) {
    return (
      <div className="scr bg-empty">
        {/* Scroll-safe: empty-state centers via margin:auto, scrolls if it overflows */}
        <div className="body" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="empty-state" style={{ margin: 'auto' }}>
            <div className="sticker-wrap" style={{ height: 160 }}>
              <div className="glow-orb" style={{ background: 'radial-gradient(circle,rgba(120,80,255,.4),transparent 70%)' }} />
              <div className="sticker">
                <ProxMascot mood="happy" size={130} />
              </div>
            </div>

            <div className="empty-h">Ще немає підписок</div>
            <div className="empty-s">
              Відскануй QR-код від власника,<br />щоб отримати доступ до бази
            </div>

            <button className="mbtn" onClick={() => navigate('qr-scanner')} style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', width: '80%', marginTop: 8 }}>
              Сканувати QR
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="scr bg-empty">
      {/* Scrollable content; the create button stays pinned at the bottom (position:absolute) */}
      <div className="body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingBottom: 'calc(var(--btn-h) + 40px + var(--safe-bottom))' }}>
        <div className="sticker-wrap">
          <div className="shimmer-ring" />
          <div className="glow-orb" style={{ background: 'radial-gradient(circle,rgba(122,179,255,.4),transparent 70%)' }} />
          <div className="sticker">
            <ProxMascot mood="happy" size={130} />
          </div>
        </div>

        <div className="heading">Немає жодної бази</div>
        <div className="subtext">
          Створи першу базу об&apos;єктів нерухомості — це займе менше хвилини
        </div>

        {/* Tips */}
        <div className="features-list" style={{ width: '100%' }}>
          <div className="feature">
            <GlassDbIcon type="business_center" color="blue" size={32} />
            <div>
              <div className="feature-t">1. Назви базу</div>
              <div className="feature-s">Наприклад &quot;БЦ Олімп&quot; або &quot;ЖК Перемоги&quot;</div>
            </div>
          </div>
          <div className="feature">
            <GlassPhoto size={32} />
            <div>
              <div className="feature-t">2. Додай об&apos;єкти</div>
              <div className="feature-s">Офіси, квартири, магазини з фото і ціною</div>
            </div>
          </div>
          <div className="feature">
            <GlassShare size={32} />
            <div>
              <div className="feature-t">3. Поділись QR</div>
              <div className="feature-s">Ріелтори отримають доступ миттєво</div>
            </div>
          </div>
        </div>
      </div>

      <button
        className="mbtn success"
        onClick={() => navigate('create-db')}
      >
        Створити першу базу
      </button>
    </div>
  )
}
