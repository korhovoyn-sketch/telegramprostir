'use client'

import { useAppStore } from '@/store/appStore'
import ProxMascot from '@/components/ProxMascot'
import { GlassDbIcon, GlassPhoto, GlassShare } from '@/components/Icons'
import { tx } from '@/lib/tx'
import { tr } from '@/lib/i18n'

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

            <div className="empty-h">{tr('Ще немає підписок')}</div>
            <div className="empty-s">
              {tx('Відскануй QR-код від власника,{0}щоб отримати доступ до бази', <br />)}
            </div>

            <button className="mbtn mbtn-flow" onClick={() => navigate('qr-scanner')} style={{ width: '80%' }}>
              {tr('Сканувати QR')}
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

        <div className="heading">{tr('Немає жодної бази')}</div>
        <div className="subtext">
          {tr('Створи першу базу обʼєктів нерухомості — це займе менше хвилини')}
        </div>

        {/* Tips */}
        <div className="features-list" style={{ width: '100%' }}>
          <div className="feature">
            <GlassDbIcon type="business_center" color="blue" size={32} />
            <div>
              <div className="feature-t">{tr('1. Назви базу')}</div>
              <div className="feature-s">{tr('Наприклад "БЦ Олімп" або "ЖК Перемоги"')}</div>
            </div>
          </div>
          <div className="feature">
            <GlassPhoto size={32} />
            <div>
              <div className="feature-t">{tr('2. Додай обʼєкти')}</div>
              <div className="feature-s">{tr('Офіси, квартири, магазини з фото і ціною')}</div>
            </div>
          </div>
          <div className="feature">
            <GlassShare size={32} />
            <div>
              <div className="feature-t">{tr('3. Поділись QR')}</div>
              <div className="feature-s">{tr('Ріелтори отримають доступ миттєво')}</div>
            </div>
          </div>
        </div>
      </div>

      <button
        className="mbtn success"
        onClick={() => navigate('create-db')}
      >
        {tr('Створити першу базу')}
      </button>
    </div>
  )
}
