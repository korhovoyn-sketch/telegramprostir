'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconBell, IconKey, IconBuilding } from '@/components/Icons'
import { StatusBadge } from '@/components/ui/Badge'
import type { GuestLink } from '@/types'

export default function GuestHomeScreen() {
  const { user, navigate, unreadCount } = useAppStore()
  const [links, setLinks] = useState<GuestLink[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  async function load() {
    if (!user) return
    setLoading(true)
    setLoadError(null)
    try {
      const { data, error } = await supabase
        .from('guest_links')
        .select('*, property:properties(*), database:databases(*)')
        .eq('guest_user_id', user.id)
        .eq('status', 'active')
        .order('claimed_at', { ascending: false })
      if (error) throw error
      setLinks((data ?? []) as GuestLink[])
    } catch (e) {
      setLoadError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  const hour = new Date().getHours()
  const greet = hour < 12 ? 'Доброго ранку' : hour < 17 ? 'Добрий день' : 'Добрий вечір'

  return (
    <div className="scr bg-teal">
      <div className="hdr">
        <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg,#4ade80,#16a34a)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 15, color: '#fff', border: 'var(--bd)', flexShrink: 0 }}>
          {(user?.first_name ?? 'G').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 16, fontWeight: 700 }}>prostir</div>
        </div>
        <button
          className="hdr-a"
          aria-label="Сповіщення"
          onClick={() => navigate('notifications')}
          style={{ background: 'none', border: 'var(--bd)', position: 'relative' }}
        >
          <IconBell size={16} />
          {unreadCount > 0 && <span className="hdr-a-dot" />}
        </button>
      </div>

      <div className="body has-tabbar">
        <div className="greet">{greet}, {user?.first_name}</div>
        <div className="display">Мої об&apos;єкти</div>

        <div className="stat-g" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <div className="stat glass-s">
            <div className="stat-n">{links.length}</div>
            <div className="stat-l">Доступів</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{links.filter(l => l.property_id).length}</div>
            <div className="stat-l">Об&apos;єктів</div>
          </div>
        </div>

        {loading ? (
          <SkeletonLoader />
        ) : loadError ? (
          <div className="retry-wrap">
            <div className="retry-ic">📡</div>
            <div className="retry-h">Не вдалося завантажити</div>
            <div className="retry-s">{loadError}</div>
            <button className="retry-btn" onClick={load}>Спробувати ще раз</button>
          </div>
        ) : links.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏠</div>
            <div className="empty-h">Немає доступних об&apos;єктів</div>
            <div className="empty-s">Власник надішле вам запрошення-посилання</div>
          </div>
        ) : (
          <div>
            {links.map((link) => {
              const isProperty = !!link.property_id
              const name = isProperty
                ? (link.property?.name ?? 'Об\'єкт')
                : (link.database?.name ?? 'База')
              const status = isProperty ? (link.property?.status ?? null) : null

              return (
                <div
                  key={link.id}
                  className="glass-s"
                  style={{ margin: '0 12px 10px', borderRadius: 'var(--r-md)', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}
                  onClick={() => {
                    if (isProperty) {
                      navigate('property-detail', { propertyId: link.property_id!, dbId: link.property?.db_id })
                    } else {
                      navigate('db-objects', { dbId: link.db_id! })
                    }
                  }}
                >
                  <div style={{ width: 40, height: 40, borderRadius: 'var(--r-sm)', background: isProperty ? 'rgba(74,222,128,.15)' : 'rgba(122,179,255,.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    {isProperty
                      ? <IconKey size={18} color="#4ade80" />
                      : <IconBuilding size={18} color="#7AB3FF" />}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {name}
                    </div>
                    {link.label && (
                      <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {link.label}
                      </div>
                    )}
                    {status && <div style={{ marginTop: 4 }}><StatusBadge status={status} /></div>}
                    {!isProperty && (
                      <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 2 }}>База об&apos;єктів</div>
                    )}
                  </div>
                  <svg width="7" height="12" viewBox="0 0 7 12" fill="none">
                    <path d="M1 1l5 5-5 5" stroke="rgba(255,255,255,.3)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
              )
            })}
          </div>
        )}

        <div style={{ height: 100 }} />
      </div>

      <TabBar />
    </div>
  )
}
