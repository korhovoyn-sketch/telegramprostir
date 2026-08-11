'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconKey, IconBuilding, IconChevronRight } from '@/components/Icons'
import { StatusBadge } from '@/components/ui/Badge'
import { greeting, humanizeDbError } from '@/lib/utils'
import type { GuestLink } from '@/types'

export default function GuestHomeScreen() {
  const { user, navigate } = useAppStore()
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
      setLoadError(humanizeDbError(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  const greet = greeting()

  return (
    <div className="scr bg-teal">
      <div className="hdr">
        <div className="hdr-av av-grad-guest">
          {(user?.first_name ?? 'G').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 'var(--fs-call)', fontWeight: 'var(--fw-bold)' }}>prostir</div>
        </div>
        {/* Notifications live in the tab bar (with unread badge) — a header
            bell here duplicated that tab and confused users. */}
        <div className="hdr-sp" />
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
          <SkeletonLoader rowHeight={69} />
        ) : loadError ? (
          <RetryState subtitle={loadError} onRetry={load} />
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
                  <div style={{ width: 40, height: 40, borderRadius: 'var(--r-sm)', background: isProperty ? 'rgba(74,222,128,.15)' : 'var(--info-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    {isProperty
                      ? <IconKey size={18} color="#4ade80" />
                      : <IconBuilding size={18} color="var(--info)" />}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--fs-sub)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {name}
                    </div>
                    {link.label && (
                      <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {link.label}
                      </div>
                    )}
                    {status && <div style={{ marginTop: 4 }}><StatusBadge status={status} /></div>}
                    {!isProperty && (
                      <div style={{ fontSize: 'var(--fs-cap1)', color: 'var(--t3)', marginTop: 2 }}>База об&apos;єктів</div>
                    )}
                  </div>
                  <IconChevronRight size={12} color="var(--t4)" />
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
