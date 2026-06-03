'use client'

import { useEffect, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import { FreshnessBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconBell, IconChevronRight } from '@/components/Icons'
import { DB_TYPE_LABELS, DB_COLORS, DB_TYPE_EMOJI } from '@/lib/utils'
import type { Database, RealtorSubscription } from '@/types'

export default function RealtorDashboardScreen() {
  const { user, navigate, unreadCount, showToast } = useAppStore()
  const [subscriptions, setSubscriptions] = useState<RealtorSubscription[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [propertyCount, setPropertyCount] = useState<number>(0)

  async function load() {
    if (!user) return
    setLoading(true)
    setLoadError(null)
    try {
      const { data, error } = await supabase
        .from('realtor_subscriptions')
        .select('*, database:databases(*)')
        .eq('realtor_id', user.id)
        .order('created_at', { ascending: false })
      if (error) throw error
      setSubscriptions((data ?? []) as RealtorSubscription[])

      // Load real property count across all subscribed databases
      const dbIds = (data ?? []).map((s) => (s as RealtorSubscription & { database?: { id: string } }).database?.id).filter((id): id is string => Boolean(id))
      if (dbIds.length > 0) {
        const { count } = await supabase
          .from('properties')
          .select('id', { count: 'exact', head: true })
          .in('db_id', dbIds)
        setPropertyCount(count ?? 0)
      }
    } catch (e) {
      const msg = (e as Error).message
      setLoadError(msg)
      showToast({ type: 'error', title: 'Помилка завантаження', subtitle: msg })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  const filtered = subscriptions.filter((s) =>
    s.database?.name.toLowerCase().includes(search.toLowerCase()) ?? false
  )

  const hour = new Date().getHours()
  const greet = hour < 12 ? 'Доброго ранку' : hour < 17 ? 'Добрий день' : 'Добрий вечір'

  return (
    <div className="scr bg-cyan">
      <div className="hdr">
        <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg,#FF7AB8,#C42378)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 15, color: '#fff', border: 'var(--bd)', flexShrink: 0 }}>
          {(user?.first_name ?? 'R').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 16, fontWeight: 700 }}>PropSpace</div>
        </div>
        <button className="hdr-a" onClick={() => navigate('notifications')} style={{ background: 'none', border: 'var(--bd)', position: 'relative' }}>
          <IconBell size={16} />
          {unreadCount > 0 && <span className="hdr-a-dot" />}
        </button>
      </div>

      <div className="body has-tabbar-btn">
        <div className="greet">{greet}, {user?.first_name}</div>
        <div className="display">Робочі бази</div>

        <div className="stat-g">
          <div className="stat glass-s">
            <div className="stat-n">{subscriptions.length}</div>
            <div className="stat-l">Власників</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{propertyCount}</div>
            <div className="stat-l">Об&apos;єктів</div>
          </div>
          <div className="stat glass-s" style={{ background: 'rgba(255,80,180,.18)', border: '.5px solid rgba(255,80,180,.28)' }}>
            {/* Favorites count not yet implemented */}
            <div className="stat-n" style={{ color: '#ffb8e0' }}>-</div>
            <div className="stat-l" style={{ color: '#ffb8e0' }}>Обраних</div>
          </div>
        </div>

        <SearchBar value={search} onChange={setSearch} placeholder="Пошук бази..." />

        {loading ? (
          <SkeletonLoader />
        ) : loadError && subscriptions.length === 0 ? (
          <div className="retry-wrap">
            <div className="retry-ic">📡</div>
            <div className="retry-h">Не вдалося завантажити</div>
            <div className="retry-s">{loadError}</div>
            <button className="retry-btn" onClick={load}>Спробувати ще раз</button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">
              {search ? 'Нічого не знайдено' : 'Немає підписок'}
            </div>
            <div className="empty-s">
              {search ? 'Немає баз за запитом' : 'Відскануй QR від власника'}
            </div>
          </div>
        ) : (
          <div className="list">
            {filtered.map((sub) => {
              const db = sub.database as Database
              if (!db) return null
              return (
                <div
                  key={sub.id}
                  className="row glass-s"
                  onClick={() => navigate('realtor-database', { dbId: db.id })}
                >
                  <div className="row-ic" style={{ background: DB_COLORS[db.color] ?? DB_COLORS.purple }}>
                    {DB_TYPE_EMOJI[db.type] ?? '🏢'}
                  </div>
                  <div className="row-mn">
                    <div className="row-t">{db.name}</div>
                    <div className="row-s">
                      <FreshnessBadge updatedAt={db.updated_at} />
                      <span>·</span>
                      <span>{DB_TYPE_LABELS[db.type]}</span>
                    </div>
                  </div>
                  <IconChevronRight size={14} color="var(--t4)" />
                </div>
              )
            })}
          </div>
        )}

      </div>

      <button className="mbtn" onClick={() => navigate('qr-scanner')} style={{ bottom: 'calc(78px + var(--safe-bottom))' }}>
        Додати базу за QR
      </button>

      <TabBar />
    </div>
  )
}
