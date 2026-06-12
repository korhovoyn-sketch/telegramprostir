'use client'

import { useEffect, useState, useMemo, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import { FreshnessBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import CoachMark from '@/components/ui/CoachMark'
import { useOnboarding } from '@/hooks/useOnboarding'
import { IconBell, IconChevronRight, IconPlus, GlassDbIcon } from '@/components/Icons'
import { DB_TYPE_LABELS, formatPrice, STATUS_COLORS, STATUS_LABELS } from '@/lib/utils'
import type { PropertyStatus } from '@/types'

interface PropSearchResult {
  id: string
  name: string
  status: PropertyStatus
  db_id: string
  dbName: string
  floor?: string | null
}

export default function DatabaseListScreen() {
  const { user, navigate, unreadCount } = useAppStore()
  const { databases, loading, error, loadDatabases } = useDatabases()
  const [search, setSearch] = useState('')

  // Cross-database property search
  const [propResults, setPropResults]     = useState<PropSearchResult[]>([])
  const [propSearching, setPropSearching] = useState(false)

  useEffect(() => { loadDatabases() }, [loadDatabases])

  // Debounced cross-db property search when query ≥ 3 chars
  useEffect(() => {
    if (search.length < 3 || !user) { setPropResults([]); return }
    setPropSearching(true)
    const timer = setTimeout(async () => {
      try {
        const { data } = await supabase
          .from('properties')
          .select('id, name, status, db_id, floor')
          .eq('owner_id', user.id)
          .ilike('name', `%${search}%`)
          .limit(20)
        setPropResults(
          (data ?? []).map(p => ({
            id:     p.id,
            name:   p.name,
            status: p.status as PropertyStatus,
            db_id:  p.db_id,
            floor:  p.floor,
            dbName: databases.find(d => d.id === p.db_id)?.name ?? '—',
          }))
        )
      } finally {
        setPropSearching(false)
      }
    }, 320)
    return () => clearTimeout(timer)
  }, [search, user, databases])

  const filtered = useMemo(() =>
    databases.filter(db =>
      (db.name ?? '').toLowerCase().includes(search.toLowerCase()) ||
      (db.address ?? '').toLowerCase().includes(search.toLowerCase())
    ),
  [databases, search])

  const fabRef = useRef<HTMLButtonElement>(null)
  const { isDone: fabSeen, markDone: markFabSeen } = useOnboarding('owner-fab')

  const totals = useMemo(() => ({
    dbs:      databases.length,
    props:    databases.reduce((s, d) => s + (d._property_count  ?? 0), 0),
    free:     databases.reduce((s, d) => s + (d._free_count      ?? 0), 0),
    occupied: databases.reduce((s, d) => s + (d._occupied_count  ?? 0), 0),
    income:   databases.reduce((s, d) => s + (d._monthly_income  ?? 0), 0),
  }), [databases])

  const hour  = new Date().getHours()
  const greet = hour < 12 ? 'Доброго ранку' : hour < 17 ? 'Добрий день' : 'Добрий вечір'
  const showPropResults = search.length >= 3

  return (
    <div className="scr bg-purple">
      {/* Header */}
      <div className="hdr">
        <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg,#7AB3FF,#A87CFF)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 15, color: 'var(--t1)', border: 'var(--bd)', flexShrink: 0 }}>
          {(user?.first_name ?? 'U').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 16, fontWeight: 700 }}>prostir</div>
        </div>
        <button className="hdr-a" aria-label="Сповіщення" onClick={() => navigate('notifications')} style={{ background: 'none', border: 'var(--bd)', position: 'relative' }}>
          <IconBell size={16} />
          {unreadCount > 0 && <span className="hdr-a-dot" />}
        </button>
      </div>

      <div className="body has-fab">
        <div className="greet">{greet}, {user?.first_name}</div>
        <div className="display">Мої бази</div>

        {/* Stats */}
        <div className="stat-g">
          <div className="stat glass-s">
            <div className="stat-n">{totals.dbs}</div>
            <div className="stat-l">Баз</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{totals.props}</div>
            <div className="stat-l">Об&apos;єктів</div>
          </div>
          <div className="stat glass-s" style={{ background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)' }}>
            <div className="stat-n" style={{ color: 'var(--ok-fg)' }}>{totals.free}</div>
            <div className="stat-l" style={{ color: 'var(--ok-fg)' }}>Вільно</div>
          </div>
          {totals.income > 0 && (
            <div className="stat glass-s" style={{ gridColumn: '1 / -1', background: 'rgba(52,199,89,.07)', border: '.5px solid rgba(52,199,89,.18)' }}>
              <div className="stat-n" style={{ color: '#34c759', fontSize: 18 }}>
                {formatPrice(totals.income, user?.currency)}
              </div>
              <div className="stat-l">на місяць (зайнято {totals.occupied})</div>
            </div>
          )}
        </div>

        {/* Search */}
        <SearchBar value={search} onChange={setSearch} placeholder="Пошук бази або об'єкту..." />

        {/* Cross-database property search results */}
        {showPropResults && (
          <div style={{ marginBottom: 8 }}>
            <div className="over">
              <span>Об&apos;єкти по всіх базах</span>
              {propSearching
                ? <span className="over-a">…</span>
                : <span className="over-a">{propResults.length} знайдено</span>
              }
            </div>
            {propSearching ? (
              <div style={{ padding: '8px 16px' }}>
                <div className="skel" style={{ height: 44, borderRadius: 10 }} />
              </div>
            ) : propResults.length === 0 ? (
              <div style={{ padding: '8px 16px', fontSize: 13, color: 'var(--t3)' }}>Нічого не знайдено</div>
            ) : (
              <div className="list">
                {propResults.map(p => {
                  const badge = STATUS_COLORS[p.status]
                  return (
                    <div
                      key={p.id}
                      className="row glass-s"
                      onClick={() => navigate('property-detail', { propertyId: p.id, dbId: p.db_id })}
                    >
                      <div className="row-mn">
                        <div className="row-t">{p.name}</div>
                        <div className="row-s">
                          <span style={{ color: 'var(--t3)' }}>{p.dbName}</span>
                          {p.floor && <><span>·</span><span>{p.floor} пов.</span></>}
                        </div>
                      </div>
                      <div className="row-r">
                        <span className="bdg" style={{ background: badge.bg, color: badge.color }}>{STATUS_LABELS[p.status]}</span>
                      </div>
                      <IconChevronRight size={14} color="var(--t4)" />
                    </div>
                  )
                })}
              </div>
            )}
            {/* Divider before DB results */}
            {filtered.length > 0 && (
              <div className="over" style={{ marginTop: 4 }}><span>Бази</span></div>
            )}
          </div>
        )}

        {/* Databases list */}
        {loading ? (
          <SkeletonLoader />
        ) : error && databases.length === 0 ? (
          <div className="retry-wrap">
            <div className="retry-ic">📡</div>
            <div className="retry-h">Не вдалося завантажити</div>
            <div className="retry-s">{error}</div>
            <button className="retry-btn" onClick={loadDatabases}>Спробувати ще раз</button>
          </div>
        ) : !showPropResults && filtered.length === 0 && search ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🔍</div>
            <div className="empty-h">Нічого не знайдено</div>
            <div className="empty-s">Немає баз за запитом &quot;{search}&quot;</div>
          </div>
        ) : filtered.length === 0 && !showPropResults ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Немає баз</div>
            <div className="empty-s">Створи першу базу об&apos;єктів</div>
            <button
              className="mbtn success"
              style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', marginTop: 24, width: 'auto', minWidth: 200 }}
              onClick={() => navigate('create-db')}
            >
              Створити першу базу
            </button>
          </div>
        ) : filtered.length > 0 ? (
          <div className="list">
            {filtered.map(db => (
              <div
                key={db.id}
                className="row glass-s"
                onClick={() => navigate('db-objects', { dbId: db.id })}
              >
                <GlassDbIcon type={db.type} color={db.color} size={32} />
                <div className="row-mn">
                  <div className="row-t">{db.name}</div>
                  <div className="row-s">
                    <FreshnessBadge updatedAt={db.updated_at} />
                    <span>·</span>
                    <span>{DB_TYPE_LABELS[db.type]}</span>
                    {db.address && <><span>·</span><span>{db.address}</span></>}
                  </div>
                  {(db._monthly_income ?? 0) > 0 && (
                    <div style={{ fontSize: 11, color: '#34c759', marginTop: 2, fontWeight: 600 }}>
                      {formatPrice(db._monthly_income!, user?.currency)}/міс
                    </div>
                  )}
                </div>
                <div className="row-r">
                  <span className="bdg bdg-info">{db._property_count ?? 0} об.</span>
                  {(db._free_count ?? 0) > 0 && (
                    <span className="bdg bdg-ok">{db._free_count} вільно</span>
                  )}
                </div>
                <IconChevronRight size={14} color="var(--t4)" />
              </div>
            ))}
          </div>
        ) : null}

        {/* CTA */}
        <div className="cta" onClick={() => navigate('create-db')}>
          <IconPlus size={16} />
          Створити нову базу
        </div>
      </div>

      <button
        ref={fabRef}
        className="fab"
        aria-label="Створити базу"
        onClick={() => navigate('create-db')}
      >
        <IconPlus size={20} />
      </button>

      {!fabSeen && !loading && (
        <CoachMark
          title="Створіть першу базу"
          body="Натисніть +, щоб додати базу нерухомості — офісний центр, житловий комплекс або склад."
          targetRef={fabRef}
          placement="above"
          onDone={markFabSeen}
        />
      )}

      <TabBar />
    </div>
  )
}
