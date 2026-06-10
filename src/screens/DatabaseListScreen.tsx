'use client'

import { useEffect, useState, useMemo, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import { FreshnessBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import CoachMark from '@/components/ui/CoachMark'
import { useOnboarding } from '@/hooks/useOnboarding'
import { IconBell, IconChevronRight, IconPlus } from '@/components/Icons'
import { DB_COLORS, DB_TYPE_LABELS, DB_TYPE_EMOJI } from '@/lib/utils'

export default function DatabaseListScreen() {
  const { user, navigate, unreadCount } = useAppStore()
  const { databases, loading, error, loadDatabases } = useDatabases()
  const [search, setSearch] = useState('')

  useEffect(() => {
    loadDatabases()
  }, [loadDatabases])

  const filtered = useMemo(() =>
    databases.filter((db) =>
      (db.name ?? '').toLowerCase().includes(search.toLowerCase()) ||
      (db.address ?? '').toLowerCase().includes(search.toLowerCase())
    ),
  [databases, search])

  const fabRef = useRef<HTMLButtonElement>(null)
  const { isDone: fabSeen, markDone: markFabSeen } = useOnboarding('owner-fab')

  const { totalProps, freeProps } = useMemo(() => ({
    totalProps: databases.reduce((s, d) => s + (d._property_count ?? 0), 0),
    freeProps: databases.reduce((s, d) => s + (d._free_count ?? 0), 0),
  }), [databases])

  const hour = new Date().getHours()
  const greet = hour < 12 ? 'Доброго ранку' : hour < 17 ? 'Добрий день' : 'Добрий вечір'

  return (
    <div className="scr bg-purple">
      {/* Header */}
      <div className="hdr">
        <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg,#7AB3FF,#A87CFF)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 15, color: 'var(--t1)', border: 'var(--bd)', flexShrink: 0 }}>
          {(user?.first_name ?? 'U').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 16, fontWeight: 700 }}>PropSpace</div>
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
            <div className="stat-n">{databases.length}</div>
            <div className="stat-l">Баз</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{totalProps}</div>
            <div className="stat-l">Об&apos;єктів</div>
          </div>
          <div className="stat glass-s" style={{ background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)' }}>
            <div className="stat-n" style={{ color: 'var(--ok-fg)' }}>{freeProps}</div>
            <div className="stat-l" style={{ color: 'var(--ok-fg)' }}>Вільно</div>
          </div>
        </div>

        {/* Search */}
        <SearchBar value={search} onChange={setSearch} placeholder="Пошук бази..." />

        {/* List */}
        {loading ? (
          <SkeletonLoader />
        ) : error && databases.length === 0 ? (
          <div className="retry-wrap">
            <div className="retry-ic">📡</div>
            <div className="retry-h">Не вдалося завантажити</div>
            <div className="retry-s">{error}</div>
            <button className="retry-btn" onClick={loadDatabases}>Спробувати ще раз</button>
          </div>
        ) : filtered.length === 0 && search ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-ic">🔍</div>
            <div className="empty-h">Нічого не знайдено</div>
            <div className="empty-s">Немає баз за запитом &quot;{search}&quot;</div>
          </div>
        ) : filtered.length === 0 ? (
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
        ) : (
          <div className="list">
            {filtered.map((db) => {
              const colorStyle = { background: DB_COLORS[db.color] ?? DB_COLORS.purple }
              return (
                <div
                  key={db.id}
                  className="row glass-s"
                  onClick={() => navigate('db-objects', { dbId: db.id })}
                >
                  <div className="row-ic" style={colorStyle}>
                    <span style={{ fontSize: 18 }}>{DB_TYPE_EMOJI[db.type] ?? '🏢'}</span>
                  </div>
                  <div className="row-mn">
                    <div className="row-t">{db.name}</div>
                    <div className="row-s">
                      <FreshnessBadge updatedAt={db.updated_at} />
                      <span>·</span>
                      <span>{DB_TYPE_LABELS[db.type]}</span>
                      {db.address && <><span>·</span><span>{db.address}</span></>}
                    </div>
                  </div>
                  <div className="row-r">
                    <span className="bdg bdg-info">{db._property_count ?? 0} об.</span>
                    {(db._free_count ?? 0) > 0 && (
                      <span className="bdg bdg-ok">{db._free_count} вільно</span>
                    )}
                  </div>
                  <IconChevronRight size={14} color="var(--t4)" />
                </div>
              )
            })}
          </div>
        )}

        {/* CTA create */}
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
