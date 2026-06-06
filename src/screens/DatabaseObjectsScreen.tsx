'use client'

import { useEffect, useState, useMemo } from 'react'
import { useAppStore } from '@/store/appStore'
import { useDatabases } from '@/hooks/useDatabases'
import { useProperties } from '@/hooks/useProperties'
import Header from '@/components/ui/Header'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import { StatusBadge, FreshnessBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import Modal from '@/components/ui/Modal'
import { IconPlus, IconDots, IconEye, IconPhoto, IconShare, IconChevronUp, IconChevronDown } from '@/components/Icons'
import { formatPrice, calcRent, calcUtilities, DB_TYPE_LABELS, DB_TYPE_EMOJI, formatLeasePeriod } from '@/lib/utils'
import type { PropertyStatus } from '@/types'

export default function DatabaseObjectsScreen() {
  const { screenParams, navigate, databases, user } = useAppStore()
  const { deleteDatabase } = useDatabases()
  const { properties, loading, error, loadProperties, reorderProperty, batchDeleteProperties, batchUpdateStatus } = useProperties(screenParams.dbId)

  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'all' | PropertyStatus>('all')
  const [showMenu, setShowMenu] = useState(false)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [reorderMode, setReorderMode] = useState(false)
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showBatchDeleteModal, setShowBatchDeleteModal] = useState(false)

  function enterReorderMode() {
    setShowMenu(false)
    setSearch('')
    setTab('all')
    setSelectMode(false)
    setSelectedIds(new Set())
    setReorderMode(true)
  }

  function enterSelectMode() {
    setShowMenu(false)
    setReorderMode(false)
    setSelectMode(true)
  }

  function exitSelectMode() {
    setSelectMode(false)
    setSelectedIds(new Set())
  }

  function toggleSelect(id: string) {
    window.Telegram?.WebApp?.HapticFeedback?.selectionChanged()
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleBatchDelete() {
    setShowBatchDeleteModal(false)
    await batchDeleteProperties([...selectedIds])
    exitSelectMode()
  }

  async function handleBatchStatus(status: PropertyStatus) {
    await batchUpdateStatus([...selectedIds], status)
    exitSelectMode()
  }

  const db = databases.find((d) => d.id === screenParams.dbId)

  useEffect(() => {
    if (screenParams.dbId) loadProperties(screenParams.dbId)
  }, [screenParams.dbId, loadProperties])

  const filtered = useMemo(() =>
    properties.filter((p) => {
      const matchSearch = p.name.toLowerCase().includes(search.toLowerCase())
      const matchTab = tab === 'all' || p.status === tab
      return matchSearch && matchTab
    }),
  [properties, search, tab])

  const counts = useMemo(() => ({
    all: properties.length,
    free: properties.filter(p => p.status === 'free').length,
    occupied: properties.filter(p => p.status === 'occupied').length,
    for_sale: properties.filter(p => p.status === 'for_sale').length,
  }), [properties])

  if (!db) return (
    <div className="scr bg-blue">
      <div className="loader-wrap" style={{ paddingTop: 80 }}><div className="loader" /></div>
    </div>
  )

  return (
    <div className="scr bg-blue">
      <Header
        title={db.name}
        subtitle={DB_TYPE_LABELS[db.type]}
        backLabel="Бази"
        right={
          reorderMode ? (
            <button className="hdr-a" onClick={() => setReorderMode(false)} style={{ background: 'rgba(34,199,89,.18)', border: 'none', color: '#22c759', fontWeight: 600, fontSize: 13 }}>
              Готово
            </button>
          ) : selectMode ? (
            <button className="hdr-a" onClick={exitSelectMode} style={{ background: 'none', border: 'var(--bd)', fontSize: 13 }}>
              Скасувати
            </button>
          ) : (
            <button className="hdr-a" aria-label="Меню бази" onClick={() => setShowMenu(true)} style={{ background: 'none', border: 'var(--bd)' }}>
              <IconDots size={16} />
            </button>
          )
        }
      />

      <div className="body has-fab">
        {/* DB info card */}
        <div className="info-card glass-s" style={{ margin: '0 12px 12px' }}>
          <div className="info-ic">{DB_TYPE_EMOJI[db.type] ?? '🏢'}</div>
          <div className="info-mn">
            <div className="info-t">{db.name}</div>
            <div className="info-s">
              <FreshnessBadge updatedAt={db.updated_at} />
              <span>·</span>
              <span>{properties.length} об&apos;єктів</span>
              <span>·</span>
              <span>{counts.free} вільно</span>
            </div>
          </div>
          <button
            className="info-act"
            aria-label="Аналітика та поширення"
            onClick={() => navigate('sharing-analytics', { dbId: db.id })}
          >
            <IconShare size={14} />
          </button>
        </div>

        {/* Segment tabs — hidden while reordering */}
        {!reorderMode && (
          <div className="seg">
            {([
              { id: 'all', label: `Всі (${counts.all})` },
              { id: 'free', label: `Вільно (${counts.free})` },
              { id: 'occupied', label: `Зайнято (${counts.occupied})` },
              { id: 'for_sale', label: `Продаж (${counts.for_sale})` },
            ] as const).map((t) => (
              <div
                key={t.id}
                className={`seg-b ${tab === t.id ? 'on' : ''}`}
                onClick={() => { window.Telegram?.WebApp?.HapticFeedback?.selectionChanged(); setTab(t.id) }}
              >
                {t.label}
              </div>
            ))}
          </div>
        )}

        {/* Search — hidden while reordering */}
        {!reorderMode && (
          <SearchBar value={search} onChange={setSearch} placeholder="Пошук об&apos;єкту..." />
        )}

        {/* Mode hints */}
        {reorderMode && (
          <div style={{ padding: '8px 16px', fontSize: 12, color: 'var(--t3)', textAlign: 'center' }}>
            Натисніть ↑ або ↓ щоб змінити позицію об&apos;єкта
          </div>
        )}
        {selectMode && (
          <div style={{ padding: '6px 16px', fontSize: 12, color: 'var(--t3)', textAlign: 'center', display: 'flex', justifyContent: 'center', gap: 12 }}>
            <span>Оберіть об&apos;єкти для дії</span>
            {filtered.length > 0 && (
              <button
                onClick={() => {
                  const allSelected = filtered.every(p => selectedIds.has(p.id))
                  if (allSelected) setSelectedIds(new Set())
                  else setSelectedIds(new Set(filtered.map(p => p.id)))
                }}
                style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: 12, cursor: 'pointer', padding: 0 }}
              >
                {filtered.every(p => selectedIds.has(p.id)) ? 'Зняти все' : 'Вибрати все'}
              </button>
            )}
          </div>
        )}

        {/* Property cards */}
        {loading ? (
          <SkeletonLoader />
        ) : error && properties.length === 0 ? (
          <div className="retry-wrap">
            <div className="retry-ic">📡</div>
            <div className="retry-h">Не вдалося завантажити</div>
            <div className="retry-s">{error}</div>
            <button className="retry-btn" onClick={() => loadProperties(screenParams.dbId)}>Спробувати ще раз</button>
          </div>
        ) : filtered.length === 0 && properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Немає об&apos;єктів</div>
            <div className="empty-s">Натисни + щоб додати перший об&apos;єкт</div>
            <button
              className="mbtn success"
              style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', marginTop: 24, width: 'auto', minWidth: 200 }}
              onClick={() => navigate('property-form', { dbId: screenParams.dbId })}
            >
              Додати перший об&apos;єкт
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">🔍</div>
            <div className="empty-h">Нічого не знайдено</div>
            <div className="empty-s">Немає результатів для &quot;{search}&quot;</div>
            <button
              style={{ marginTop: 16, padding: '8px 20px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: 'var(--bd)', color: 'var(--t2)', fontSize: 13, cursor: 'pointer' }}
              onClick={() => setSearch('')}
            >
              Очистити пошук
            </button>
          </div>
        ) : (
          <div className="list">
            {filtered.map((p, idx) => {
              const rent = p.rent_rate && p.area_useful
                ? calcRent(p.area_useful, p.rent_rate, p.rent_type)
                : 0
              const utils = p.utilities_rate && p.area_total
                ? calcUtilities(p.area_total, p.utilities_rate)
                : 0
              const total = rent + utils
              const inMode = reorderMode || selectMode

              return (
                <div
                  key={p.id}
                  className="obj-card glass-s"
                  style={inMode ? {
                    display: 'flex',
                    alignItems: 'stretch',
                    overflow: 'hidden',
                    outline: selectMode && selectedIds.has(p.id) ? '2px solid var(--accent)' : undefined,
                  } : undefined}
                  onClick={
                    selectMode ? () => toggleSelect(p.id) :
                    !reorderMode ? () => navigate('property-detail', { propertyId: p.id, dbId: db.id }) :
                    undefined
                  }
                >
                  {/* Select checkbox */}
                  {selectMode && (
                    <div style={{
                      width: 48, flexShrink: 0,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      borderRight: 'var(--bd)',
                    }}>
                      <div style={{
                        width: 22, height: 22, borderRadius: 11,
                        border: `2px solid ${selectedIds.has(p.id) ? 'var(--accent)' : 'var(--t4)'}`,
                        background: selectedIds.has(p.id) ? 'var(--accent)' : 'transparent',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        transition: 'background .15s, border-color .15s',
                        flexShrink: 0,
                      }}>
                        {selectedIds.has(p.id) && (
                          <svg width="11" height="8" viewBox="0 0 11 8" fill="none">
                            <path d="M1 4l3 3 6-6" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                          </svg>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Reorder controls */}
                  {reorderMode && (
                    <div style={{
                      width: 48, flexShrink: 0,
                      display: 'flex', flexDirection: 'column',
                      borderRight: 'var(--bd)',
                    }}>
                      <button
                        onClick={(e) => { e.stopPropagation(); window.Telegram?.WebApp?.HapticFeedback?.selectionChanged(); reorderProperty(p.id, 'up') }}
                        disabled={idx === 0}
                        aria-label="Вгору"
                        style={{
                          flex: 1, background: 'none', border: 'none',
                          color: idx === 0 ? 'var(--t4)' : 'var(--t2)',
                          cursor: idx === 0 ? 'default' : 'pointer',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          borderBottom: 'var(--bd)',
                        }}
                      >
                        <IconChevronUp size={15} />
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); window.Telegram?.WebApp?.HapticFeedback?.selectionChanged(); reorderProperty(p.id, 'down') }}
                        disabled={idx === filtered.length - 1}
                        aria-label="Вниз"
                        style={{
                          flex: 1, background: 'none', border: 'none',
                          color: idx === filtered.length - 1 ? 'var(--t4)' : 'var(--t2)',
                          cursor: idx === filtered.length - 1 ? 'default' : 'pointer',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}
                      >
                        <IconChevronDown size={15} />
                      </button>
                    </div>
                  )}

                  {/* Card content — same markup as normal mode, just wrapped in flex child */}
                  <div style={inMode ? { flex: 1, minWidth: 0 } : undefined}>
                    <div className="obj-hd">
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div className="obj-t" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {p.name}
                        </div>
                        <div className="obj-s">
                          {p.floor && <><span>🏢</span><span>{p.floor} поверх</span></>}
                        </div>
                      </div>
                      <div style={{ flexShrink: 0 }}>
                        <StatusBadge status={p.status} />
                      </div>
                    </div>
                    <div className="obj-met">
                      {p.area_useful && (
                        <div className="obj-mt">
                          <span>📐</span>
                          <span>{p.area_useful}/{p.area_total ?? p.area_useful} м²</span>
                        </div>
                      )}
                      {p.has_parking && (
                        <div className="obj-mt">
                          <span>🅿️</span>
                          <span>{p.parking_spaces} місць</span>
                        </div>
                      )}
                      {(p.photos?.length ?? 0) > 0 && (
                        <div className="obj-mt">
                          <IconPhoto size={11} />
                          <span>{p.photos!.length}</span>
                        </div>
                      )}
                      {(p._view_count ?? 0) > 0 && (
                        <div className="obj-mt">
                          <IconEye size={11} />
                          <span>{p._view_count}</span>
                        </div>
                      )}
                      {p.status === 'occupied' && formatLeasePeriod(p.lease_start_date, p.lease_end_date) && (
                        <div className="obj-mt" style={{ gridColumn: '1 / -1', color: 'var(--t3)' }}>
                          <span>📅</span>
                          <span>{formatLeasePeriod(p.lease_start_date, p.lease_end_date)}</span>
                        </div>
                      )}
                    </div>
                    {total > 0 && (
                      <div className="obj-tot">
                        <div>
                          <div className="obj-tot-l">На місяць</div>
                          <div className="obj-tot-sub">оренда + комунальні</div>
                        </div>
                        <div className="obj-tot-v">{formatPrice(total, user?.currency)}</div>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* FAB — hidden while reordering or selecting */}
      {!reorderMode && !selectMode && (
        <button className="fab" aria-label="Додати об'єкт" onClick={() => navigate('property-form', { dbId: db.id })}>
          <IconPlus size={20} />
        </button>
      )}

      {/* Batch action bar */}
      {selectMode && selectedIds.size > 0 && (
        <div style={{
          position: 'fixed', bottom: 56, left: 0, right: 0, zIndex: 100,
          background: 'var(--bg2)', borderTop: 'var(--bd)',
          padding: '8px 12px', display: 'flex', gap: 8, alignItems: 'center',
        }}>
          <span style={{ fontSize: 12, color: 'var(--t3)', whiteSpace: 'nowrap' }}>
            {selectedIds.size} обрано
          </span>
          <div style={{ flex: 1, display: 'flex', gap: 6, overflowX: 'auto' }}>
            <button
              onClick={() => handleBatchStatus('free')}
              style={{ padding: '6px 10px', borderRadius: 'var(--r-pill)', background: 'rgba(52,199,89,.18)', border: 'none', color: '#34c759', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              Вільно
            </button>
            <button
              onClick={() => handleBatchStatus('occupied')}
              style={{ padding: '6px 10px', borderRadius: 'var(--r-pill)', background: 'rgba(255,159,10,.18)', border: 'none', color: '#ff9f0a', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              Зайнято
            </button>
            <button
              onClick={() => handleBatchStatus('for_sale')}
              style={{ padding: '6px 10px', borderRadius: 'var(--r-pill)', background: 'rgba(122,179,255,.18)', border: 'none', color: '#7ab3ff', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap' }}
            >
              Продаж
            </button>
            <button
              onClick={() => setShowBatchDeleteModal(true)}
              style={{ padding: '6px 10px', borderRadius: 'var(--r-pill)', background: 'rgba(255,59,48,.18)', border: 'none', color: 'var(--err)', fontSize: 12, cursor: 'pointer', whiteSpace: 'nowrap', marginLeft: 'auto' }}
            >
              🗑 Видалити
            </button>
          </div>
        </div>
      )}

      <TabBar />

      {/* DB menu modal */}
      {showMenu && (
        <Modal
          title={db.name}
          subtitle="Дії з базою"
          onClose={() => setShowMenu(false)}
          actions={[
            { label: '📊 Аналітика і поширення', variant: 'secondary', onClick: () => { setShowMenu(false); navigate('sharing-analytics', { dbId: db.id }) } },
            { label: '📤 Експорт', variant: 'secondary', onClick: () => { setShowMenu(false); navigate('export', { dbId: db.id }) } },
            { label: '☑ Виділити об\'єкти', variant: 'secondary', onClick: enterSelectMode },
            { label: '↕ Змінити порядок об\'єктів', variant: 'secondary', onClick: enterReorderMode },
            { label: '✏️ Редагувати базу', variant: 'secondary', onClick: () => { setShowMenu(false); navigate('edit-db', { dbId: db.id }) } },
            { label: '🗑️ Видалити базу', variant: 'danger', onClick: () => { setShowMenu(false); setShowDeleteModal(true) } },
          ]}
        />
      )}

      {/* Batch delete confirm */}
      {showBatchDeleteModal && (
        <Modal
          title={`Видалити ${selectedIds.size} об'єктів?`}
          subtitle="Всі вибрані об'єкти і їхні фото будуть видалені. Це незворотно."
          onClose={() => setShowBatchDeleteModal(false)}
          actions={[
            { label: `Видалити (${selectedIds.size})`, variant: 'danger', onClick: handleBatchDelete },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowBatchDeleteModal(false) },
          ]}
        />
      )}

      {/* Delete confirm */}
      {showDeleteModal && (
        <Modal
          title="Видалити базу?"
          subtitle={`База "${db.name}" і всі ${properties.length} об'єктів будуть видалені. Це незворотно.`}
          onClose={() => setShowDeleteModal(false)}
          actions={[
            { label: 'Видалити', variant: 'danger', onClick: async () => { window.Telegram?.WebApp?.HapticFeedback?.notificationOccurred('warning'); await deleteDatabase(db.id); setShowDeleteModal(false) } },
            { label: 'Скасувати', variant: 'secondary', onClick: () => setShowDeleteModal(false) },
          ]}
        />
      )}
    </div>
  )
}
