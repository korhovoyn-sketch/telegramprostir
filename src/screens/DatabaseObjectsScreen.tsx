'use client'

import { useEffect, useState, useMemo, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { hapticSelection } from '@/lib/telegram'
import { offlineGuard } from '@/lib/offline'
import { confirmAction } from '@/lib/confirm'
import { useDatabases } from '@/hooks/useDatabases'
import { useProperties } from '@/hooks/useProperties'
import { useFolders } from '@/hooks/useFolders'
import Header from '@/components/ui/Header'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import { StatusBadge } from '@/components/ui/Badge'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import Modal from '@/components/ui/Modal'
import FolderManageModal from '@/components/ui/FolderManageModal'
import FolderPickerModal from '@/components/ui/FolderPickerModal'
import Collapsible from '@/components/ui/Collapsible'
import { IconCheck, IconPlus, IconDots, IconPhoto, IconChevronUp, IconChevronDown, IconBuilding, IconRuler, IconParking, IconCalendar, IconActivity, IconCurrencyDollar, IconEdit, IconCopy, IconUser, IconUsers, IconFile, IconLayers, IconLayoutGrid, IconChartBar, IconKey, IconFileExport, IconCircleCheck, IconAdjustments, IconTrash, IconChevronRight, IconFolder, IconInbox } from '@/components/Icons'
import DatabaseStatsPanel from '@/components/ui/DatabaseStatsPanel'
import FloatingButton from '@/components/ui/FloatingButton'
import { formatPrice, calcRent, calcRentUtils, basisArea, floorSortKey, computedRentUnit, rentUnitLabel, objectsWord, DB_TYPE_LABELS, formatLeasePeriod, STATUS_COLORS, matchesQuery } from '@/lib/utils'
import { supabase } from '@/lib/supabase'
import type { Database, Property, PropertyStatus } from '@/types'
import DbPickerModal from '@/components/ui/DbPickerModal'
import CoachMark from '@/components/ui/CoachMark'
import { useOnboarding } from '@/hooks/useOnboarding'
import { useHideOnScrollDown } from '@/hooks/useHideOnScrollDown'

export default function DatabaseObjectsScreen() {
  const fabHidden = useHideOnScrollDown()
  const { screenParams, navigate, databases, user } = useAppStore()
  const { deleteDatabase, createDatabase } = useDatabases()
  const { properties, loading, error, loadProperties, reorderProperty, batchDeleteProperties, batchUpdateStatus, moveToFolder, moveToDatabase } = useProperties(screenParams.dbId)
  const { folders, unavailable: foldersUnavailable, loadFolders, createFolder, renameFolder, deleteFolder, reorderFolder } = useFolders(screenParams.dbId)
  const memberDbIds = useAppStore(st => st.memberDbIds)
  // Редактор команди отримує ту саму edit-поверхню, що власник…
  const isOwner = user?.role === 'owner' || memberDbIds.includes(screenParams.dbId ?? '')

  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'all' | PropertyStatus>('all')
  const [sortBy, setSortBy] = useState<'default' | 'floor' | 'area' | 'rent'>('default')
  const [showMenu, setShowMenu] = useState(false)
  const [reorderMode, setReorderMode] = useState(false)
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showFolderManage, setShowFolderManage] = useState(false)
  const [showFolderPicker, setShowFolderPicker] = useState(false)
  const [showDbPicker, setShowDbPicker] = useState(false)
  // Згорнуті папки — ключі папок ('__none__' для «Без папки»), персист per user+db.
  const collapseKey = user && screenParams.dbId ? `ps:foldCollapse:${user.id}:${screenParams.dbId}` : ''
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    try {
      const raw = collapseKey && localStorage.getItem(collapseKey)
      return raw ? new Set<string>(JSON.parse(raw)) : new Set<string>()
    } catch { return new Set<string>() }
  })

  function toggleFolder(key: string) {
    hapticSelection()
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      try { if (collapseKey) localStorage.setItem(collapseKey, JSON.stringify([...next])) } catch { /* private mode */ }
      return next
    })
  }

  async function handleBulkMove(folderId: string | null) {
    setShowFolderPicker(false)
    if (offlineGuard()) return
    await moveToFolder([...selectedIds], folderId)
    exitSelectMode()
  }

  async function handleMoveToDb(target: Database) {
    setShowDbPicker(false)
    if (offlineGuard()) return
    await moveToDatabase([...selectedIds], target.id, target.owner_id, target.name)
    exitSelectMode()
  }

  // Нова база під перенос успадковує тип і колір поточної — обрані обʼєкти майже
  // завжди тієї ж природи (форма обʼєкта залежить від типу бази).
  async function handleCreateDbForMove(name: string): Promise<Database | null> {
    if (!db) return null
    return createDatabase({ name, address: db.address, type: db.type, color: db.color }, { navigate: false })
  }
  // Одне вподобання «компактно» на обидві статусні вкладки (зайняті + вільні).
  // Ключ лишається історичним 'ps:occCompact', щоб не скидати вибір користувачам.
  const [statusCompact, setStatusCompact] = useState(() =>
    typeof window !== 'undefined' && localStorage.getItem('ps:occCompact') === '1')

  function toggleStatusCompact(next: boolean) {
    hapticSelection()
    setStatusCompact(next)
    try { localStorage.setItem('ps:occCompact', next ? '1' : '0') } catch { /* private mode blocks storage */ }
  }

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
    hapticSelection()
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleBatchDelete() {
    const n = selectedIds.size
    const ok = await confirmAction({
      title: `Видалити ${n} ${objectsWord(n)}?`,
      message: 'Всі вибрані об\'єкти і їхні фото будуть видалені. Це незворотно.',
      confirmLabel: `Видалити (${n})`,
      destructive: true,
    })
    if (!ok) return
    if (offlineGuard()) return
    await batchDeleteProperties([...selectedIds])
    exitSelectMode()
  }

  async function handleDeleteDatabase() {
    if (!db) return
    const ok = await confirmAction({
      title: 'Видалити базу?',
      message: `База "${db.name}" і всі ${properties.length} ${objectsWord(properties.length)} будуть видалені. Це незворотно.`,
      confirmLabel: 'Видалити',
      destructive: true,
    })
    if (!ok || offlineGuard()) return
    await deleteDatabase(db.id)
  }

  async function handleBatchStatus(status: PropertyStatus) {
    if (offlineGuard()) return
    await batchUpdateStatus([...selectedIds], status)
    exitSelectMode()
  }

  const fabRef = useRef<HTMLButtonElement>(null)
  const { isDone: fabSeen, markDone: markFabSeen } = useOnboarding('obj-fab')

  const db = databases.find((d) => d.id === screenParams.dbId)

  useEffect(() => {
    if (screenParams.dbId) loadProperties(screenParams.dbId)
  }, [screenParams.dbId, loadProperties])

  useEffect(() => {
    if (screenParams.dbId) loadFolders(screenParams.dbId)
  }, [screenParams.dbId, loadFolders])

  // Deep link (own_db / team_ / db-гість) веде сюди повз db-list на холодному
  // старті — стор порожній, і без власного довантаження екран висів би на
  // вічному спінері (!db нижче). Тягнемо одну базу за id: RLS сам вирішує
  // видимість для будь-якої ролі (owner/editor/guest/realtor), на відміну від
  // loadDatabases, що фільтрує по owner_id + membership.
  const dbMissing = !db
  // Розрізняє «ще вантажиться» від «справді не існує/немає доступу» — без
  // цього прапорця запит, що резолвиться `data: null` (видалена база,
  // застарілий deep link, чужий share), лишав екран на вічному спінері:
  // нема куди повернутись і нема сигналу, що ще чекати нічого.
  const [dbFetchDone, setDbFetchDone] = useState(false)
  const [dbRetryKey, setDbRetryKey] = useState(0)
  useEffect(() => {
    if (!dbMissing || !screenParams.dbId) return
    let stale = false
    setDbFetchDone(false)
    supabase
      .from('databases')
      .select('id,owner_id,name,address,type,color,share_token,share_expires_at,created_at,updated_at')
      .eq('id', screenParams.dbId)
      .maybeSingle()
      .then(({ data }) => {
        if (stale) return
        if (data) {
          const cur = useAppStore.getState().databases
          if (!cur.some((d) => d.id === (data as Database).id)) {
            useAppStore.getState().setDatabases([...cur, data as Database])
          }
        }
        setDbFetchDone(true)
      })
    return () => { stale = true }
  }, [dbMissing, screenParams.dbId, dbRetryKey])

  const filtered = useMemo(() => {
    const base = properties.filter((p) => {
      const matchSearch = matchesQuery(search, p.name, p.tenant_name, p.floor, p.address, p.description)
      const matchTab = tab === 'all' || p.status === tab
      return matchSearch && matchTab
    })
    switch (sortBy) {
      // Ascending by floor, ground up. Floors are free-text ("1", "-1", "B-1",
      // "МП") — sort by the leading signed number, non-numeric floors last.
      case 'floor':  return [...base].sort((a, b) => {
        const fa = floorSortKey(a.floor), fb = floorSortKey(b.floor)
        return fa !== fb ? fa - fb : (a.floor ?? '').localeCompare(b.floor ?? '', 'uk')
      })
      case 'area':   return [...base].sort((a, b) => (b.area_useful ?? 0) - (a.area_useful ?? 0))
      case 'rent':   return [...base].sort((a, b) => {
        const aR = calcRent(basisArea(a.area_useful, a.area_total, a.area_basis), a.rent_rate ?? 0, a.rent_type ?? 'per_m2')
        const bR = calcRent(basisArea(b.area_useful, b.area_total, b.area_basis), b.rent_rate ?? 0, b.rent_type ?? 'per_m2')
        return bR - aR
      })
      default: return base
    }
  }, [properties, search, tab, sortBy])

  const counts = useMemo(() => ({
    all: properties.length,
    free: properties.filter(p => p.status === 'free').length,
    occupied: properties.filter(p => p.status === 'occupied').length,
    for_sale: properties.filter(p => p.status === 'for_sale').length,
  }), [properties])

  const compactView = statusCompact && !reorderMode && !selectMode

  // Кількість об'єктів у кожній папці — по ВСІХ об'єктах (для modal керування).
  const folderCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const p of properties) if (p.folder_id) m.set(p.folder_id, (m.get(p.folder_id) ?? 0) + 1)
    return m
  }, [properties])

  const foldersById = useMemo(() => new Map(folders.map(f => [f.id, f])), [folders])
  const foldersEnabled = !foldersUnavailable && folders.length > 0

  // Групування filtered-списку в акордеон-секції. Порожні папки ховаємо під час
  // фільтрації (пошук/вкладка), але показуємо в нейтральному вигляді, щоб було
  // куди складати. Reorder-режим — завжди плаский список (глобальний sort_order).
  const sections = useMemo(() => {
    if (!foldersEnabled || reorderMode) return null
    const byFolder = new Map<string, Property[]>()
    const none: Property[] = []
    for (const p of filtered) {
      if (p.folder_id && foldersById.has(p.folder_id)) {
        const arr = byFolder.get(p.folder_id) ?? []
        arr.push(p)
        byFolder.set(p.folder_id, arr)
      } else none.push(p)
    }
    const isFiltering = search.trim() !== '' || tab !== 'all'
    const out: { key: string; id: string | null; name: string; items: Property[] }[] = []
    for (const f of folders) {
      const items = byFolder.get(f.id) ?? []
      if (items.length === 0 && isFiltering) continue
      out.push({ key: f.id, id: f.id, name: f.name, items })
    }
    if (none.length > 0) out.push({ key: '__none__', id: null, name: 'Без папки', items: none })
    return out
  }, [foldersEnabled, reorderMode, filtered, folders, foldersById, search, tab])

  // Під час пошуку розгортаємо всі секції, щоб знахідки не ховались у згорнутій папці.
  const forceExpand = search.trim() !== ''

  if (!db && dbFetchDone) return (
    <div className="scr bg-blue">
      <Header title="База" backLabel="Назад" />
      <RetryState
        icon="🗄️"
        title="Базу не знайдено"
        subtitle="Можливо, її видалили, або в тебе більше немає до неї доступу."
        onRetry={() => { setDbFetchDone(false); setDbRetryKey(k => k + 1) }}
      />
    </div>
  )

  if (!db) return (
    <div className="scr bg-blue">
      <div className="loader-wrap" style={{ paddingTop: 80 }}><div className="loader" /></div>
    </div>
  )

  // idx матеріальний лише в reorder-режимі (межі ↑/↓); у групованому/плоскому
  // списку передаємо 0 — там кнопок реордера немає.
  const renderCard = (p: Property, idx: number) => {
    const { rent, utils, total } = calcRentUtils(p.area_useful, p.area_total, p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis)
    // A daily rate can't be summed with monthly utilities — show the raw
    // daily rate (/добу); everything else shows the monthly total (/міс).
    const isDaily = p.rent_type === 'per_day'
    const dispVal = isDaily ? rent : total
    const dispUnit = computedRentUnit(p.rent_type)

    if (compactView) {
      const title = p.tenant_name?.trim() || p.name
      // Права колонка за статусом: вільний — це оголошення, СИРА
      // ставка (rentUnitLabel, «$18/м²»); продаж — ціна продажу без
      // суфікса; зайнятий — фактичний порахований дохід «/міс».
      const compVal = p.status === 'free' ? (p.rent_rate ?? 0)
        : p.status === 'for_sale' ? (p.sale_price ?? 0)
        : dispVal
      const compUnit = p.status === 'free' ? rentUnitLabel(p.rent_type)
        : p.status === 'for_sale' ? ''
        : dispUnit
      return (
        <div
          key={p.id}
          className="row glass-s"
          onClick={() => navigate('property-detail', { propertyId: p.id, dbId: db.id })}
        >
          <div className="row-mn">
            <div className="row-t" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {/* На змішаній вкладці «Всі» рядки без статусної крапки нерозрізненні */}
              {tab === 'all' && <span className="fdot" style={{ background: STATUS_COLORS[p.status].color, flexShrink: 0 }} />}
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</span>
            </div>
            <div className="row-s">
              {p.tenant_name?.trim() && <><IconBuilding size={14} color="var(--t3)" /><span>{p.name}</span></>}
              {p.floor && <><IconLayers size={14} color="var(--t3)" /><span>{p.floor} пов.</span></>}
              {p.area_useful && <><IconRuler size={14} color="var(--t3)" /><span>{p.area_useful} м²</span></>}
            </div>
          </div>
          <div className="row-r">
            <span className="row-tot">{compVal > 0 ? formatPrice(compVal, user?.currency) : '—'}</span>
            {compVal > 0 && compUnit && <span className="row-tot-u">{compUnit}</span>}
          </div>
        </div>
      )
    }

    return (
      <div
        key={p.id}
        className="obj-card glass-s"
        style={reorderMode ? {
          display: 'flex', alignItems: 'stretch', overflow: 'hidden', cursor: 'default',
        } : selectMode ? {
          display: 'flex', alignItems: 'stretch', overflow: 'hidden',
          // inset-ring замість outline: outline малюється ЗА межами border-box,
          // і contain:paint на картці обрізав його по боках
          boxShadow: selectedIds.has(p.id) ? 'inset 0 0 0 2px var(--accent)' : undefined,
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
                <IconCheck size={12} color="var(--t1)" />
              )}
            </div>
          </div>
        )}

        {/* Reorder controls */}
        {reorderMode && (
          <div style={{
            width: 44, flexShrink: 0,
            display: 'flex', flexDirection: 'column',
            borderRight: '.5px solid rgba(255,255,255,.10)',
            background: 'var(--glass-1)',
          }}>
            <button
              onClick={(e) => { e.stopPropagation(); hapticSelection(); reorderProperty(p.id, 'up') }}
              disabled={idx === 0}
              aria-label="Вгору"
              style={{
                flex: 1, background: 'none', border: 'none', minHeight: 26,
                color: idx === 0 ? 'rgba(255,255,255,.18)' : 'var(--t2)',
                cursor: idx === 0 ? 'default' : 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                borderBottom: '.5px solid rgba(255,255,255,.08)',
                transition: 'color .15s',
              }}
            >
              <IconChevronUp size={14} />
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); hapticSelection(); reorderProperty(p.id, 'down') }}
              disabled={idx === filtered.length - 1}
              aria-label="Вниз"
              style={{
                flex: 1, background: 'none', border: 'none', minHeight: 26,
                color: idx === filtered.length - 1 ? 'rgba(255,255,255,.18)' : 'var(--t2)',
                cursor: idx === filtered.length - 1 ? 'default' : 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'color .15s',
              }}
            >
              <IconChevronDown size={14} />
            </button>
          </div>
        )}

        {/* Card content */}
        {reorderMode ? (
          /* Simplified row in reorder mode */
          <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', padding: '0 12px', gap: 8, height: 52 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 'var(--fs-note)', fontWeight: 'var(--fw-semi)', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: 1.2 }}>
                {p.name}
              </div>
              {p.floor && (
                <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--t3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 3 }}>
                  <IconBuilding size={14} color="var(--t3)" />{p.floor} поверх
                </div>
              )}
            </div>
            <div style={{ flexShrink: 0 }}>
              <StatusBadge status={p.status} />
            </div>
          </div>
        ) : (
          <div style={selectMode ? { flex: 1, minWidth: 0 } : undefined}>
            <div className="obj-hd">
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="obj-t" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {p.name}
                </div>
                {/* Один рядок фактів: поверх · площа — компактно, без розсипаної сітки */}
                <div className="obj-s">
                  {p.floor && <><IconBuilding size={14} color="var(--t3)" /><span>{p.floor} поверх</span></>}
                  {p.area_useful != null && <>
                    {p.floor && <span className="obj-s-sep">·</span>}
                    <IconRuler size={14} color="var(--t3)" /><span>{p.area_useful}/{p.area_total ?? p.area_useful} м²</span>
                  </>}
                </div>
              </div>
              <div style={{ flexShrink: 0 }}>
                <StatusBadge status={p.status} />
              </div>
            </div>

            {/* Зайнятий об'єкт: хто орендує і до якого терміну — ключова інформація картки */}
            {p.status === 'occupied' && (p.tenant_name?.trim() || formatLeasePeriod(p.lease_start_date, p.lease_end_date)) && (
              <div className="obj-ten">
                {p.tenant_name?.trim() && (
                  <div className="obj-ten-name">
                    <IconUser size={14} color="var(--accent)" />
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.tenant_name}</span>
                  </div>
                )}
                {formatLeasePeriod(p.lease_start_date, p.lease_end_date) && (
                  <div className="obj-ten-lease">
                    <IconCalendar size={14} color="var(--t3)" />
                    <span>{formatLeasePeriod(p.lease_start_date, p.lease_end_date)}</span>
                  </div>
                )}
              </div>
            )}

            {/* Другорядні позначки — лише коли є що показати */}
            {(p.has_parking || (p.photos?.length ?? 0) > 0) && (
              <div className="obj-met">
                {p.has_parking && (
                  <div className="obj-mt">
                    <IconParking size={14} color="var(--t3)" />
                    <span>{p.parking_spaces} місць</span>
                  </div>
                )}
                {(p.photos?.length ?? 0) > 0 && (
                  <div className="obj-mt">
                    <IconPhoto size={14} />
                    <span>{p.photos!.length}</span>
                  </div>
                )}
              </div>
            )}
            {dispVal > 0 && (
              <div className="obj-tot">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 22, height: 22, borderRadius: 'var(--r-xs)', background: 'var(--ok-bg)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <IconCurrencyDollar size={12} color="var(--ok-fg)" />
                  </span>
                  <div>
                    <div className="obj-tot-l">{isDaily ? 'За добу' : 'На місяць'}</div>
                    <div className="obj-tot-sub">{isDaily ? 'подобово' : rent > 0 && utils > 0 ? 'оренда + експлуатаційні' : rent > 0 ? 'оренда' : 'експлуатаційні'}</div>
                  </div>
                </div>
                <div className="obj-tot-v">{formatPrice(dispVal, user?.currency)}</div>
              </div>
            )}
            {!selectMode && !reorderMode && (
              <div className="obj-act" onClick={e => e.stopPropagation()}>
                {isOwner && (
                  <button
                    className="obj-act-btn"
                    onClick={() => navigate('property-form', { propertyId: p.id, dbId: db.id })}
                  >
                    <IconEdit size={12} /> Редагувати
                  </button>
                )}
                {isOwner && (
                  <button
                    className="obj-act-btn"
                    onClick={() => { hapticSelection(); navigate('property-form', { dbId: db.id, duplicateId: p.id }) }}
                  >
                    <IconCopy size={12} /> Дублювати
                  </button>
                )}
                {p.status === 'occupied' && (
                  <button
                    className="obj-act-btn"
                    onClick={() => navigate('payment-calendar', { propertyId: p.id, dbId: db.id })}
                  >
                    <IconCalendar size={12} /> Платежі
                  </button>
                )}
                <button
                  className="obj-act-btn"
                  onClick={() => navigate('property-detail', { propertyId: p.id, dbId: db.id, scrollTo: 'files' })}
                >
                  <IconFile size={12} /> Файли
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="scr bg-blue">
      <Header
        title={db.name}
        subtitle={DB_TYPE_LABELS[db.type]}
        backLabel="Бази"
        right={
          reorderMode ? (
            <button className="hdr-a" onClick={() => setReorderMode(false)} style={{ background: 'var(--ok-bg)', border: 'none', color: 'var(--ok-fg)', fontWeight: 'var(--fw-semi)', fontSize: 'var(--fs-foot)' }}>
              Готово
            </button>
          ) : selectMode ? (
            <button className="hdr-a" onClick={exitSelectMode} style={{ background: 'none', border: 'var(--bd)', fontSize: 'var(--fs-foot)' }}>
              Скасувати
            </button>
          ) : isOwner ? (
            <button className="hdr-a" aria-label="Меню бази" onClick={() => setShowMenu(true)} style={{ background: 'none', border: 'var(--bd)' }}>
              <IconDots size={16} />
            </button>
          ) : <div className="hdr-sp" />
        }
      />

      <div className={`body has-fab${selectMode ? ' has-batchbar' : ''}`}>
        {/* No summary card here — the header already names the DB, the segment
            tabs carry the counts, and share lives in the «⋯» menu. Dropping it
            lifts real content above the fold. */}

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
                onClick={() => { hapticSelection(); setTab(t.id) }}
              >
                {t.label}
              </div>
            ))}
          </div>
        )}

        {/* Search — hidden while reordering */}
        {!reorderMode && (
          <SearchBar value={search} onChange={setSearch} placeholder="Пошук об'єкту..." />
        )}

        {/* Sort + view toggle — one row: chips scroll left, toggle pinned right */}
        {!reorderMode && !selectMode && filtered.length > 0 && (
          <div style={{ margin: '0 12px 8px', display: 'flex', alignItems: 'center', gap: 8 }}>
            {properties.length > 1 ? (
              <div className="sort-scroll" style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 6, overflowX: 'auto', paddingBottom: 2 }}>
                <span style={{ display: 'flex', flexShrink: 0 }}><IconActivity size={12} color="var(--t4)" /></span>
                {([
                  { id: 'default', label: 'За порядком' },
                  { id: 'floor',   label: 'За поверхом' },
                  { id: 'rent',    label: 'За орендою'  },
                  { id: 'area',    label: 'За площею'   },
                ] as const).map(opt => (
                  <button
                    key={opt.id}
                    className="sort-chip"
                    onClick={() => setSortBy(opt.id)}
                    style={{
                      flexShrink: 0,
                      padding: '4px 10px', borderRadius: 8,
                      background: sortBy === opt.id ? 'var(--info-bg)' : 'var(--glass-1)',
                      color:      sortBy === opt.id ? 'var(--info)' : 'var(--t3)',
                      border:     sortBy === opt.id ? '.5px solid rgba(122,179,255,.4)' : 'var(--bd)',
                      fontSize: 'var(--fs-cap2)', fontWeight: 'var(--fw-semi)', cursor: 'pointer', whiteSpace: 'nowrap',
                    }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            ) : <div style={{ flex: 1 }} />}
            {/* Icon-only view switch — compact, no labels */}
            <div className="view-seg">
              <button className={`view-seg-b ${!statusCompact ? 'on' : ''}`} aria-label="Картки" onClick={() => toggleStatusCompact(false)}>
                <IconLayoutGrid size={16} />
              </button>
              <button className={`view-seg-b ${statusCompact ? 'on' : ''}`} aria-label="Компактно" onClick={() => toggleStatusCompact(true)}>
                <IconLayers size={16} />
              </button>
            </div>
          </div>
        )}

        {/* Stats dashboard — у компакті ховаємо: користувач попросив щільності,
            а панель з'їдала пів першого екрана списку */}
        {!reorderMode && !selectMode && !compactView && (
          <DatabaseStatsPanel properties={properties} currency={user?.currency} />
        )}

        {/* Mode hints */}
        {reorderMode && (
          <div style={{ padding: '8px 16px', fontSize: 'var(--fs-cap1)', color: 'var(--t3)', textAlign: 'center' }}>
            Натисніть ↑ або ↓ щоб змінити позицію об&apos;єкта
          </div>
        )}
        {selectMode && (
          <div style={{ padding: '6px 16px', fontSize: 'var(--fs-cap1)', color: 'var(--t3)', textAlign: 'center', display: 'flex', justifyContent: 'center', gap: 12 }}>
            <span>Оберіть об&apos;єкти для дії</span>
            {filtered.length > 0 && (
              <button
                onClick={() => {
                  const allSelected = filtered.every(p => selectedIds.has(p.id))
                  if (allSelected) setSelectedIds(new Set())
                  else setSelectedIds(new Set(filtered.map(p => p.id)))
                }}
                style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: 'var(--fs-cap1)', cursor: 'pointer', padding: 0 }}
              >
                {filtered.every(p => selectedIds.has(p.id)) ? 'Зняти все' : 'Вибрати все'}
              </button>
            )}
          </div>
        )}

        {/* Property cards */}
        {loading ? (
          <SkeletonLoader rowHeight={compactView ? 69 : 200} />
        ) : error && properties.length === 0 ? (
          <RetryState subtitle={error} onRetry={() => loadProperties(screenParams.dbId)} />
        ) : filtered.length === 0 && properties.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">🏢</div>
            <div className="empty-h">Немає об&apos;єктів</div>
            <div className="empty-s">{isOwner ? 'Натисни + щоб додати перший об\'єкт' : 'У цій базі поки немає об\'єктів'}</div>
            {isOwner && (
              <button
                className="mbtn success"
                style={{ position: 'relative', bottom: 'auto', left: 'auto', right: 'auto', marginTop: 24, width: 'auto', minWidth: 200 }}
                onClick={() => navigate('property-form', { dbId: screenParams.dbId })}
              >
                Додати перший об&apos;єкт
              </button>
            )}
          </div>
        ) : filtered.length === 0 && search ? (
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">🔍</div>
            <div className="empty-h">Нічого не знайдено</div>
            <div className="empty-s">Немає результатів для &quot;{search}&quot;</div>
            <button
              style={{ marginTop: 16, padding: '8px 20px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: 'var(--bd)', color: 'var(--t2)', fontSize: 'var(--fs-foot)', cursor: 'pointer' }}
              onClick={() => setSearch('')}
            >
              Очистити пошук
            </button>
          </div>
        ) : filtered.length === 0 ? (
          // Empty because of the status tab, not search — a status-specific
          // message + a way back to all, instead of the misleading "no results".
          <div className="empty-state" style={{ paddingTop: 24 }}>
            <div className="empty-ic">{tab === 'free' ? '🟢' : tab === 'occupied' ? '🔑' : '🏷️'}</div>
            <div className="empty-h">
              {tab === 'free' ? 'Немає вільних об\'єктів' : tab === 'occupied' ? 'Немає зайнятих об\'єктів' : 'Немає об\'єктів на продаж'}
            </div>
            <div className="empty-s">Усього в базі — {properties.length} {objectsWord(properties.length)}</div>
            <button
              style={{ marginTop: 16, padding: '8px 20px', borderRadius: 'var(--r-pill)', background: 'var(--glass-2)', border: 'var(--bd)', color: 'var(--t2)', fontSize: 'var(--fs-foot)', cursor: 'pointer' }}
              onClick={() => { hapticSelection(); setTab('all') }}
            >
              Показати всі
            </button>
          </div>
        ) : sections ? (
          // Секція = хедер + Collapsible (JS-анімація висоти). Картки лишаються
          // змонтованими, щоб плавно анімувалась висота, а не миготів mount.
          <div className="list">
            {sections.map((sec) => {
              const open = forceExpand || !collapsed.has(sec.key)
              return (
                <div key={sec.key} className="fold-sec">
                  <div className={`fold-hd ${open ? 'open' : ''}`} onClick={() => toggleFolder(sec.key)}>
                    <span className={`fold-hd-chev ${open ? 'open' : ''}`}><IconChevronRight size={16} /></span>
                    <span className="fold-hd-ic">{sec.id ? <IconFolder size={16} /> : <IconInbox size={16} />}</span>
                    <span className="fold-hd-name">{sec.name}</span>
                    <span className="fold-hd-cnt">{sec.items.length}</span>
                  </div>
                  <Collapsible open={open} className="fold-wrap-inner">
                    {sec.items.map((p) => renderCard(p, 0))}
                  </Collapsible>
                </div>
              )
            })}
          </div>
        ) : (
          <div className="list">
            {filtered.map((p, idx) => renderCard(p, idx))}
          </div>
        )}
      </div>

      {/* FAB — owner only, hidden while reordering or selecting */}
      {isOwner && !reorderMode && !selectMode && (
        <FloatingButton
          ref={fabRef}
          variant="create"
          raised
          hidden={fabHidden}
          icon={<IconPlus size={16} />}
          label="Додати об'єкт"
          onClick={() => navigate('property-form', { dbId: db.id })}
        />
      )}

      {isOwner && !fabSeen && !reorderMode && !selectMode && !loading && (
        <CoachMark
          title="Додайте перший об'єкт"
          body="Натисніть +, щоб внести квартиру, офіс або приміщення з площею, статусом та орендою."
          targetRef={fabRef}
          placement="above"
          onDone={markFabSeen}
        />
      )}

      {/* Batch action bar — owner only */}
      {isOwner && selectMode && selectedIds.size > 0 && (
        <div className="batchbar-scrim" aria-hidden />
      )}
      {isOwner && selectMode && selectedIds.size > 0 && (
        <div className="batchbar">
          <span className="batchbar-n">{selectedIds.size} обрано</span>
          <div className="batch-scroll">
            {!foldersUnavailable && (
              <button className="batch-pill" onClick={() => setShowFolderPicker(true)}>
                <IconFolder size={14} /> У папку
              </button>
            )}
            <button className="batch-pill" onClick={() => setShowDbPicker(true)}>
              <IconBuilding size={14} /> В базу
            </button>
            <button className="batch-pill ok" onClick={() => handleBatchStatus('free')}>Вільно</button>
            <button className="batch-pill warn" onClick={() => handleBatchStatus('occupied')}>Зайнято</button>
            <button className="batch-pill info" onClick={() => handleBatchStatus('for_sale')}>Продаж</button>
          </div>
          <button
            className="batch-pill err"
            aria-label={`Видалити ${selectedIds.size} ${objectsWord(selectedIds.size)}`}
            onClick={handleBatchDelete}
          >
            <IconTrash size={16} />
          </button>
        </div>
      )}

      <TabBar />

      {/* DB menu modal — nav items in children (scrollable), destructive in actions */}
      {showMenu && (
        <Modal
          title={db.name}
          subtitle="Дії з базою"
          onClose={() => setShowMenu(false)}
        >
          <div className="sheet-group">
            {[
              // …але шаринг/гості/команда — тільки для справжнього власника
              ...(db.owner_id === user?.id ? [
                { Icon: IconChartBar,  label: 'Аналітика і поширення', nav: true,  danger: false, action: () => { setShowMenu(false); navigate('sharing-analytics', { dbId: db.id }) } },
              ] : []),
              { Icon: IconCalendar,    label: 'Календар платежів',     nav: true,  danger: false, action: () => { setShowMenu(false); navigate('payment-calendar', { dbId: db.id }) } },
              ...(db.owner_id === user?.id ? [
                { Icon: IconKey,       label: 'Управління гостями',    nav: true,  danger: false, action: () => { setShowMenu(false); navigate('manage-guests', { dbId: db.id }) } },
                { Icon: IconUsers,     label: 'Команда',               nav: true,  danger: false, action: () => { setShowMenu(false); navigate('team', { dbId: db.id }) } },
              ] : []),
              { Icon: IconFileExport,  label: 'Експорт',               nav: true,  danger: false, action: () => { setShowMenu(false); navigate('export', { dbId: db.id }) } },
              ...(!foldersUnavailable ? [
                { Icon: IconFolder,    label: 'Папки',                 nav: false, danger: false, action: () => { setShowMenu(false); setShowFolderManage(true) } },
              ] : []),
              { Icon: IconCircleCheck, label: 'Виділити об\'єкти',      nav: false, danger: false, action: enterSelectMode },
              { Icon: IconAdjustments, label: 'Змінити порядок',       nav: false, danger: false, action: enterReorderMode },
              // Редагування й видалення САМОЇ бази — теж owner-only (як шаринг/гості/команда
              // вище): редактор команди має лише CRUD об'єктів/фото/файлів/платежів
              // (041), а не право стерти чи перейменувати чужу базу. Без цього гейту
              // RLS мовчки блокує сам DELETE рядка databases (0 рядків, без помилки),
              // але storage-політика редактора ВСЕ ОДНО дозволяє видалити всі фото
              // бази — тож клієнт репортував би фальшивий успіх, стерши лише фотографії.
              ...(db.owner_id === user?.id ? [
                { Icon: IconEdit,      label: 'Редагувати базу',       nav: true,  danger: false, action: () => { setShowMenu(false); navigate('edit-db', { dbId: db.id }) } },
                { Icon: IconTrash,     label: 'Видалити базу',         nav: false, danger: true,  action: () => { setShowMenu(false); void handleDeleteDatabase() } },
              ] : []),
            ].map(({ Icon, label, nav, danger, action }) => (
              <div key={label} className={`sheet-row${danger ? ' danger' : ''}`} onClick={action}>
                <span className="sheet-ic"><Icon size={16} /></span>
                <span className="sheet-lbl">{label}</span>
                {nav && <IconChevronRight size={16} className="sheet-chev" />}
              </div>
            ))}
          </div>
          <button className="sheet-cancel" onClick={() => setShowMenu(false)}>Скасувати</button>
        </Modal>
      )}

      {/* Folder management */}
      {showFolderManage && (
        <FolderManageModal
          folders={folders}
          counts={folderCounts}
          onCreate={createFolder}
          onRename={renameFolder}
          // Перезавантажувати список НЕ треба: секції групують лише по папках, що
          // існують (foldersById.has), тож обʼєкти видаленої папки самі падають у
          // «Без папки». Зайвий раунд-трип лише підвішував модалку.
          onDelete={deleteFolder}
          onReorder={reorderFolder}
          onClose={() => setShowFolderManage(false)}
        />
      )}

      {/* Bulk move to folder */}
      {showFolderPicker && (
        <FolderPickerModal
          folders={folders}
          title={`Перемістити ${selectedIds.size} ${objectsWord(selectedIds.size)}`}
          subtitle="Оберіть папку або створіть нову"
          onPick={handleBulkMove}
          onCreate={createFolder}
          onClose={() => setShowFolderPicker(false)}
        />
      )}

      {/* Bulk move to another database (or a brand-new one) */}
      {showDbPicker && (
        <DbPickerModal
          databases={databases.filter((d) => d.id !== screenParams.dbId)}
          count={selectedIds.size}
          onPick={handleMoveToDb}
          onCreate={handleCreateDbForMove}
          onClose={() => setShowDbPicker(false)}
        />
      )}

    </div>
  )
}
