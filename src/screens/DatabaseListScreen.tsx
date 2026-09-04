'use client'

import { useEffect, useState, useMemo, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { hapticImpact } from '@/lib/telegram'
import { useDatabases } from '@/hooks/useDatabases'
import { useSlowLoadingToast } from '@/hooks/useSlowLoadingToast'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import CoachMark from '@/components/ui/CoachMark'
import FloatingButton from '@/components/ui/FloatingButton'
import { useOnboarding } from '@/hooks/useOnboarding'
import { useHideOnScrollDown } from '@/hooks/useHideOnScrollDown'
import { IconChevronRight, IconPlus, IconDatabase, IconBuilding, IconCircleCheck, IconCurrencyDollar, IconBolt, GlassDbIcon } from '@/components/Icons'
import { DB_TYPE_LABELS, formatPrice, STATUS_COLORS, STATUS_LABELS, greeting, matchesQuery, searchPattern, pluralUk, objectsWord } from '@/lib/utils'
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
  const fabHidden = useHideOnScrollDown()
  const { user, navigate } = useAppStore()
  const { databases, loading, error, loadDatabases } = useDatabases()
  useSlowLoadingToast(loading)
  // Саме перехід true→false, а не «зараз не вантажимо»: на першому кадрі
  // `loading` ще false, тож проста перевірка спрацювала б ДО запиту.
  const sawLoading = useRef(false)
  const [loadedOnce, setLoadedOnce] = useState(false)
  useEffect(() => {
    if (loading) sawLoading.current = true
    else if (sawLoading.current) setLoadedOnce(true)
  }, [loading])
  /** Порожній стан має ВЛАСНУ первинну дію («Створити першу базу»), тож
      плаваюча ховається: дві кнопки того самого призначення на екрані, де
      прокручувати нема чого, лише сперечаються за увагу.
      `loadedOnce` обовʼязковий: `useDatabases` стартує з `loading:false`, тож
      на ПЕРШОМУ кадрі список порожній ще до запиту — без цієї умови FAB
      встигав блимнути схованим і поїхати назад. Спіймав це не огляд, а
      `design-system-runtime`: він заміряв кнопку в `fab-off`, тобто 43px
      (46 × scale .94) замість 46. */
  const showEmptyCta = loadedOnce && !loading && !error && databases.length === 0
  const [search, setSearch] = useState('')

  // Cross-database property search
  const [propResults, setPropResults]     = useState<PropSearchResult[]>([])
  const [propSearching, setPropSearching] = useState(false)

  useEffect(() => { loadDatabases() }, [loadDatabases])

  // Debounced cross-db property search when query ≥ 3 chars
  useEffect(() => {
    const pattern = searchPattern(search)
    if (pattern.length < 3 || !user) { setPropResults([]); return }
    setPropSearching(true)
    const timer = setTimeout(async () => {
      try {
        // Вибірку звужуємо НАЙДОВШИМ токеном по всіх полях, за якими люди
        // шукають (не лише назва — орендар, адреса, поверх), а повний
        // багатослівний збіг доганяємо matchesQuery уже тут: порядок слів у
        // запиті не мусить впливати на результат.
        //
        // owner_id НЕ фільтруємо: у члена команди обʼєкти належать власнику
        // бази, тож звуження «свій owner_id» віддавало йому порожньо. Видимість
        // вирішує RLS — вона знає і власника, і membership.
        const like = `%${pattern}%`
        const { data } = await supabase
          .from('properties')
          .select('id, name, status, db_id, floor, tenant_name, address')
          .or([
            `name.ilike.${like}`,
            `tenant_name.ilike.${like}`,
            `address.ilike.${like}`,
            `floor.ilike.${like}`,
          ].join(','))
          .limit(40)
        setPropResults(
          (data ?? [])
            .filter(p => matchesQuery(search, p.name, p.tenant_name, p.floor, p.address))
            .slice(0, 20)
            .map(p => ({
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
    databases.filter(db => matchesQuery(search, db.name, db.address)),
  [databases, search])

  const fabRef = useRef<HTMLButtonElement>(null)
  const { isDone: fabSeen, markDone: markFabSeen } = useOnboarding('owner-fab')

  const totals = useMemo(() => ({
    dbs:      databases.length,
    props:    databases.reduce((s, d) => s + (d._property_count  ?? 0), 0),
    free:     databases.reduce((s, d) => s + (d._free_count      ?? 0), 0),
    occupied: databases.reduce((s, d) => s + (d._occupied_count  ?? 0), 0),
    income:   databases.reduce((s, d) => s + (d._monthly_income  ?? 0), 0),
    // Знімок SWR зі старою формою поля не має — половина експлуатаційних
    // просто не малюється, як і при нулі. Окремої міграції кешу не треба.
    utils:    databases.reduce((s, d) => s + (d._monthly_utils   ?? 0), 0),
  }), [databases])

  const greet = greeting()
  const showPropResults = search.length >= 3

  return (
    <div className="scr bg-purple">
      {/* Header */}
      <div className="hdr">
        <div className="hdr-av hdr-av-owner">
          {(user?.first_name ?? 'U').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 'var(--fs-call)', fontWeight: 'var(--fw-bold)' }}>prostir</div>
        </div>
        {/* Notifications live in the tab bar (with unread badge) — a header
            bell here duplicated that tab and confused users. */}
        <div className="hdr-sp" />
      </div>

      <div className="body has-fab">
        <div className="greet">{greet}, {user?.first_name}</div>
        <div className="display">Мої бази</div>

        {/* Stats */}
        <div className="stat-g">
          <div className="stat glass-s" style={{ background: 'var(--dv-blue-bg)', border: '.5px solid var(--dv-blue-bd)' }}>
            <div className="stat-ic"><IconDatabase size={16} color="var(--dv-blue)" /></div>
            <div className="stat-n">{totals.dbs}</div>
            <div className="stat-l">{pluralUk(totals.dbs, 'База', 'Бази', 'Баз')}</div>
          </div>
          <div className="stat glass-s" style={{ background: 'var(--dv-purple-bg)', border: '.5px solid var(--dv-purple-bd)' }}>
            <div className="stat-ic"><IconBuilding size={16} color="var(--violet)" /></div>
            <div className="stat-n">{totals.props}</div>
            <div className="stat-l">{objectsWord(totals.props)}</div>
          </div>
          <div className="stat glass-s" style={{ background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)' }}>
            <div className="stat-ic"><IconCircleCheck size={16} color="var(--ok-fg)" /></div>
            <div className="stat-n" style={{ color: 'var(--ok-fg)' }}>{totals.free}</div>
            <div className="stat-l" style={{ color: 'var(--ok-fg)' }}>Вільно</div>
          </div>
          {totals.income > 0 && (
            /* Дві грошові цифри в ОДНІЙ плитці, а не двома — рішення власника:
               окремий ряд коштував би ~70px висоти, а кожні додані пікселі
               зсувають список нижче в градієнт, який світлішає донизу, і
               забирають контраст у карток під блоком. */
            <div
              className={`stat glass-s stat-split${totals.utils > 0 ? '' : ' one'}`}
              style={{ gridColumn: '1 / -1', background: 'var(--ok-bg)', border: '.5px solid var(--ok-bd)' }}
            >
              <div className="stat-half">
                <div className="stat-ic"><IconCurrencyDollar size={16} color="var(--ok-fg)" /></div>
                <div className="stat-n" style={{ color: 'var(--ok-fg)', fontSize: 'var(--fs-lead)' }}>
                  {formatPrice(totals.income, user?.currency)}
                </div>
                <div className="stat-l">Оренда · зайнято {totals.occupied}</div>
              </div>
              {totals.utils > 0 && (
                <div className="stat-half">
                  <div className="stat-ic"><IconBolt size={16} color="var(--warn-fg)" /></div>
                  <div className="stat-n" style={{ color: 'var(--warn-fg)', fontSize: 'var(--fs-lead)' }}>
                    {formatPrice(totals.utils, user?.currency)}
                  </div>
                  <div className="stat-l">Експлуатаційні</div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Search */}
        <SearchBar value={search} onChange={setSearch} placeholder="Пошук бази або обʼєкту..." />

        {/* Cross-database property search results */}
        {showPropResults && (
          <div style={{ marginBottom: 8 }}>
            <div className="over">
              <span>Обʼєкти по всіх базах</span>
              {propSearching
                ? <span className="over-a">…</span>
                : <span className="over-a">{propResults.length} знайдено</span>
              }
            </div>
            {propSearching ? (
              <div style={{ padding: '8px 16px' }}>
                <div className="skel" style={{ height: 44, borderRadius: 'var(--r-xs)' }} />
              </div>
            ) : propResults.length === 0 ? (
              <div style={{ padding: '8px 16px', fontSize: 'var(--fs-foot)', color: 'var(--t3)' }}>Нічого не знайдено</div>
            ) : (
              <div className="list">
                {propResults.map(p => {
                  const badge = STATUS_COLORS[p.status]
                  return (
                    <div
                      key={p.id}
                      className="row glass-s"
                      onClick={() => { hapticImpact('light'); navigate('property-detail', { propertyId: p.id, dbId: p.db_id }) }}
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
          <SkeletonLoader rowHeight={88} />
        ) : error && databases.length === 0 ? (
          <RetryState subtitle={error} onRetry={loadDatabases} />
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
            <div className="empty-s">Створи першу базу обʼєктів</div>
            <button
              className="mbtn success mbtn-flow"
              onClick={() => { hapticImpact('light'); navigate('create-db') }}
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
                onClick={() => { hapticImpact('light'); navigate('db-objects', { dbId: db.id }) }}
              >
                <GlassDbIcon type={db.type} color={db.color} size={32} />
                <div className="row-mn">
                  <div className="row-t">{db.name}</div>
                  <div className="row-s">
                    <span>{DB_TYPE_LABELS[db.type]}</span>
                    {db.address && <><span>·</span><span>{db.address}</span></>}
                  </div>
                  {(db._monthly_income ?? 0) > 0 && (
                    <div style={{ fontSize: 'var(--fs-cap2)', color: 'var(--ok-fg)', marginTop: 2, fontWeight: 'var(--fw-semi)' }}>
                      {formatPrice(db._monthly_income!, user?.currency)}/міс
                    </div>
                  )}
                </div>
                <div className="row-r">
                  {db._member && (
                    <span className="bdg bdg-info">Команда</span>
                  )}
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
      </div>

      <FloatingButton
        ref={fabRef}
        variant="create"
        compact
        raised
        hidden={fabHidden || showEmptyCta}
        icon={<IconPlus size={14} />}
        label="Створити базу"
        onClick={() => { hapticImpact('light'); navigate('create-db') }}
      />

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
