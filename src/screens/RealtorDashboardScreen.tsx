'use client'

import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '@/store/appStore'
import RetryState from '@/components/ui/RetryState'
import { supabase } from '@/lib/supabase'
import TabBar from '@/components/ui/TabBar'
import SearchBar from '@/components/ui/SearchBar'
import SkeletonLoader from '@/components/ui/SkeletonLoader'
import { IconChevronRight, GlassDbIcon } from '@/components/Icons'
import { DB_TYPE_LABELS, greeting, humanizeDbError, matchesQuery, pluralUk, objectsWord } from '@/lib/utils'
import type { Database, DbMember, RealtorSubscription } from '@/types'
import CoachMark from '@/components/ui/CoachMark'
import { useOnboarding } from '@/hooks/useOnboarding'
import { useSlowLoadingToast } from '@/hooks/useSlowLoadingToast'

export default function RealtorDashboardScreen() {
  const { user, navigate, showToast } = useAppStore()
  const setMemberDbIds = useAppStore(st => st.setMemberDbIds)
  const [subscriptions, setSubscriptions] = useState<RealtorSubscription[]>([])
  // Бази, куди user запрошений як редактор команди (db_members, migration 041) —
  // ОКРЕМО від realtor_subscriptions (звичайний перегляд по share-лінку).
  // Без цього списку редактор із role:'realtor' бачив свою базу РІВНО один раз:
  // deep link team_<token> примусово веде на db-list (де memberDbIds рахується
  // правильно), але «Бази» в таббарі для role:'realtor' завжди веде сюди — і
  // сюди-код ніколи не питав db_members, тож на будь-якому наступному вході
  // isOwner-шлюзи на db-objects/property-detail мовчки гасли (memberDbIds
  // лишався порожнім), хоч бекенд і далі дозволяв повний запис.
  const [memberDatabases, setMemberDatabases] = useState<Database[]>([])
  const [loading, setLoading] = useState(true)
  useSlowLoadingToast(loading)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [propertyCount, setPropertyCount] = useState<number>(0)
  const qrBtnRef = useRef<HTMLButtonElement>(null)
  const { isDone: qrSeen, markDone: markQrSeen } = useOnboarding('realtor-qr')

  async function load() {
    if (!user) return
    setLoading(true)
    setLoadError(null)
    try {
      const [{ data, error }, memberRes] = await Promise.all([
        supabase
          .from('realtor_subscriptions')
          // Дашборд показує лише назву й адресу бази — токен шарингу йому тут
          // не потрібен. Рієлтор дістає його свідомо в `RealtorDatabaseScreen`,
          // коли справді ділиться; віддавати його ще й списком підписок означає
          // роздавати доступ ширше, ніж вимагає екран.
          .select('id,realtor_id,db_id,created_at,database:databases(id,name,type,color,address)')
          .eq('realtor_id', user.id)
          .order('created_at', { ascending: false }),
        supabase
          .from('db_members')
          // Явні колонки: `*` віддавав РЕДАКТОРОВІ `databases.share_token`
          // власника. Шаринг бази — owner-only (див. Team editors у CLAUDE.md),
          // тож редактор із цим токеном роздавав би публічні /v-лінки на чужу
          // базу, і відкликання його membership цього б не скасувало.
          .select('db_id, database:databases(id,owner_id,name,type,color,address)')
          .eq('user_id', user.id)
          .eq('status', 'active')
          .eq('role', 'editor'),
      ])
      if (error) throw error
      setSubscriptions((data ?? []) as unknown as RealtorSubscription[])

      // На бекенді без міграції 041 запит по db_members падає — команда тоді
      // просто вимкнена (той самий толерантний патерн, що в useDatabases.ts).
      // PostgREST embed типізується як масив незалежно від кардинальності —
      // беремо перший елемент.
      type MemberRow = Pick<DbMember, 'db_id'> & { database?: Database | Database[] | null }
      const memberRows = memberRes.error ? [] : ((memberRes.data ?? []) as unknown as MemberRow[])
      const memberDbs = memberRows
        .map((r) => (Array.isArray(r.database) ? r.database[0] : r.database))
        .filter((d): d is Database => Boolean(d))
      setMemberDatabases(memberDbs)
      setMemberDbIds(memberDbs.map((d) => d.id))

      // Load real property count across all subscribed AND member databases
      const subDbIds = (data ?? []).map((s) => (s as unknown as RealtorSubscription & { database?: { id: string } }).database?.id).filter((id): id is string => Boolean(id))
      const dbIds = [...subDbIds, ...memberDbs.map((d) => d.id)]
      if (dbIds.length > 0) {
        const { count } = await supabase
          .from('properties')
          .select('id', { count: 'exact', head: true })
          .in('db_id', dbIds)
        setPropertyCount(count ?? 0)
      }
    } catch (e) {
      const msg = humanizeDbError(e)
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
    matchesQuery(search, s.database?.name, s.database?.address)
  )
  const filteredMemberDbs = memberDatabases.filter((d) =>
    matchesQuery(search, d.name, d.address)
  )

  const greet = greeting()

  return (
    <div className="scr bg-cyan">
      <div className="hdr">
        <div className="hdr-av hdr-av-realtor">
          {(user?.first_name ?? 'R').charAt(0).toUpperCase()}
        </div>
        <div className="hdr-t">
          <div style={{ fontSize: 'var(--fs-call)', fontWeight: 'var(--fw-bold)' }}>prostir</div>
        </div>
        {/* Notifications live in the tab bar (with unread badge) — a header
            bell here duplicated that tab and confused users. */}
        <div className="hdr-sp" />
      </div>

      <div className="body has-tabbar-btn">
        <div className="greet">{greet}, {user?.first_name}</div>
        <div className="display">Робочі бази</div>

        <div className="stat-g cols-2">
          <div className="stat glass-s">
            <div className="stat-n">{subscriptions.length + memberDatabases.length}</div>
            <div className="stat-l">{pluralUk(subscriptions.length + memberDatabases.length, 'База', 'Бази', 'Баз')}</div>
          </div>
          <div className="stat glass-s">
            <div className="stat-n">{propertyCount}</div>
            <div className="stat-l">{objectsWord(propertyCount)}</div>
          </div>
        </div>

        <SearchBar value={search} onChange={setSearch} placeholder="Пошук бази..." />

        {loading ? (
          <SkeletonLoader rowHeight={88} />
        ) : loadError && subscriptions.length === 0 && memberDatabases.length === 0 ? (
          <RetryState subtitle={loadError} onRetry={load} />
        ) : filtered.length === 0 && filteredMemberDbs.length === 0 ? (
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
            {/* Бази, де user — редактор команди (db_members): повний CRUD,
                тож ведуть у db-objects, не в read-only realtor-database. */}
            {filteredMemberDbs.map((db) => (
              <div
                key={db.id}
                className="row glass-s"
                onClick={() => navigate('db-objects', { dbId: db.id })}
              >
                <GlassDbIcon type={db.type} color={db.color} size={32} />
                <div className="row-mn">
                  <div className="row-t">{db.name}</div>
                  <div className="row-s">
                    <span>{DB_TYPE_LABELS[db.type]}</span>
                  </div>
                </div>
                <span className="bdg bdg-info">Команда</span>
                <IconChevronRight size={14} color="var(--t4)" />
              </div>
            ))}
            {filtered.map((sub) => {
              const db = sub.database as Database
              if (!db) return null
              return (
                <div
                  key={sub.id}
                  className="row glass-s"
                  onClick={() => navigate('realtor-database', { dbId: db.id })}
                >
                  <GlassDbIcon type={db.type} color={db.color} size={32} />
                  <div className="row-mn">
                    <div className="row-t">{db.name}</div>
                    <div className="row-s">
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

      <button ref={qrBtnRef} className="mbtn" onClick={() => navigate('qr-scanner')} style={{ bottom: 'calc(92px + var(--safe-bottom))' }}>
        Додати базу за QR
      </button>

      {!qrSeen && !loading && (
        <CoachMark
          title="Підключіться до бази"
          body="Попросіть власника надіслати QR-код або посилання, потім натисніть цю кнопку."
          targetRef={qrBtnRef}
          placement="above"
          onDone={markQrSeen}
        />
      )}

      <TabBar />
    </div>
  )
}
