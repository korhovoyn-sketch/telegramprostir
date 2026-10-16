'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useAppSlice } from '@/store/appStore'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import {
  IconCalendar, IconClock, IconCurrencyDollar, IconEdit, IconFile, IconLayers, IconPhoto,
  IconPlus, IconTrash, IconUser, IconActivity,
} from '@/components/Icons'
import { supabase } from '@/lib/supabase'
import { daysSince, humanizeDbError, localDay } from '@/lib/utils'
import { describeActivity, type ActivityIcon, type ActivityTone } from '@/lib/activity'
import { locale, tr } from '@/lib/i18n'
import type { DbActivity } from '@/types'

const ACTIVITY_COLUMNS = 'id,db_id,property_id,property_name,actor_id,actor_name,kind,details,created_at'

/** Порція журналу. Журнал росте без меж — повний список на вході був би
 *  найдовшим запитом застосунку, а читають зазвичай останні дні. */
const PAGE = 50

const ICONS: Record<ActivityIcon, typeof IconPlus> = {
  plus: IconPlus, trash: IconTrash, edit: IconEdit, move: IconLayers, user: IconUser,
  status: IconActivity, money: IconCurrencyDollar, calendar: IconCalendar, file: IconFile, photo: IconPhoto,
}
const TONE: Record<ActivityTone, string> = {
  ok: 'var(--ok)', warn: 'var(--warn)', err: 'var(--err)', info: 'var(--info)', plain: 'var(--t2)',
}

/** Таблиці немає (073 не накочена) — розділ показує пояснення, а не помилку. */
const isMissingTable = (e: { code?: string; message?: string } | null): boolean =>
  e?.code === 'PGRST205' || e?.code === '42P01' || /db_activity/i.test(e?.message ?? '')

/**
 * ЖУРНАЛ ЗМІН БАЗИ (073): хто що зробив з обʼєктами й грошима.
 *
 * Екран ЛИШЕ ЧИТАЄ. Події пишуть тригери на сервері — тобто журнал не можна
 * «забути оновити» з якогось шляху клієнта, і його не можна підправити.
 * Видно власнику і редакторам команди (так само, як архів оренд).
 */
export default function DbActivityScreen() {
  const { screenParams, back, databases, user } = useAppSlice('screenParams', 'back', 'databases', 'user')
  const dbId = screenParams.dbId as string | undefined
  const db = databases.find(d => d.id === dbId)

  const [rows, setRows] = useState<DbActivity[]>([])
  const [loading, setLoading] = useState(true)
  const [more, setMore] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [unavailable, setUnavailable] = useState(false)
  // Збій ≠ «змін не було»: порожній журнал — впевнена відповідь, і малювати
  // її після обриву звʼязку означало б неправду саме про те, хто що робив.
  const [error, setError] = useState<string | null>(null)

  const loadPage = useCallback(async (from: number) => {
    if (!dbId) return
    const { data, error: err } = await supabase
      .from('db_activity').select(ACTIVITY_COLUMNS)
      .eq('db_id', dbId)
      .order('created_at', { ascending: false }).order('id', { ascending: false })
      .range(from, from + PAGE - 1)
    if (err) {
      if (isMissingTable(err)) { setUnavailable(true); setRows([]); setMore(false); return }
      throw err
    }
    const page = (data ?? []) as DbActivity[]
    setRows(prev => (from === 0 ? page : [...prev, ...page]))
    setMore(page.length === PAGE)
  }, [dbId])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try { await loadPage(0) } catch (e) { setError(humanizeDbError(e)) } finally { setLoading(false) }
  }, [loadPage])

  useEffect(() => { void load() }, [load])

  async function loadMore() {
    setLoadingMore(true)
    try { await loadPage(rows.length) } catch (e) { setError(humanizeDbError(e)) } finally { setLoadingMore(false) }
  }

  const groups = useMemo(() => {
    const out: { label: string; items: DbActivity[] }[] = []
    for (const a of rows) {
      const ago = daysSince(a.created_at)
      const label = ago === 0 ? tr('Сьогодні')
        : ago === 1 ? tr('Вчора')
        : new Date(`${localDay(a.created_at)}T00:00:00`).toLocaleDateString(locale(), { day: 'numeric', month: 'long', year: 'numeric' })
      const last = out[out.length - 1]
      if (last?.label === label) last.items.push(a)
      else out.push({ label, items: [a] })
    }
    return out
  }, [rows])

  const timeOf = (iso: string) => new Date(iso).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' })

  return (
    <div className="scr bg-teal">
      <Header title={tr('Журнал змін')} subtitle={db?.name} onBack={back} />

      <div className="body">
        {loading && rows.length === 0 ? (
          <SkeletonList count={4} rowHeight={64} />
        ) : error && rows.length === 0 ? (
          <RetryState subtitle={error} onRetry={() => void load()} />
        ) : unavailable ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic"><IconClock size={34} color="var(--t3)" /></div>
            <div className="empty-h">{tr('Журнал ще не увімкнено')}</div>
            <div className="empty-s">{tr('Розділ зʼявиться після оновлення бази даних.')}</div>
          </div>
        ) : rows.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic"><IconClock size={34} color="var(--t3)" /></div>
            <div className="empty-h">{tr('Змін ще не було')}</div>
            <div className="empty-s">{tr('Тут зʼявляться дії з обʼєктами й платежами — хто й коли їх зробив.')}</div>
          </div>
        ) : (
          <>
            {groups.map(g => (
              <div key={g.label}>
                <div className="over"><span>{g.label}</span></div>
                <div className="pay-card act-list">
                  {g.items.map(a => {
                    const v = describeActivity(a, user?.currency)
                    const Icon = ICONS[v.icon]
                    const who = a.actor_id && a.actor_id === user?.id ? tr('Ви') : (a.actor_name || tr('Невідомо'))
                    return (
                      <div key={a.id} className="act-row">
                        <span className="act-ic" style={{ color: TONE[v.tone] }}><Icon size={16} /></span>
                        <span className="act-main">
                          <span className="act-t">{v.title}</span>
                          <span className="act-s">
                            {[a.property_name, who, timeOf(a.created_at)].filter(Boolean).join(' · ')}
                          </span>
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
            {more && (
              <button
                type="button"
                className={`act-more ${loadingMore ? 'is-loading' : ''}`}
                onClick={() => void loadMore()}
                disabled={loadingMore}
                aria-busy={loadingMore}
              >
                {tr('Показати ще')}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  )
}
