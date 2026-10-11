'use client'

import { useCallback, useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'
import { useAppStore } from '@/store/appStore'
import { GlassDbIcon, IconKey, IconChevronRight } from '@/components/Icons'
import { DB_TYPE_LABELS } from '@/lib/utils'
import { tr } from '@/lib/i18n'
import type { DatabaseType } from '@/types'

/**
 * «ІНШІ ДОСТУПИ» — те, що людина МАЄ, але домашній екран її ролі не показує.
 *
 * Таббар будує вкладки за `users.role`, а кожна домашня показує лише «свій»
 * вид доступу: власник — бази (власні й команди), рієлтор — підписки й
 * команду, гість — запрошення. Доступи ж від ролі не залежать (RLS дивиться
 * на членство), і людина цілком законно буває кількома одразу: власник, що
 * сам орендує офіс; гість, якого взяли в команду; власник, якому колега
 * передав свою базу. Deep link приводив такого користувача на потрібний екран
 * РІВНО ОДИН РАЗ — а після виходу дійти назад було нікуди: доступ лишався на
 * сервері, а в інтерфейсі зникав. Той самий клас уже ловили на редакторі з
 * роллю рієлтора (див. `RealtorDashboardScreen`); тут він закритий для всіх
 * поєднань одним компонентом, а не латкою на кожному екрані окремо.
 *
 * `show` — лише те, чого хост НЕ малює сам: інакше одна база зʼявилась би на
 * екрані двічі.
 */
export type AccessKind = 'subscriptions' | 'guest' | 'team'

interface Item {
  key: string
  title: string
  caption: string
  dbType?: DatabaseType
  dbColor?: string
  isProperty?: boolean
  go: () => void
}

type Embedded<T> = T | T[] | null | undefined
const one = <T,>(v: Embedded<T>): T | null => (Array.isArray(v) ? v[0] ?? null : v ?? null)

interface DbLite { id: string; name: string; type: DatabaseType; color: string }

/** Таблиці ще немає (бекенд без міграції) — цей вид доступу просто вимкнений. */
const isMissingTable = (e: { code?: string } | null) => e?.code === '42P01'

export default function OtherAccess({ show, onCount }: { show: AccessKind[]; onCount?: (n: number) => void }) {
  const user = useAppStore((s) => s.user)
  const navigate = useAppStore((s) => s.navigate)
  const [items, setItems] = useState<Item[]>([])
  const [failed, setFailed] = useState(false)
  // Лічильник для хоста — лише ПІСЛЯ відповіді: до неї «0» означає «ще не
  // знаю», а хост, що на нуль малює «нічого немає», блимнув би неправдою.
  const [loaded, setLoaded] = useState(false)
  const key = show.join(',')

  const load = useCallback(async () => {
    if (!user) return
    setFailed(false)
    const want = new Set(key.split(',') as AccessKind[])
    const [subs, guest, team] = await Promise.all([
      want.has('subscriptions')
        ? supabase.from('realtor_subscriptions')
          .select('id,db_id,database:databases(id,name,type,color)')
          .eq('realtor_id', user.id)
        : null,
      want.has('guest')
        ? supabase.from('guest_links')
          .select('id,property_id,db_id,label,property:properties(id,db_id,name),database:databases(id,name,type,color)')
          .eq('guest_user_id', user.id)
          .eq('status', 'active')
        : null,
      want.has('team')
        ? supabase.from('db_members')
          .select('db_id,database:databases(id,name,type,color)')
          .eq('user_id', user.id)
          .eq('status', 'active')
          .eq('role', 'editor')
        : null,
    ])

    const next: Item[] = []
    let err = false

    if (subs) {
      if (subs.error) err = err || !isMissingTable(subs.error)
      for (const r of (subs.data ?? []) as unknown as Array<{ id: string; database: Embedded<DbLite> }>) {
        const d = one(r.database)
        if (!d) continue
        next.push({
          key: `s:${r.id}`, title: d.name, dbType: d.type, dbColor: d.color,
          caption: tr('Спільна база · {0}', DB_TYPE_LABELS()[d.type] ?? d.type),
          go: () => navigate('realtor-database', { dbId: d.id }),
        })
      }
    }

    if (team) {
      if (team.error) err = err || !isMissingTable(team.error)
      const ids: string[] = []
      for (const r of (team.data ?? []) as unknown as Array<{ db_id: string; database: Embedded<DbLite> }>) {
        const d = one(r.database)
        if (!d) continue
        ids.push(d.id)
        next.push({
          key: `t:${d.id}`, title: d.name, dbType: d.type, dbColor: d.color,
          caption: tr('Команда · {0}', DB_TYPE_LABELS()[d.type] ?? d.type),
          go: () => navigate('db-objects', { dbId: d.id }),
        })
      }
      // Права редагування на екрані бази беруться з `memberDbIds` — кладемо
      // їх одразу, щоб перший кадр уже мав кнопки (див. `useMemberAccess`).
      if (ids.length) {
        const cur = useAppStore.getState().memberDbIds
        const merged = [...new Set([...cur, ...ids])]
        if (merged.length !== cur.length) useAppStore.getState().setMemberDbIds(merged)
      }
    }

    if (guest) {
      if (guest.error) err = err || !isMissingTable(guest.error)
      type Row = {
        id: string; property_id: string | null; db_id: string | null; label: string | null
        property: Embedded<{ id: string; db_id: string; name: string }>
        database: Embedded<DbLite>
      }
      for (const r of (guest.data ?? []) as unknown as Row[]) {
        const p = one(r.property)
        const d = one(r.database)
        if (r.property_id && p) {
          next.push({
            key: `g:${r.id}`, title: p.name, isProperty: true,
            caption: r.label ? tr('Гостьовий доступ · {0}', r.label) : tr('Гостьовий доступ'),
            go: () => navigate('property-detail', { propertyId: p.id, dbId: p.db_id }),
          })
        } else if (r.db_id && d) {
          next.push({
            key: `g:${r.id}`, title: d.name, dbType: d.type, dbColor: d.color,
            caption: r.label ? tr('Гостьовий доступ · {0}', r.label) : tr('Гостьовий доступ'),
            go: () => navigate('db-objects', { dbId: d.id }),
          })
        }
      }
    }

    setItems(next)
    setFailed(err)
    setLoaded(true)
  }, [user, key, navigate])

  useEffect(() => { void load() }, [load])
  // Хосту, чий порожній стан інакше казав би «нічого немає», хоча доступи є.
  useEffect(() => { if (loaded) onCount?.(items.length) }, [loaded, items.length, onCount])

  if (items.length === 0 && !failed) return null

  return (
    <section aria-label={tr('Інші доступи')} className="other-access">
      <div className="over"><span>{tr('Інші доступи')}</span></div>
      <div className="list">
        {items.map((it) => (
          <button key={it.key} type="button" className="row glass-s" onClick={it.go}>
            {it.isProperty
              ? <span className="row-ic oa-key"><IconKey size={16} color="var(--ok-bright)" /></span>
              : <GlassDbIcon type={it.dbType} color={it.dbColor} size={32} />}
            <div className="row-mn">
              <div className="row-t">{it.title}</div>
              <div className="row-s"><span>{it.caption}</span></div>
            </div>
            <IconChevronRight size={14} color="var(--t4)" />
          </button>
        ))}
        {failed && (
          <button type="button" className="row glass-s" onClick={() => void load()}>
            <div className="row-mn">
              <div className="row-t">{tr('Не вдалося завантажити інші доступи')}</div>
              <div className="row-s"><span>{tr('Натисніть, щоб повторити')}</span></div>
            </div>
          </button>
        )}
      </div>
    </section>
  )
}
