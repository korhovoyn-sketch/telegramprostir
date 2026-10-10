'use client'

import { useEffect, useMemo, useState } from 'react'
import { useAppStore } from '@/store/appStore'
import { useTenancies } from '@/hooks/useTenancies'
import { useDbType } from '@/hooks/useDbType'
import Header from '@/components/ui/Header'
import RetryState from '@/components/ui/RetryState'
import SearchBar from '@/components/ui/SearchBar'
import { SkeletonList } from '@/components/ui/SkeletonLoader'
import { IconArchive, IconUser, IconClock, IconCurrencyDollar } from '@/components/Icons'
import { formatPrice, matchesQuery, calcRentUtils, pluralUk } from '@/lib/utils'
import { locale, tr } from '@/lib/i18n'
import type { Tenancy } from '@/types'

/**
 * АРХІВ ПРАВОВІДНОСИН — історія оренд ОДНІЄЇ бази.
 *
 * Живе в базі, а не на картці обʼєкта (рішення власника): питання «з ким я мав
 * справу» ставлять до всього портфеля, а не до одного приміщення, і обʼєкт
 * може бути вже видалений — його оренди тут лишаються (`property_id` стає
 * NULL, назва заморожена в самому рядку).
 *
 * Екран ЛИШЕ ЧИТАЄ. Рядки створює й закриває тригер `trg_sync_tenancy` — тобто
 * архів не можна «забути оновити» з якогось шляху клієнта.
 */
export default function TenancyArchiveScreen() {
  const { screenParams, back, databases, user } = useAppStore()
  const dbId = screenParams.dbId as string | undefined

  const { tenancies, loading, unavailable, error, loadTenancies } = useTenancies(dbId)
  // Паркінг рахує експлуатаційні ПЛАСКОЮ сумою, а не ставкою × площа. Тип бази
  // тут потрібен саме для цього — той самий гейт, що на картці й у деталі.
  const { isParking } = useDbType(dbId)

  const [query, setQuery] = useState('')

  useEffect(() => {
    void loadTenancies()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dbId])

  const db = databases.find(d => d.id === dbId)
  const currency = user?.currency || 'USD'

  const filtered = useMemo(
    () => tenancies.filter(t => matchesQuery(query, t.property_name, t.tenant_name, t.landlord_name)),
    [tenancies, query],
  )

  const closedCount = tenancies.filter(t => t.ended_at).length

  const fmtDay = (iso: string) => new Date(iso).toLocaleDateString(locale(), {
    day: 'numeric', month: 'short', year: 'numeric',
  })

  // Тривалість ФАКТИЧНОГО періоду — від дії до дії. Договірні дати показуємо
  // окремим рядком, бо вони необовʼязкові й можуть із фактичними не збігатись.
  const durationLabel = (t: Tenancy): string => {
    const from = new Date(t.started_at).getTime()
    const to = t.ended_at ? new Date(t.ended_at).getTime() : Date.now()
    const days = Math.max(0, Math.round((to - from) / 86_400_000))
    if (days < 31) return `${days} ${pluralUk(days, tr('день'), tr('дні'), tr('днів'))}`
    const months = Math.round(days / 30.44)
    return `${months} ${pluralUk(months, tr('місяць'), tr('місяці'), tr('місяців'))}`
  }

  const renderCard = (t: Tenancy) => {
    const open = !t.ended_at
    const { total } = calcRentUtils(
      t.area_useful, t.area_total, t.rent_rate, t.rent_type, t.utilities_rate, t.area_basis, isParking,
    )
    const paid = t._paid_total ?? 0
    return (
      <div key={t.id} className="glass-s acc-card">
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <div className="acc-av" style={{ background: open ? 'var(--ok-bg)' : 'var(--glass-2)' }}>
            {open ? <IconUser size={16} color="var(--ok)" /> : <IconArchive size={16} color="var(--t3)" />}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <span className="acc-name">{t.tenant_name || tr('Без імені')}</span>
              <span
                className="acc-badge"
                style={open
                  ? { background: 'var(--ok-bg)', color: 'var(--ok)' }
                  : { background: 'var(--glass-2)', color: 'var(--t2)' }}
              >
                {open ? tr('Триває') : tr('Завершено')}
              </span>
            </div>
            <div className="acc-name ten-prop">{t.property_name}</div>
            <div className="acc-meta ten-when">
              <IconClock size={12} color="var(--t3)" />
              {t.ended_at
                ? tr('{0} — {1} · {2}', fmtDay(t.started_at), fmtDay(t.ended_at), durationLabel(t))
                : tr('з {0} · {1}', fmtDay(t.started_at), durationLabel(t))}
            </div>
            {t.landlord_name && (
              <div className="acc-meta ten-ll">
                {tr('Орендодавець: {0}', t.landlord_name)}
              </div>
            )}
            <div className="ten-sums">
              {total > 0 && (
                <span className="ten-sum">
                  {tr('Ставка')}<b>{formatPrice(total, t.currency || currency)}{tr('/міс')}</b>
                </span>
              )}
              {/* Платежі беруться ПЕРІОДОМ, не ключем: `due_date` у
                  `[started_at, ended_at)`. Нуль підтверджених — це теж
                  відповідь, тож блок малюється навіть із нулем. */}
              <span className="ten-sum ok">
                <IconCurrencyDollar size={12} color="var(--ok-fg)" />
                {tr('Отримано')}<b>{formatPrice(paid, t.currency || currency)}</b>
              </span>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="scr bg-teal">
      <Header
        title={tr('Архів оренд')}
        subtitle={db?.name}
        onBack={back}
      />

      <div className="body">
        {!unavailable && tenancies.length > 0 && (
          <SearchBar value={query} onChange={setQuery} placeholder={tr('Орендар або обʼєкт...')} />
        )}

        {loading && tenancies.length === 0 ? (
          <SkeletonList count={3} rowHeight={118} />
        ) : error && tenancies.length === 0 ? (
          <RetryState subtitle={error} onRetry={() => void loadTenancies(dbId)} />
        ) : unavailable ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic"><IconArchive size={34} color="var(--t3)" /></div>
            <div className="empty-h">{tr('Архів ще не увімкнено')}</div>
            <div className="empty-s">{tr('Розділ зʼявиться після оновлення бази даних.')}</div>
          </div>
        ) : tenancies.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 48 }}>
            <div className="empty-ic"><IconArchive size={34} color="var(--t3)" /></div>
            <div className="empty-h">{tr('Оренд ще не було')}</div>
            <div className="empty-s">{tr('Щойно ви здасте обʼєкт, тут зʼявиться картка правовідносин — і залишиться після звільнення.')}</div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ paddingTop: 32 }}>
            <div className="empty-h">{tr('Нічого не знайдено')}</div>
            <div className="empty-s">{tr('Спробуйте іншу назву обʼєкта або імʼя орендаря.')}</div>
          </div>
        ) : (
          <>
            <div className="over"><span>{tr('{0} у списку · {1} завершено', filtered.length, closedCount)}</span></div>
            <div style={{ paddingTop: 2 }}>{filtered.map(renderCard)}</div>
          </>
        )}
      </div>
    </div>
  )
}
