'use client'

import { STATUS_LABELS, STATUS_BADGE_CLS } from '@/lib/utils'
import type { PropertyStatus } from '@/types'

interface StatusBadgeProps {
  status: PropertyStatus
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span className={`bdg ${STATUS_BADGE_CLS[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

interface FreshnessBadgeProps {
  updatedAt: string
}

export function FreshnessBadge({ updatedAt }: FreshnessBadgeProps) {
  const days = Math.floor((Date.now() - new Date(updatedAt).getTime()) / 86400000)
  let label = 'сьогодні'
  let cls = 'fresh'

  if (days === 0) { label = 'сьогодні'; cls = 'fresh' }
  else if (days <= 3) { label = `${days}д тому`; cls = 'fresh' }
  else if (days <= 7) { label = `${days}д тому`; cls = 'stale' }
  else { label = `${days}д тому`; cls = 'old' }

  return (
    <span className={`fresh ${cls === 'fresh' ? '' : cls}`}>
      <span className="fdot" />
      {label}
    </span>
  )
}
