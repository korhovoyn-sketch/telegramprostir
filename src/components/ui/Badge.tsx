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
