'use client'
import { hapticImpact } from '@/lib/telegram'

interface ToggleProps {
  value: boolean
  onChange: (v: boolean) => void
}

export default function Toggle({ value, onChange }: ToggleProps) {
  return (
    <div
      className={`tgl ${value ? 'on' : ''}`}
      onClick={() => { hapticImpact('medium'); onChange(!value) }}
      role="switch"
      aria-checked={value}
    >
      <div className="tgl-th" />
    </div>
  )
}
