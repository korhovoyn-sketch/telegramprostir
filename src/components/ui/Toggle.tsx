'use client'

interface ToggleProps {
  value: boolean
  onChange: (v: boolean) => void
}

export default function Toggle({ value, onChange }: ToggleProps) {
  return (
    <div
      className={`tgl ${value ? 'on' : ''}`}
      onClick={() => { window.Telegram?.WebApp?.HapticFeedback?.impactOccurred('medium'); onChange(!value) }}
      role="switch"
      aria-checked={value}
    >
      <div className="tgl-th" />
    </div>
  )
}
