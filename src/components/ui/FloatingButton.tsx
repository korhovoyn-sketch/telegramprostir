'use client'

const VARIANTS = {
  success: {
    background: 'rgba(74,219,122,.18)',
    border: '.5px solid rgba(74,219,122,.42)',
    boxShadow: '0 4px 24px rgba(74,219,122,.22), inset 0 1px 0 rgba(255,255,255,.18)',
  },
  danger: {
    background: 'rgba(255,107,97,.16)',
    border: '.5px solid rgba(255,107,97,.38)',
    boxShadow: '0 4px 24px rgba(255,107,97,.18), inset 0 1px 0 rgba(255,255,255,.15)',
  },
  info: {
    background: 'rgba(42,171,238,.15)',
    border: '.5px solid rgba(42,171,238,.35)',
    boxShadow: '0 4px 24px rgba(42,171,238,.18), inset 0 1px 0 rgba(255,255,255,.18)',
  },
} as const

interface FloatingButtonProps {
  variant: keyof typeof VARIANTS
  icon: React.ReactNode
  label: string
  onClick: () => void
}

export default function FloatingButton({ variant, icon, label, onClick }: FloatingButtonProps) {
  return (
    <button
      style={{
        position: 'absolute', bottom: 'calc(14px + var(--safe-bottom))',
        left: '50%', transform: 'translateX(-50%)',
        height: 'var(--btn-h)', padding: '0 32px', minWidth: 200,
        borderRadius: 'var(--r-pill)', whiteSpace: 'nowrap',
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        fontSize: 15, fontWeight: 600, color: '#fff', cursor: 'pointer',
        backdropFilter: 'blur(16px) saturate(180%)',
        WebkitBackdropFilter: 'blur(16px) saturate(180%)',
        zIndex: 20,
        ...VARIANTS[variant],
      }}
      onClick={onClick}
    >
      {icon}
      {label}
    </button>
  )
}
