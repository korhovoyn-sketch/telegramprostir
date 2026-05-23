'use client'

interface MainButtonProps {
  label: string
  onClick?: () => void
  variant?: 'default' | 'success' | 'danger' | 'disabled'
  loading?: boolean
  icon?: React.ReactNode
}

export default function MainButton({ label, onClick, variant = 'default', loading, icon }: MainButtonProps) {
  const cls = [
    'mbtn',
    variant === 'success' ? 'success' : '',
    variant === 'danger' ? 'danger' : '',
    variant === 'disabled' || loading ? 'disabled' : '',
    loading ? 'is-loading' : '',
  ].filter(Boolean).join(' ')

  return (
    <button className={cls} onClick={onClick} disabled={variant === 'disabled' || loading}>
      {!loading && icon}
      {!loading && label}
    </button>
  )
}
