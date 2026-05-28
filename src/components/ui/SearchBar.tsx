'use client'

import { IconSearch, IconX } from '@/components/Icons'

interface SearchBarProps {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}

export default function SearchBar({ value, onChange, placeholder = 'Пошук...' }: SearchBarProps) {
  return (
    <div className="search-inline">
      <IconSearch size={15} color="var(--t3)" />
      <input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {value && (
        <button
          onClick={() => onChange('')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--t3)', display: 'flex' }}
        >
          <IconX size={14} />
        </button>
      )}
    </div>
  )
}
