'use client'

interface ProxMascotProps {
  mood?: 'happy' | 'sad' | 'neutral'
  size?: number
}

export default function ProxMascot({ mood = 'neutral', size = 140 }: ProxMascotProps) {
  const eyeColor = mood === 'sad' ? '#FF6B6B' : '#7AB3FF'
  const mouthPath = mood === 'happy'
    ? 'M 42 68 Q 50 76 58 68'
    : mood === 'sad'
    ? 'M 42 72 Q 50 64 58 72'
    : 'M 42 70 L 58 70'

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 110"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Body */}
      <rect x="18" y="36" width="64" height="56" rx="16" fill="url(#bodyGrad)" />

      {/* Head */}
      <rect x="22" y="8" width="56" height="46" rx="18" fill="url(#headGrad)" />

      {/* Screen glow on head */}
      <rect x="28" y="18" width="44" height="28" rx="8" fill="rgba(122,179,255,0.12)" />

      {/* Eyes */}
      <ellipse cx="38" cy="32" rx="6" ry="7" fill={eyeColor} />
      <ellipse cx="62" cy="32" rx="6" ry="7" fill={eyeColor} />

      {/* Eye shine */}
      <ellipse cx="40" cy="29" rx="2" ry="2.5" fill="white" opacity="0.8" />
      <ellipse cx="64" cy="29" rx="2" ry="2.5" fill="white" opacity="0.8" />

      {/* Antenna */}
      <line x1="50" y1="8" x2="50" y2="0" stroke="url(#antennaGrad)" strokeWidth="3" strokeLinecap="round" />
      <circle cx="50" cy="0" r="4" fill="#7AB3FF" className="ant-light" />

      {/* Mouth */}
      <path d={mouthPath} stroke={mood === 'happy' ? '#A4F0C1' : mood === 'sad' ? '#FF6B6B' : 'rgba(255,255,255,0.5)'} strokeWidth="2.5" strokeLinecap="round" fill="none" />

      {/* Arms */}
      <rect x="4" y="50" width="16" height="8" rx="4" fill="url(#bodyGrad)" />
      <rect x="80" y="50" width="16" height="8" rx="4" fill="url(#bodyGrad)" />

      {/* Legs */}
      <rect x="28" y="88" width="14" height="16" rx="6" fill="url(#bodyGrad)" />
      <rect x="58" y="88" width="14" height="16" rx="6" fill="url(#bodyGrad)" />

      {/* Chest panel */}
      <rect x="30" y="50" width="40" height="26" rx="8" fill="rgba(255,255,255,0.06)" stroke="rgba(255,255,255,0.14)" strokeWidth="0.5" />

      {/* Chest indicators */}
      <circle cx="40" cy="60" r="3" fill="#34C759" opacity="0.8" />
      <circle cx="50" cy="60" r="3" fill="#7AB3FF" opacity="0.8" />
      <circle cx="60" cy="60" r="3" fill="#FF9500" opacity="0.5" />
      <rect x="34" y="68" width="32" height="2" rx="1" fill="rgba(255,255,255,0.2)" />
      <rect x="34" y="68" width="20" height="2" rx="1" fill="#7AB3FF" opacity="0.7" />

      <defs>
        <linearGradient id="headGrad" x1="22" y1="8" x2="78" y2="54" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2A2A5A" />
          <stop offset="1" stopColor="#1A1A3E" />
        </linearGradient>
        <linearGradient id="bodyGrad" x1="18" y1="36" x2="82" y2="92" gradientUnits="userSpaceOnUse">
          <stop stopColor="#242460" />
          <stop offset="1" stopColor="#14143A" />
        </linearGradient>
        <linearGradient id="antennaGrad" x1="50" y1="8" x2="50" y2="0" gradientUnits="userSpaceOnUse">
          <stop stopColor="#3A3A7A" />
          <stop offset="1" stopColor="#7AB3FF" />
        </linearGradient>
      </defs>
    </svg>
  )
}
