'use client'

export function SkeletonRow() {
  return <div className="skel skel-row" />
}

export function SkeletonStat() {
  return <div className="skel skel-stat" />
}

export function SkeletonText({ width = '100%' }: { width?: string }) {
  return <div className="skel skel-text" style={{ width }} />
}

export function SkeletonList({ count = 3 }: { count?: number }) {
  return (
    <div style={{ padding: '0 12px' }}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonRow key={i} />
      ))}
    </div>
  )
}

export default function SkeletonLoader() {
  return (
    <div style={{ padding: '0 12px' }}>
      <div className="stat-g">
        <SkeletonStat />
        <SkeletonStat />
        <SkeletonStat />
      </div>
      <SkeletonRow />
      <SkeletonRow />
      <SkeletonRow />
    </div>
  )
}
