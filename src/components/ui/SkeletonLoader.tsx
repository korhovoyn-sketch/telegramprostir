'use client'

/**
 * Заглушка мусить мати геометрію того, що її замінить — інакше момент приходу
 * даних це не «проявлення», а перебудова екрана.
 *
 * Тому `rowHeight` передається екраном: рядок списку баз — 88px, картка
 * обʼєкта — ~200px, компактний рядок — 69px. Спільний дефолт 48px лишається
 * для дрібних списків (сповіщення, гості, команда).
 *
 * Блока статистики тут свідомо НЕМА: усі пʼять екранів, що використовували
 * `SkeletonLoader`, малюють свій `.stat-g` ПОЗА гілкою loading, тож три
 * плиткові заглушки або дублювали справжні плитки (бази, дашборд рієлтора,
 * гостьовий дім), або малювали фантомний блок там, де статистики нема взагалі
 * (обʼєкти бази, база рієлтора).
 */

export function SkeletonRow({ height }: { height?: number }) {
  return <div className="skel skel-row" style={height ? { height } : undefined} />
}

export function SkeletonList({ count = 3, rowHeight }: { count?: number; rowHeight?: number }) {
  return (
    <div style={{ padding: '0 12px' }}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonRow key={i} height={rowHeight} />
      ))}
    </div>
  )
}

export default function SkeletonLoader({ rows = 3, rowHeight }: { rows?: number; rowHeight?: number }) {
  return <SkeletonList count={rows} rowHeight={rowHeight} />
}
