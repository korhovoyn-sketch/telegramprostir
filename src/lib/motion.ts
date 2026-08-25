/**
 * `prefers-reduced-motion` мусить читатися В JS, а не лише в CSS.
 *
 * Блок `@media (prefers-reduced-motion: reduce)` у globals.css гасить
 * `animation`/`transition` — тобто CSS. Він НЕ спиняє ні `requestAnimationFrame`,
 * ні інлайновий transform, ні Web Animations API. Кожне таке місце мусить
 * питати саме́ і виходити в кінцевий стан синхронно.
 *
 * Третє входження рецепта (Collapsible, SpaceOrb, useCountUp) — тож він тут,
 * а не скопійований учетверте.
 */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}
