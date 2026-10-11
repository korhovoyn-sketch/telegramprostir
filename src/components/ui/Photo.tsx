'use client'

/* eslint-disable @next/next/no-img-element */
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'

/**
 * Знімок, який проявляється ПІСЛЯ завантаження і не малює гліф битої картинки.
 *
 * Сирий `<img>` мав два дефекти, обидва видно лише на реальній мережі:
 * 1. на LTE знімок зʼявлявся РИВКОМ поверх героя, а анімація появи (якщо була)
 *    програвала при МОНТУВАННІ, тобто на порожньому елементі — байти приїжджали
 *    вже після неї;
 * 2. 404 (осиротілий шлях, збій сховища) лишав у DOM гліф битої картинки разом
 *    з alt-текстом поверх скриму героя.
 *
 * Стан виводиться з `src`, а не синхронізується ефектом: зміна знімка сама
 * повертає «вантажиться», без кадру, де новий знімок уже видно наполовину.
 */
export function Photo({
  src, alt, className, style, fallback = null, onFail, eager = false, zoom = false,
}: {
  src: string
  alt: string
  className?: string
  style?: CSSProperties
  /** Що малювати замість знімка, який не завантажився. */
  fallback?: ReactNode
  onFail?: () => void
  /** Перший кадр екрана: без `lazy` і з пріоритетом завантаження. */
  eager?: boolean
  /** Легке наближення разом із проявом — для повноекранного перегляду. */
  zoom?: boolean
}) {
  const [loaded, setLoaded] = useState<string | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const ref = useRef<HTMLImageElement>(null)

  // Знімок із кешу може встигнути завантажитись ДО того, як React повісить
  // обробник — тоді `load` не прийде ніколи, і фото лишилось би невидимим.
  useEffect(() => {
    const img = ref.current
    if (!img?.complete) return
    if (img.naturalWidth > 0) setLoaded(src)
    else { setFailed(src); onFail?.() }
    // onFail свідомо поза залежностями: інлайновий колбек викликача міняється
    // щорендеру, а перевірка потрібна саме на зміну знімка.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src])

  if (failed === src) return <>{fallback}</>

  const on = loaded === src
  return (
    <img
      ref={ref}
      src={src}
      alt={alt}
      decoding="async"
      loading={eager ? 'eager' : 'lazy'}
      // React 19 знає `fetchPriority` як DOM-властивість.
      fetchPriority={eager ? 'high' : 'auto'}
      className={`photo-img${zoom ? ' zoom' : ''}${on ? ' on' : ''}${className ? ` ${className}` : ''}`}
      style={style}
      onLoad={() => setLoaded(src)}
      onError={() => { setFailed(src); onFail?.() }}
    />
  )
}
