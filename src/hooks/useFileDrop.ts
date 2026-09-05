'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * ПЕРЕТЯГУВАННЯ ФАЙЛІВ У ВІКНО.
 *
 * На компʼютері це очікуваний спосіб додати файл, і без нього Telegram Desktop
 * поводиться ГІРШЕ, ніж просто «не підтримує»: браузер за замовчуванням
 * ВІДКРИВАЄ кинутий файл, тобто застосунок зникає разом із незбереженим станом.
 * Тому тут дві окремі речі, і друга обовʼязкова навіть без першої:
 *
 * 1. `useFileDrop` — зона прийому: підсвітка під час перетягування і фільтр
 *    типів. Лічильник глибини (`depth`) обовʼязковий: `dragenter`/`dragleave`
 *    спрацьовують і на ДІТЯХ зони, тож без нього підсвітка блимає на кожному
 *    вкладеному елементі.
 * 2. `useGlobalDropGuard` — глушник для промахів: усе, що впало ПОЗА зоною,
 *    гаситься на вікні. Це не косметика, а захист від втрати даних.
 *
 * Фільтр приймає `File`, а не рядок розширення: тип файлу в системі не завжди
 * доходить у `type` (Windows любить порожній MIME для .docx), тож рішення
 * лишається за викликачем, який знає і про розширення.
 */

interface Options {
  /** Чи приймати цей файл. Викликається на кожен файл дропу. */
  accept: (file: File) => boolean
  /** Прийняті файли. Не викликається, якщо після фільтра нічого не лишилось. */
  onFiles: (files: File[]) => void
  /** Повідомити, що дроп цілком відкинуто фільтром. */
  onRejected?: () => void
  /** Вимкнути зону (немає прав, триває аплоуд). */
  disabled?: boolean
}

export function useFileDrop({ accept, onFiles, onRejected, disabled }: Options) {
  const [dropping, setDropping] = useState(false)
  const depth = useRef(0)

  // Обробники читають свіжі колбеки через ref: зона живе довго, а викликач
  // передає інлайнові функції щоразу.
  const cb = useRef({ accept, onFiles, onRejected, disabled })
  cb.current = { accept, onFiles, onRejected, disabled }

  const reset = useCallback(() => { depth.current = 0; setDropping(false) }, [])

  const onDragEnter = useCallback((e: React.DragEvent) => {
    if (cb.current.disabled) return
    // Перетягування ТЕКСТУ чи посилання — не наш випадок, зону не підсвічуємо.
    if (!Array.from(e.dataTransfer.types).includes('Files')) return
    e.preventDefault()
    depth.current += 1
    setDropping(true)
  }, [])

  const onDragOver = useCallback((e: React.DragEvent) => {
    if (cb.current.disabled) return
    if (!Array.from(e.dataTransfer.types).includes('Files')) return
    // Без цього браузер відмовляється від дропу і відкриє файл сам.
    e.preventDefault()
    e.dataTransfer.dropEffect = 'copy'
  }, [])

  const onDragLeave = useCallback((e: React.DragEvent) => {
    if (cb.current.disabled) return
    e.preventDefault()
    depth.current -= 1
    if (depth.current <= 0) reset()
  }, [reset])

  const onDrop = useCallback((e: React.DragEvent) => {
    if (cb.current.disabled) return
    e.preventDefault()
    e.stopPropagation()
    reset()
    const files = Array.from(e.dataTransfer.files ?? [])
    if (!files.length) return
    const ok = files.filter(cb.current.accept)
    if (!ok.length) { cb.current.onRejected?.(); return }
    cb.current.onFiles(ok)
  }, [reset])

  return {
    dropping,
    dropProps: { onDragEnter, onDragOver, onDragLeave, onDrop },
  }
}

/**
 * Гасить дропи ПОЗА зонами прийому. Без цього кинутий повз файл відкривається
 * замість застосунку — на десктопі це втрата незбереженого стану.
 * Вішається один раз на застосунок.
 */
export function useGlobalDropGuard() {
  useEffect(() => {
    const swallow = (e: DragEvent) => {
      if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes('Files')) return
      e.preventDefault()
    }
    // `dragover` теж обовʼязковий: без нього браузер не вважає вікно ціллю і
    // `drop` до нас не доходить.
    window.addEventListener('dragover', swallow)
    window.addEventListener('drop', swallow)
    return () => {
      window.removeEventListener('dragover', swallow)
      window.removeEventListener('drop', swallow)
    }
  }, [])
}
