'use client'

import { useEffect, useRef, useState } from 'react'

// Ховає плаваючу кнопку, коли користувач гортає ВНИЗ (читає список), і повертає
// її на гортанні ВГОРУ або біля верху. Без цього FAB стоїть у правому нижньому
// куті й постійно накриває статус-бейдж тієї картки, що трапилась на його висоті.
//
// Скролиться не window, а внутрішній контейнер `.body`, тож слухаємо саме його.
const DOWN_THRESHOLD = 8   // менші рухи — це дрож пальця, не намір гортати
const TOP_ZONE = 28        // біля верху кнопка завжди видима

export function useHideOnScrollDown(): boolean {
  const [hidden, setHidden] = useState(false)
  const lastRef = useRef(0)

  useEffect(() => {
    const el = document.querySelector<HTMLElement>('.body')
    if (!el) return
    lastRef.current = el.scrollTop

    const onScroll = () => {
      const y = el.scrollTop
      const dy = y - lastRef.current

      if (y <= TOP_ZONE) {
        setHidden(false)
      } else if (dy > DOWN_THRESHOLD) {
        setHidden(true)
        lastRef.current = y
      } else if (dy < -DOWN_THRESHOLD) {
        setHidden(false)
        lastRef.current = y
      }
      // Рухи в межах порога не оновлюють lastRef — інакше повільне гортання
      // ніколи не набрало б порога і кнопка не реагувала б узагалі.
      if (Math.abs(dy) > DOWN_THRESHOLD || y <= TOP_ZONE) lastRef.current = y
    }

    el.addEventListener('scroll', onScroll, { passive: true })
    return () => el.removeEventListener('scroll', onScroll)
  }, [])

  return hidden
}
