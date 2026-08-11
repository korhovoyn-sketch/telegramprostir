'use client'

import { useEffect, useRef, useState } from 'react'

// Ховає плаваючу кнопку, коли користувач гортає ВНИЗ (читає список), і повертає
// її на гортанні ВГОРУ або біля верху. Без цього FAB стоїть у правому нижньому
// куті й постійно накриває статус-бейдж тієї картки, що трапилась на його висоті.
//
// Скролиться не window, а внутрішній контейнер `.body`, тож слухаємо саме його.

// Пороги НЕсиметричні свідомо. Ховати треба ЛІНИВО: 8px кнопка «відстрілювала»
// на першому ж русі пальця, ще до того, як користувач насправді почав гортати —
// саме це читалось як ривок, а не як зникання. Показувати навпаки треба ОХОЧЕ:
// щойно людина повела вгору, кнопка потрібна їй негайно.
const DOWN_THRESHOLD = 40  // ховаємо лише після осмисленого гортання вниз
const UP_THRESHOLD = 10    // повертаємо майже одразу
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
        lastRef.current = y
        return
      }
      // Рухи в межах порога НЕ оновлюють lastRef — так дельта накопичується від
      // останнього якоря, інакше повільне гортання ніколи не набрало б порога.
      if (dy > DOWN_THRESHOLD) {
        setHidden(true)
        lastRef.current = y
      } else if (dy < -UP_THRESHOLD) {
        setHidden(false)
        lastRef.current = y
      }
    }

    el.addEventListener('scroll', onScroll, { passive: true })
    return () => el.removeEventListener('scroll', onScroll)
  }, [])

  return hidden
}
