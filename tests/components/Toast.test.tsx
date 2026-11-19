import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import Toast from '@/components/ui/Toast'
import { useAppStore } from '@/store/appStore'

/**
 * Тост — єдиний елемент, який зʼявляється ПОВЕРХ будь-якого екрана і чиї кнопки
 * не міряв жоден обхід: a11y-гард ходить екранами у стані спокою, а тост живе
 * 3.5с після дії. Кнопка закриття — іконка без тексту, тож без `aria-label`
 * читалка озвучувала «кнопка» без жодного слова про те, що вона робить.
 */
describe('Toast', () => {
  beforeEach(() => {
    useAppStore.setState({ toast: { type: 'success', title: 'Збережено' } })
  })

  it('кнопка закриття має доступну назву', () => {
    render(<Toast />)
    expect(screen.getByRole('button', { name: 'Закрити' })).toBeInTheDocument()
  })

  it('кнопка дії лишається названою власним підписом, а закриття — окремою кнопкою', () => {
    // Антивакуум: якщо підпис закриття колись «злипнеться» з дією, обидві
    // кнопки стали б одним іменем і гард вище проходив би на чужій кнопці.
    useAppStore.setState({
      toast: { type: 'success', title: 'Видалено', actionLabel: 'Скасувати', onAction: () => {} },
    })
    render(<Toast />)
    expect(screen.getByRole('button', { name: 'Скасувати' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Закрити' })).toBeInTheDocument()
  })

  it('без тоста нічого не малюється', () => {
    useAppStore.setState({ toast: null })
    const { container } = render(<Toast />)
    expect(container).toBeEmptyDOMElement()
  })
})
