'use client'

import { useEffect, useRef, useState } from 'react'

interface SecondaryOptions {
  text: string
  /** Небезпечна дія — червоний підпис на смузі, а не залита кнопка. */
  destructive?: boolean
  onClick: () => void
}

interface MainButtonOptions {
  text: string
  visible: boolean
  enabled?: boolean
  loading?: boolean
  // Native bottom-bar color while this button is up — pass the BOTTOM stop of
  // the screen's .bg-* gradient so the bar reads as its continuation (the
  // Telegram API takes only a hex literal, no CSS vars).
  barColor?: string
  onClick: () => void
  /**
   * Парна нативна кнопка ЛІВОРУЧ від головної (Bot API 7.10+). Гайдлайни
   * Telegram просять тримати пару «первинна / другорядна» на нижній смузі, а не
   * ховати другу дію в хедері. Немає в старих клієнтах — `secondaryAvailable`
   * у результаті каже, чи можна ховати власну DOM-кнопку.
   */
  secondary?: SecondaryOptions
}

// Matches layout.tsx's default chrome color (near-black top of every .bg-*).
const DEFAULT_BAR = '#06050e'
const DESTRUCTIVE_FG = '#FF453A'

interface MainButtonState {
  /** Нативна MainButton керує первинною дією — DOM-фолбек можна ховати. */
  available: boolean
  /** Нативна SecondaryButton намальована — власну кнопку дії ховаємо. */
  secondaryAvailable: boolean
}

// Drives the native Telegram MainButton as a screen's primary action: always
// visible above the keyboard, native look, system progress spinner.
//
// The click handler goes through a ref so re-renders never re-subscribe;
// unmount hides the button and detaches the handler so it can't leak onto the
// next screen.
export function useMainButton(opts: MainButtonOptions): MainButtonState {
  const { text, visible, enabled = true, loading = false, barColor, onClick, secondary } = opts
  const [available, setAvailable] = useState(false)
  const [secondaryAvailable, setSecondaryAvailable] = useState(false)
  const cbRef = useRef(onClick)
  cbRef.current = onClick
  const secCbRef = useRef(secondary?.onClick)
  secCbRef.current = secondary?.onClick

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    // initData is only non-empty inside a real Telegram container — in a
    // plain browser the SDK object may exist but the button never renders.
    if (!tg?.MainButton || !tg.initData) return
    const mb = tg.MainButton
    const handler = () => cbRef.current()
    mb.onClick(handler)
    setAvailable(true)

    const sb = tg.SecondaryButton
    const secHandler = () => secCbRef.current?.()
    if (sb) sb.onClick(secHandler)

    return () => {
      mb.offClick(handler)
      mb.hideProgress()
      mb.hide()
      sb?.offClick(secHandler)
      sb?.hide()
      tg.setBottomBarColor?.(DEFAULT_BAR)
    }
  }, [])

  useEffect(() => {
    if (!available) return
    const tg = window.Telegram?.WebApp
    const mb = tg?.MainButton
    if (!mb) return
    mb.setText(text)
    tg.setBottomBarColor?.(barColor ?? DEFAULT_BAR)
    // Brand green (.mbtn.success / --ok) only while actionable — a custom
    // setParams color survives disable(), so a disabled button would stay
    // bright green and read as tappable. Grey it explicitly instead.
    const actionable = enabled && !loading
    mb.setParams?.({
      color: actionable ? '#34C759' : '#3A4149',
      text_color: actionable ? '#FFFFFF' : '#8E959E',
    })
    if (loading) mb.showProgress()
    else mb.hideProgress()
    if (actionable) mb.enable()
    else mb.disable()
    if (visible) mb.show()
    else mb.hide()
  }, [available, text, visible, enabled, loading, barColor])

  const secText = secondary?.text
  const secDestructive = secondary?.destructive
  useEffect(() => {
    if (!available) return
    const tg = window.Telegram?.WebApp
    const sb = tg?.SecondaryButton
    if (!sb || typeof sb.setParams !== 'function') return
    const show = visible && !!secText && !loading
    // Заливка = колір смуги: другорядна дія читається підписом на смузі, а не
    // другою суцільною кнопкою, яка сперечалась би з головною за увагу.
    sb.setParams({
      text: secText ?? ' ',
      position: 'left',
      color: barColor ?? DEFAULT_BAR,
      text_color: secDestructive === false ? '#FFFFFF' : DESTRUCTIVE_FG,
      is_visible: show,
    })
    setSecondaryAvailable(show)
  }, [available, visible, loading, barColor, secText, secDestructive])

  return { available, secondaryAvailable }
}
