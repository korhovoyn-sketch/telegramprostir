'use client'

import { useEffect, useRef, useState } from 'react'

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
}

// Matches layout.tsx's default chrome color (near-black top of every .bg-*).
const DEFAULT_BAR = '#06050e'

// Drives the native Telegram MainButton as a screen's primary action: always
// visible above the keyboard, native look, system progress spinner. Returns
// true when the native button is in charge — the caller should hide its DOM
// fallback then (outside Telegram it returns false and the DOM button stays).
//
// The click handler goes through a ref so re-renders never re-subscribe;
// unmount hides the button and detaches the handler so it can't leak onto the
// next screen.
export function useMainButton({ text, visible, enabled = true, loading = false, barColor, onClick }: MainButtonOptions): boolean {
  const [available, setAvailable] = useState(false)
  const cbRef = useRef(onClick)
  cbRef.current = onClick

  useEffect(() => {
    const tg = window.Telegram?.WebApp
    // initData is only non-empty inside a real Telegram container — in a
    // plain browser the SDK object may exist but the button never renders.
    if (!tg?.MainButton || !tg.initData) return
    const mb = tg.MainButton
    const handler = () => cbRef.current()
    mb.onClick(handler)
    setAvailable(true)
    return () => {
      mb.offClick(handler)
      mb.hideProgress()
      mb.hide()
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

  return available
}
