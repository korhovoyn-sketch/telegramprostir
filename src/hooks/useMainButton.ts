'use client'

import { useEffect, useRef, useState } from 'react'

interface MainButtonOptions {
  text: string
  visible: boolean
  enabled?: boolean
  loading?: boolean
  onClick: () => void
}

// Drives the native Telegram MainButton as a screen's primary action: always
// visible above the keyboard, native look, system progress spinner. Returns
// true when the native button is in charge — the caller should hide its DOM
// fallback then (outside Telegram it returns false and the DOM button stays).
//
// The click handler goes through a ref so re-renders never re-subscribe;
// unmount hides the button and detaches the handler so it can't leak onto the
// next screen.
export function useMainButton({ text, visible, enabled = true, loading = false, onClick }: MainButtonOptions): boolean {
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
    // Match the app's green CTA (.mbtn.success / --ok) — the default is the
    // Telegram theme's button color, which reads off-brand (black on iOS).
    mb.setParams?.({ color: '#34C759', text_color: '#FFFFFF' })
    setAvailable(true)
    return () => {
      mb.offClick(handler)
      mb.hideProgress()
      mb.hide()
    }
  }, [])

  useEffect(() => {
    if (!available) return
    const mb = window.Telegram?.WebApp?.MainButton
    if (!mb) return
    mb.setText(text)
    if (loading) mb.showProgress()
    else mb.hideProgress()
    if (enabled && !loading) mb.enable()
    else mb.disable()
    if (visible) mb.show()
    else mb.hide()
  }, [available, text, visible, enabled, loading])

  return available
}
