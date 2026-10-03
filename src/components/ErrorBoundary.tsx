'use client'

import { Component, type ReactNode } from 'react'
import { tr } from '@/lib/i18n'
import { isChunkLoadError, reportError } from '@/lib/errorReporting'
import { useAppStore } from '@/store/appStore'

// Один автоматичний перезапуск на застарілий чанк, не більше: якщо файл
// відсутній і на свіжому білді, другий перезапуск дав би нескінченну петлю.
const CHUNK_RELOAD_KEY = 'ps_chunk_reload_at'
const CHUNK_RELOAD_WINDOW_MS = 30_000

function reloadedRecently(): boolean {
  try {
    const at = Number(sessionStorage.getItem(CHUNK_RELOAD_KEY) ?? 0)
    return Date.now() - at < CHUNK_RELOAD_WINDOW_MS
  } catch { return true }
}

interface Props { children: ReactNode }
interface State { hasError: boolean; error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error('[ErrorBoundary]', error, info.componentStack)
    // Застарілий чанк після деплою — не збій коду, а стара вкладка. Свіжий
    // index його лікує, тож перезапуск робиться сам, і користувач бачить
    // оновлений застосунок замість «Щось пішло не так».
    if (isChunkLoadError(error) && !reloadedRecently()) {
      try { sessionStorage.setItem(CHUNK_RELOAD_KEY, String(Date.now())) } catch { /* без сховища — один раз і так */ }
      window.location.reload()
      return
    }
    reportError(error, {
      tags: { boundary: 'app', screen: useAppStore.getState().screen },
      extra: { componentStack: info.componentStack },
    })
  }

  render() {
    if (this.state.hasError) {
      const chunk = isChunkLoadError(this.state.error)
      return (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'var(--bg)',
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          padding: 32, gap: 20, color: 'var(--t1)', textAlign: 'center'
        }}>
          <div style={{ fontSize: 64 }}>⚠️</div>
          <div style={{ fontSize: 'var(--fs-t3)', fontWeight: 'var(--fw-bold)' }}>
            {chunk ? tr('Вийшла нова версія') : tr('Щось пішло не так')}
          </div>
          {/* Сирий текст винятку користувачу НЕ показується: він нічого не
              пояснює («Cannot read properties of undefined»), зате може нести
              внутрішні подробиці — те саме правило 1, що й для edge-функцій. */}
          <div style={{ fontSize: 'var(--fs-note)', color: 'var(--t2)', maxWidth: 280, lineHeight: 1.5 }}>
            {chunk
              ? tr('Перезапустіть застосунок, щоб її завантажити.')
              : tr('Перезапустіть застосунок. Збережені дані не постраждали.')}
          </div>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null })
              window.location.reload()
            }}
            style={{
              marginTop: 8, padding: '12px 28px', borderRadius: 14,
              background: 'linear-gradient(135deg, #7B30EB, #3478F6)',
              border: 'none', color: 'var(--t1)', fontSize: 'var(--fs-sub)', fontWeight: 'var(--fw-semi)',
              cursor: 'pointer'
            }}
          >
            {tr('Перезапустити')}
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
