'use client'

import { Component, type ReactNode } from 'react'

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
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          padding: 32, gap: 20, color: '#fff', textAlign: 'center'
        }}>
          <div style={{ fontSize: 64 }}>⚠️</div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>Щось пішло не так</div>
          <div style={{ fontSize: 14, color: 'rgba(255,255,255,.6)', maxWidth: 280, lineHeight: 1.5 }}>
            {this.state.error?.message ?? 'Невідома помилка'}
          </div>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null })
              window.location.reload()
            }}
            style={{
              marginTop: 8, padding: '12px 28px', borderRadius: 14,
              background: 'linear-gradient(135deg, #7B30EB, #3478F6)',
              border: 'none', color: '#fff', fontSize: 15, fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Перезапустити
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
