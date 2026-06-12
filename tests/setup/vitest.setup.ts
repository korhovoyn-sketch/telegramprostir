import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { installTelegramMock, clearTelegramMock } from '../mocks/telegram'

// Tell React it's running in a test environment so state updates are batched
// under act() without warnings.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true

// jsdom implements neither of these; screens call them on focus / mount.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn()
}
if (!window.visualViewport) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(window as any).visualViewport = { height: 800, width: 375, offsetTop: 0, addEventListener: vi.fn(), removeEventListener: vi.fn() }
}

// Every test starts with a clean DOM, fresh localStorage, and a default
// Telegram mock present (a logged-in-capable user). Individual tests can
// re-install the mock with custom options.
beforeEach(() => {
  localStorage.clear()
  installTelegramMock()
})

afterEach(() => {
  cleanup()
  clearTelegramMock()
  localStorage.clear()
})
