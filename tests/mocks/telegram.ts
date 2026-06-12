// In-memory mock of window.Telegram.WebApp for tests. Mirrors the surface the
// app actually touches (see src/hooks/useTelegram.ts and src/hooks/useAuth.ts).

export interface MockTgUser {
  id: number
  first_name: string
  last_name?: string
  username?: string
}

export interface MockTelegramOptions {
  user?: MockTgUser | null
  initData?: string
  startParam?: string
  /** Seed CloudStorage (e.g. ps_user_cs / ps_session) before the app reads it */
  cloudStorageSeed?: Record<string, string>
}

const DEFAULT_USER: MockTgUser = { id: 111222333, first_name: 'Test', username: 'tester' }

export function createTelegramMock(opts: MockTelegramOptions = {}) {
  const user = opts.user === undefined ? DEFAULT_USER : opts.user
  const cloud = new Map<string, string>(Object.entries(opts.cloudStorageSeed ?? {}))

  const CloudStorage = {
    getItem: (key: string, cb: (err: unknown, val: string | null) => void) =>
      cb(null, cloud.has(key) ? cloud.get(key)! : null),
    setItem: (key: string, val: string, cb?: (err: unknown, ok: boolean) => void) => {
      cloud.set(key, val)
      cb?.(null, true)
    },
    removeItem: (key: string, cb?: (err: unknown, ok: boolean) => void) => {
      cloud.delete(key)
      cb?.(null, true)
    },
  }

  const BackButton = {
    isVisible: false,
    show() { this.isVisible = true },
    hide() { this.isVisible = false },
    onClick: (_cb: () => void) => {},
    offClick: (_cb: () => void) => {},
  }

  const HapticFeedback = {
    impactOccurred: (_s?: string) => {},
    notificationOccurred: (_s?: string) => {},
    selectionChanged: () => {},
  }

  const WebApp = {
    initData: opts.initData ?? (user ? 'mock_init_data_signed' : ''),
    initDataUnsafe: {
      user: user ?? undefined,
      start_param: opts.startParam,
    },
    colorScheme: 'dark' as const,
    viewportHeight: 800,
    viewportStableHeight: 800,
    ready: () => {},
    expand: () => {},
    close: () => {},
    enableClosingConfirmation: () => {},
    disableClosingConfirmation: () => {},
    setHeaderColor: (_c: string) => {},
    setBackgroundColor: (_c: string) => {},
    disableVerticalSwipes: () => {},
    openTelegramLink: (_u: string) => {},
    onEvent: (_e: string, _cb: () => void) => {},
    offEvent: (_e: string, _cb: () => void) => {},
    BackButton,
    HapticFeedback,
    CloudStorage,
    _cloud: cloud,
  }

  return { Telegram: { WebApp } }
}

export function installTelegramMock(opts: MockTelegramOptions = {}) {
  const mock = createTelegramMock(opts)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ;(window as any).Telegram = mock.Telegram
  return mock.Telegram.WebApp
}

export function clearTelegramMock() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  delete (window as any).Telegram
}
