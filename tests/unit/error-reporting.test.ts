import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { isChunkLoadError, scrubEvent, scrubText } from '@/lib/errorReporting'

/**
 * Звіт про збій — ЄДИНИЙ канал, яким дані застосунку йдуть ТРЕТІЙ стороні.
 * Тому тут перевіряється не «звіт відправляється», а що в ньому НЕМАЄ:
 * share-токенів (вони в query `/v` і в параметрах старту, не ротуються) і
 * користувача. Плюс що збій справді доходить до звіту — доти ErrorBoundary
 * перевіряв `window.Sentry`, якого не існувало, тож прод був сліпий.
 */
const src = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8')

describe('звіти про збої — без креденшлів', () => {
  it('query в URL і токени старту маскуються', () => {
    const s = scrubText('GET https://app.vercel.app/v?prop=Ab12Cd34Ef56&x=1 failed; start db_Ab12Cd34Ef56')
    expect(s).not.toContain('Ab12Cd34Ef56')
    expect(s).toContain('https://app.vercel.app/v')
    expect(s).toContain('db_…')
  })

  it('подія втрачає користувача, крихти, заголовки і query; повідомлення очищене', () => {
    const e = scrubEvent({
      user: { id: 'u1', username: 'olena' },
      breadcrumbs: [{ data: { url: 'https://x.supabase.co/rest/v1/databases?share_token=eq.SECRET123' } }],
      request: { url: 'https://app.vercel.app/v?db=SECRET123', query_string: 'db=SECRET123', headers: { a: 'b' } },
      exception: { values: [{ value: 'fetch https://x.supabase.co/rest/v1/p?id=eq.SECRET123 failed' }] },
      extra: { note: 'guest_SECRET123' },
    })
    expect(JSON.stringify(e)).not.toContain('SECRET123')
    expect(e.user).toBeUndefined()
    expect(e.breadcrumbs).toBeUndefined()
    // Антивакуум: очищення не сміє стерти саму суть звіту.
    expect(e.exception?.values?.[0].value).toContain('failed')
    expect(e.request?.url).toBe('https://app.vercel.app/v')
  })

  it('ініціалізація: без PII, без крихт, без трасування, beforeSend = scrubEvent', () => {
    const s = src('src/lib/errorReporting.ts')
    expect(s).toMatch(/sendDefaultPii:\s*false/)
    expect(s).toMatch(/maxBreadcrumbs:\s*0/)
    expect(s).toMatch(/beforeSend:\s*\(event\)\s*=>\s*scrubEvent\(event\)/)
    expect(s, 'вантажити SDK лише за наявності DSN').toMatch(/if \(!DSN \|\| started/)
  })

  it('збій справді доходить до звіту: ErrorBoundary і глобальні обробники', () => {
    expect(src('src/components/ErrorBoundary.tsx')).toMatch(/reportError\(error/)
    expect(src('src/components/ErrorBoundary.tsx'), 'мертвий шлях через window.Sentry повернувся')
      .not.toMatch(/window as typeof window & \{ Sentry/)
    const layout = src('src/app/layout.tsx')
    expect(layout).toMatch(/initErrorReporting\(\)/)
    expect(layout).toMatch(/reportError\(event\.error/)
    expect(layout).toMatch(/reportError\(event\.reason/)
  })

  it('ErrorBoundary не показує сирий текст винятку', () => {
    expect(src('src/components/ErrorBoundary.tsx')).not.toMatch(/this\.state\.error\?\.message/)
  })
})

describe('застарілий чанк після деплою', () => {
  it('впізнає формулювання webpack, Chromium, WebKit і Firefox', () => {
    for (const m of [
      'Loading chunk 812 failed.',
      'Loading CSS chunk 12 failed',
      'Failed to fetch dynamically imported module: https://a/b.js',
      'Importing a module script failed.',
      'error loading dynamically imported module',
    ]) expect(isChunkLoadError(new Error(m)), m).toBe(true)
    const named = new Error('x'); named.name = 'ChunkLoadError'
    expect(isChunkLoadError(named)).toBe(true)
  })

  it('антивакуум: звичайний збій перезапуском НЕ маскується', () => {
    expect(isChunkLoadError(new TypeError("Cannot read properties of undefined (reading 'name')"))).toBe(false)
    expect(isChunkLoadError(null)).toBe(false)
  })
})
