import { describe, it, expect, afterEach, vi } from 'vitest'

// TG_BOT/TG_APP are captured from process.env at module load, so each case
// stubs env then re-imports the module fresh.
async function buildDeepLink(env: { bot?: string; app?: string }, param: string) {
  vi.resetModules()
  if (env.bot === undefined) vi.stubEnv('NEXT_PUBLIC_TELEGRAM_BOT_USERNAME', '')
  else vi.stubEnv('NEXT_PUBLIC_TELEGRAM_BOT_USERNAME', env.bot)
  if (env.app === undefined) vi.stubEnv('NEXT_PUBLIC_TELEGRAM_APP_NAME', '')
  else vi.stubEnv('NEXT_PUBLIC_TELEGRAM_APP_NAME', env.app)
  const mod = await import('@/lib/telegram')
  return mod.buildDeepLink(param)
}

describe('buildDeepLink env normalisation', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('builds the direct-link form from bare bot + short name', async () => {
    expect(await buildDeepLink({ bot: 'prostirapplbot', app: 'prostir' }, 'db_abc'))
      .toBe('https://t.me/prostirapplbot/prostir?startapp=db_abc')
  })

  it('recovers the short name when APP_NAME was mis-entered as a full t.me URL', async () => {
    // The production misconfiguration that broke shares: full URL instead of "prostir".
    expect(await buildDeepLink({ bot: 'prostirapplbot', app: 'https://t.me/prostirapplbot/prostir' }, 'db_abc'))
      .toBe('https://t.me/prostirapplbot/prostir?startapp=db_abc')
  })

  it('strips a leading @ from the bot username', async () => {
    expect(await buildDeepLink({ bot: '@prostirapplbot', app: 'prostir' }, 'prop_x'))
      .toBe('https://t.me/prostirapplbot/prostir?startapp=prop_x')
  })

  it('drops a trailing query when APP_NAME carries one', async () => {
    expect(await buildDeepLink({ bot: 'prostirapplbot', app: 'prostir?startapp=leftover' }, 'col_y'))
      .toBe('https://t.me/prostirapplbot/prostir?startapp=col_y')
  })

  it('falls back to the bare bot link when no app short name is set', async () => {
    expect(await buildDeepLink({ bot: 'prostirapplbot' }, 'team_z'))
      .toBe('https://t.me/prostirapplbot?startapp=team_z')
  })

  it('returns # when the bot username is not configured', async () => {
    expect(await buildDeepLink({}, 'db_abc')).toBe('#')
  })
})
