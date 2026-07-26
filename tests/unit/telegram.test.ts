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

describe('parseStartParam', () => {
  it('splits each known prefix into kind + token', async () => {
    const { parseStartParam } = await import('@/lib/telegram')
    expect(parseStartParam('db_abc123')).toEqual({ kind: 'db', token: 'abc123' })
    expect(parseStartParam('prop_xyz')).toEqual({ kind: 'prop', token: 'xyz' })
    expect(parseStartParam('col_c1')).toEqual({ kind: 'col', token: 'c1' })
    expect(parseStartParam('guest_g1')).toEqual({ kind: 'guest', token: 'g1' })
    expect(parseStartParam('team_t1')).toEqual({ kind: 'team', token: 't1' })
  })

  it('does not confuse the db_ / guest_ prefixes (token keeps its full remainder)', async () => {
    const { parseStartParam } = await import('@/lib/telegram')
    // A token that itself starts with another prefix must not be re-split.
    expect(parseStartParam('db_guest_weird')).toEqual({ kind: 'db', token: 'guest_weird' })
  })

  it('returns null for non-deep-link, empty, and nullish input', async () => {
    const { parseStartParam } = await import('@/lib/telegram')
    expect(parseStartParam('random')).toBeNull()
    expect(parseStartParam('')).toBeNull()
    expect(parseStartParam(null)).toBeNull()
    expect(parseStartParam(undefined)).toBeNull()
  })
})

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
