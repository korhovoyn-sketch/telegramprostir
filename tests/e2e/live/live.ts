/**
 * Браузер ↔ ЖИВА база. Мокаються ЛИШЕ зовнішні сервіси, яких у пісочниці
 * немає (Telegram, GoTrue, сховище файлів, edge-функції); усе, що пише й
 * читає дані, іде в справжній Postgres через `rest.ts` — з RLS, тригерами й
 * тілами RPC.
 *
 * Сховище не обходить політики: завантаження і видалення виконуються як
 * INSERT/DELETE у `storage.objects` під роллю користувача — рівно так, як це
 * робить сервіс Storage Supabase, тож storage-політики з міграцій діють.
 */
import type { Page, Route } from '@playwright/test'
import { installTelegram, PHOTO_PNG, type HarnessUser } from '../helpers/harness'
import { handleRest, prelude, psql, type Claims, type Conn } from './rest'

export const LIVE: Conn = {
  sock: process.env.LIVE_SOCK ?? '/tmp/pglive-run',
  port: Number(process.env.LIVE_PORT ?? 5434),
  db: 'live',
}

export interface Persona { tg_id: number; first_name: string; username?: string; language_code?: string }

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const emailOf = (tg: number) => `${tg}@telegram.propspace.app`

/** Те, що робить telegram-auth: upsert у public.users і рядок в auth.users. */
export async function ensureUser(p: Persona): Promise<{ user: Record<string, unknown>; authId: string; isNew: boolean }> {
  const lit = (s: string | undefined) => (s == null ? 'NULL' : `'${s.replace(/'/g, "''")}'`)
  const out = await psql(LIVE, `
WITH ex AS (SELECT id FROM users WHERE tg_id = ${p.tg_id}),
up AS (
  UPDATE users SET tg_username = ${lit(p.username)}, first_name = ${lit(p.first_name)},
         language_code = ${lit(p.language_code ?? 'uk')}, updated_at = now()
   WHERE tg_id = ${p.tg_id} RETURNING id),
ins AS (
  INSERT INTO users (tg_id, tg_username, first_name, language_code, role)
  SELECT ${p.tg_id}, ${lit(p.username)}, ${lit(p.first_name)}, ${lit(p.language_code ?? 'uk')}, 'owner'
   WHERE NOT EXISTS (SELECT 1 FROM ex) RETURNING id),
au AS (
  -- Те, що робить admin.createUser у edge-функції: підтверджений email і
  -- app_metadata.tg_id, без якого 076 не визнає особу.
  INSERT INTO auth.users (email, email_confirmed_at, raw_app_meta_data)
  VALUES ('${emailOf(p.tg_id)}', now(), jsonb_build_object('tg_id', '${p.tg_id}'))
  ON CONFLICT (email) DO UPDATE SET raw_app_meta_data = EXCLUDED.raw_app_meta_data RETURNING id)
SELECT json_build_object('is_new', NOT EXISTS (SELECT 1 FROM ex), 'auth_id', (SELECT id FROM au));`)
  const { is_new, auth_id } = JSON.parse(out.trim())
  const row = JSON.parse((await psql(LIVE, `SELECT row_to_json(u) FROM (SELECT id,tg_id,tg_username,first_name,last_name,email,phone,role,language_code,currency,plan,notification_push,notification_weekly,notification_views,created_at,updated_at FROM users WHERE tg_id = ${p.tg_id}) u;`)).trim())
  return { user: row, authId: auth_id, isNew: is_new }
}

function jwtFor(authId: string, tg: number) {
  const now = Math.floor(Date.now() / 1000)
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: authId, email: emailOf(tg), role: 'authenticated', aud: 'authenticated', iat: now, exp: now + 3600 })}.sig`
}

function claimsFrom(auth: string | undefined): Claims {
  const tok = auth?.replace(/^Bearer\s+/i, '')
  if (!tok || tok.split('.').length !== 3) return { role: 'anon' }
  try {
    const p = JSON.parse(Buffer.from(tok.split('.')[1], 'base64url').toString())
    if (p.role === 'authenticated' && p.sub) return { role: 'authenticated', sub: p.sub, email: p.email }
  } catch { /* fallthrough */ }
  return { role: 'anon' }
}

export interface LiveLog { errors: string[]; failed: string[]; requests: string[] }

/** Під'єднує сторінку до живої бази як `persona`. */
export async function installLive(page: Page, persona: Persona, opts: { startParam?: string; platform?: string } = {}): Promise<LiveLog> {
  const log: LiveLog = { errors: [], failed: [], requests: [] }
  page.on('pageerror', (e) => log.errors.push(`pageerror: ${e.message}`))
  page.on('console', (m) => { if (m.type() === 'error') log.errors.push(`console: ${m.text()}`) })

  const harnessUser: HarnessUser = {
    id: '00000000-0000-0000-0000-000000000000', tg_id: persona.tg_id, first_name: persona.first_name,
    tg_username: persona.username, role: null, language_code: persona.language_code ?? 'uk', currency: 'USD', plan: 'free',
  }
  await installTelegram(page, { user: harnessUser, startParam: opts.startParam, platform: opts.platform ?? 'ios' })
  await page.route('**/telegram-web-app.js', (r) => r.fulfill({ status: 200, contentType: 'application/javascript', body: '' }))

  const json = (r: Route, body: unknown, status = 200) =>
    r.fulfill({ status, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(body) })

  // Загальний маршрут ПЕРШИМ: у Playwright виграє зареєстрований останнім.
  await page.route('**/functions/v1/**', (r) => json(r, { ok: true }))

  let session: { jwt: string; authId: string } | null = null
  const login = async () => {
    const { user, authId, isNew } = await ensureUser(persona)
    // АНТИВАКУУМ СТЕНДУ: база мусить упізнати цю особу через ті самі клейми,
    // що підуть із кожним запитом. Інакше всі запити тихо йдуть «нікому», і
    // прохід бачить порожні екрани замість дефектів (так і було спершу).
    const me = (await psql(LIVE, `${prelude({ role: 'authenticated', sub: authId, email: emailOf(persona.tg_id) })}
SELECT COALESCE(current_app_user_id()::text, 'NULL') || '|' || COALESCE(get_app_user_id_from_auth_uid()::text, 'NULL'); COMMIT;`)).trim()
    if (me !== `${user.id}|${user.id}`) throw new Error(`стенд не впізнає ${persona.first_name}: ${me} ≠ ${user.id}`)
    session = { jwt: jwtFor(authId, persona.tg_id), authId }
    return { user, isNew }
  }

  await page.route('**/functions/v1/telegram-auth**', async (r) => {
    if (r.request().method() === 'GET') return r.fulfill({ status: 204, body: '' })
    const { user, isNew } = await login()
    return json(r, { access_token: session!.jwt, refresh_token: 'refresh-live', user, is_new: isNew })
  })
  const authUser = () => session && { id: session.authId, email: emailOf(persona.tg_id), aud: 'authenticated', role: 'authenticated' }
  await page.route('**/auth/v1/token**', async (r) => {
    if (!session) await login()
    return json(r, { access_token: session!.jwt, refresh_token: 'refresh-live', token_type: 'bearer', expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, user: authUser() })
  })
  await page.route('**/auth/v1/user**', async (r) => {
    if (!session) await login()
    return json(r, authUser())
  })
  await page.route('**/auth/v1/logout**', (r) => json(r, {}))

  // validate-upload: справжня перевірка власності — у RLS на property_files,
  // тож мок лише видає шлях і «підписану» адресу, як це робить функція.
  await page.route('**/functions/v1/validate-upload**', async (r) => {
    const b = JSON.parse(r.request().postData() ?? '{}')
    const ext = String(b.fileName ?? 'f.pdf').split('.').pop()
    const storagePath = `${b.propertyId}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`
    return json(r, { uploadUrl: `http://localhost:9999/storage/v1/object/upload/sign/property-files/${storagePath}?token=live`, storagePath })
  })

  await page.route('**/storage/v1/**', async (r) => {
    const req = r.request()
    const url = new URL(req.url())
    const claims = claimsFrom(req.headers()['authorization'])
    const p = url.pathname.replace(/^.*\/storage\/v1\//, '')
    if (p.startsWith('object/public/photos/')) {
      return r.fulfill({ status: 200, contentType: 'image/png', body: PHOTO_PNG })
    }
    if (p.startsWith('object/upload/sign/')) {
      const [bucket, ...rest] = p.replace('object/upload/sign/', '').split('/')
      await psql(LIVE, `INSERT INTO storage.objects (bucket_id, name) VALUES ('${bucket}', '${rest.join('/').replace(/'/g, "''")}');`)
      return json(r, { Key: `${bucket}/${rest.join('/')}` })
    }
    if (p.startsWith('object/sign/')) {
      return json(r, { signedURL: `/object/sign/${p.replace('object/sign/', '')}?token=live` })
    }
    if (req.method() === 'DELETE' && p.startsWith('object/')) {
      const bucket = p.replace('object/', '').split('/')[0]
      const names: string[] = JSON.parse(req.postData() ?? '{}').prefixes ?? []
      const out = await psql(LIVE, `${prelude(claims)}WITH d AS (DELETE FROM storage.objects WHERE bucket_id = '${bucket}' AND name = ANY (ARRAY[${names.map((n) => `'${n.replace(/'/g, "''")}'`).join(',') || "''"}]::text[]) RETURNING name)
SELECT COALESCE(json_agg(json_build_object('name', name)), '[]'::json) FROM d; COMMIT;`)
      return json(r, JSON.parse(out.trim().split('\n').pop() || '[]'))
    }
    if ((req.method() === 'POST' || req.method() === 'PUT') && p.startsWith('object/')) {
      const [bucket, ...rest] = p.replace('object/', '').split('/')
      const name = rest.join('/')
      try {
        await psql(LIVE, `${prelude(claims)}INSERT INTO storage.objects (bucket_id, name, owner) VALUES ('${bucket}', '${name.replace(/'/g, "''")}', ${claims.sub ? `'${claims.sub}'` : 'NULL'}); COMMIT;`)
        return json(r, { Key: `${bucket}/${name}` })
      } catch (e) {
        return json(r, { statusCode: '403', error: 'Unauthorized', message: String((e as Error).message) }, 403)
      }
    }
    return json(r, { error: 'not found' }, 404)
  })

  await page.route('**/rest/v1/**', async (r) => {
    const req = r.request()
    if (req.method() === 'OPTIONS') return r.fulfill({ status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': '*' } })
    const claims = claimsFrom(req.headers()['authorization'])
    const res = await handleRest(LIVE, claims, req.method(), req.url(), req.headers(), req.postData())
    const short = req.url().replace(/^.*\/rest\/v1\//, '').slice(0, 140)
    log.requests.push(`${req.method()} ${short} → ${res.status}`)
    if (res.status >= 400) log.failed.push(`[${claims.role}] ${req.method()} ${short} → ${res.status} ${res.body.slice(0, 200)}`)
    return r.fulfill({ status: res.status, headers: { ...res.headers, 'access-control-allow-origin': '*' }, body: res.body })
  })
  return log
}

/** Прямий запит до бази від postgres — щоб звіряти, що дія СПРАВДІ сталась. */
export async function db<T = unknown>(sql: string): Promise<T> {
  const out = (await psql(LIVE, `SELECT COALESCE(json_agg(x), '[]'::json) FROM (${sql}) x;`)).trim()
  return JSON.parse(out) as T
}

/** Команда до бази від postgres без результату (підготовка/прибирання стану). */
export async function exec(sql: string): Promise<void> {
  await psql(LIVE, sql)
}
