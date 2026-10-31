/**
 * ЖИВИЙ СТЕНД: PostgREST-сумісний шар поверх СПРАВЖНЬОГО Postgres.
 *
 * Навіщо. Увесь e2e-набір ганяє застосунок проти мока, який віддає фікстури,
 * тож клієнт і справжній бекенд (RLS, тригери, тіла RPC) разом не
 * запускались НІКОЛИ. Цей шар закриває саме це: кожен REST-запит застосунку
 * перекладається на SQL і виконується в базі з усіма міграціями під роллю
 * `authenticated`/`anon` і з клеймами JWT — тобто політики й тригери ті самі,
 * що в проді.
 *
 * Чому не сам PostgREST: бінарника в пісочниці немає, а завантажувати чужий
 * виконуваний код тут не можна. Підтримано рівно те, що шле застосунок
 * (select з вкладеннями, фільтри, order/limit/offset, count, insert/upsert/
 * patch/delete, rpc). Чого не знає — відповідає помилкою, а не вгадує:
 * мовчазний «успіх» зробив би стенд тим самим моком, від якого він рятує.
 */
import { execFile } from 'node:child_process'

export interface Conn { sock: string; port: number; db: string }
export interface Claims { sub?: string; email?: string; role: 'anon' | 'authenticated' | 'service_role' }
export interface RestResponse { status: number; body: string; headers: Record<string, string> }

const IDENT = /^[a-z_][a-z0-9_]*$/
const q = (s: string) => `'${String(s).replace(/'/g, "''")}'`
const ident = (s: string) => {
  if (!IDENT.test(s)) throw new RestError(400, 'PGRST100', `bad identifier: ${s}`)
  return `"${s}"`
}

export class RestError extends Error {
  constructor(public status: number, public code: string, message: string, public details: string | null = null) {
    super(message)
  }
}

export function psql(conn: Conn, sql: string, as: 'postgres' = 'postgres'): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = execFile('psql', ['-h', conn.sock, '-p', String(conn.port), '-U', as, '-d', conn.db,
      '-At', '-q', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-f', '-'],
    { maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const m = /ERROR:\s+([0-9A-Z]{5}):\s+([^\n]*)/.exec(stderr)
        const det = /DETAIL:\s+([^\n]*)/.exec(stderr)
        return reject(m ? new RestError(statusFor(m[1]), m[1], m[2], det?.[1] ?? null)
          : new RestError(500, 'XX000', stderr.trim() || String(err)))
      }
      resolve(stdout)
    })
    p.stdin!.end(sql)
  })
}

function statusFor(code: string): number {
  if (code === '42501') return 403
  if (code === '23505' || code === '23503') return 409
  if (code === '42P01' || code === '42883') return 404
  if (code === 'PGRST116') return 406
  if (code.startsWith('08')) return 503
  return 400
}

// ── каталог ────────────────────────────────────────────────────────────────
interface Fk { tbl: string; col: string; ftbl: string; fcol: string }
interface Catalog { tables: Set<string>; fks: Fk[]; funcs: Map<string, { args: { name: string; type: string }[]; retset: boolean; rettype: string }> }
let catalogCache: Catalog | null = null

export async function catalog(conn: Conn): Promise<Catalog> {
  if (catalogCache) return catalogCache
  const out = await psql(conn, `
SELECT json_build_object(
 'tables', (SELECT json_agg(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind IN ('r','v','m')),
 'fks', (SELECT json_agg(json_build_object('tbl', c.conrelid::regclass::text, 'col', a.attname,
                'ftbl', c.confrelid::regclass::text, 'fcol', fa.attname))
         FROM pg_constraint c
         JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
         JOIN pg_attribute fa ON fa.attrelid=c.confrelid AND fa.attnum=c.confkey[1]
         WHERE c.contype='f' AND array_length(c.conkey,1)=1
           AND c.connamespace='public'::regnamespace),
 'funcs', (SELECT json_agg(json_build_object('name', p.proname, 'retset', p.proretset,
                 'rettype', format_type(p.prorettype, NULL),
                 'args', COALESCE((SELECT json_agg(json_build_object('name', x.n, 'type', format_type(x.t, NULL)) ORDER BY x.i)
                          FROM unnest(p.proargnames[1:p.pronargs], p.proargtypes::oid[]) WITH ORDINALITY x(n,t,i)), '[]'::json)))
           FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind='f'))`)
  const raw = JSON.parse(out.trim())
  const funcs = new Map()
  for (const f of raw.funcs ?? []) funcs.set(f.name, f)
  catalogCache = { tables: new Set(raw.tables), fks: raw.fks ?? [], funcs }
  return catalogCache
}
export function resetCatalog() { catalogCache = null }

// ── select ─────────────────────────────────────────────────────────────────
type Item = { kind: 'col'; name: string; alias: string } | { kind: 'star' }
  | { kind: 'embed'; alias: string; table: string; inner: boolean; items: Item[] }

function splitTop(s: string): string[] {
  const out: string[] = []
  let depth = 0, cur = ''
  for (const ch of s) {
    if (ch === '(') depth++
    if (ch === ')') depth--
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue }
    cur += ch
  }
  if (cur.trim()) out.push(cur)
  return out.map((x) => x.trim()).filter(Boolean)
}

export function parseSelect(s: string | null): Item[] {
  if (!s || s.trim() === '' || s.trim() === '*') return [{ kind: 'star' }]
  return splitTop(s.replace(/\s+/g, '')).map((part): Item => {
    if (part === '*') return { kind: 'star' }
    const paren = part.indexOf('(')
    if (paren >= 0) {
      const head = part.slice(0, paren)
      const inside = part.slice(paren + 1, -1)
      let [alias, table] = head.includes(':') ? head.split(':') : [head, head]
      const inner = /!inner$/.test(table)
      table = table.replace(/!.*$/, '')
      alias = alias.replace(/!.*$/, '')
      return { kind: 'embed', alias, table, inner, items: parseSelect(inside) }
    }
    const [alias, name] = part.includes(':') ? part.split(':') : [part, part]
    if (name.includes('::') || name.includes('->')) throw new RestError(400, 'PGRST100', `unsupported select: ${part}`)
    return { kind: 'col', name, alias }
  })
}

let aliasN = 0
function projection(cat: Catalog, table: string, t: string, items: Item[]): string {
  const cols: string[] = []
  for (const it of items) {
    if (it.kind === 'star') { cols.push(`${t}.*`); continue }
    if (it.kind === 'col') { cols.push(`${t}.${ident(it.name)} AS ${ident(it.alias)}`); continue }
    const e = `e${++aliasN}`
    const inner = projection(cat, it.table, e, it.items)
    const m2o = cat.fks.find((f) => f.tbl === table && f.ftbl === it.table)
    const o2m = cat.fks.find((f) => f.tbl === it.table && f.ftbl === table)
    if (m2o) {
      cols.push(`(SELECT row_to_json(x) FROM (SELECT ${inner} FROM ${ident(it.table)} ${e} WHERE ${e}.${ident(m2o.fcol)} = ${t}.${ident(m2o.col)}) x) AS ${ident(it.alias)}`)
    } else if (o2m) {
      cols.push(`(SELECT COALESCE(json_agg(x), '[]'::json) FROM (SELECT ${inner} FROM ${ident(it.table)} ${e} WHERE ${e}.${ident(o2m.col)} = ${t}.${ident(o2m.fcol)}) x) AS ${ident(it.alias)}`)
    } else {
      throw new RestError(400, 'PGRST200', `Could not find a relationship between '${table}' and '${it.table}'`)
    }
  }
  return cols.join(', ')
}

// ── фільтри ────────────────────────────────────────────────────────────────
const RESERVED = new Set(['select', 'order', 'limit', 'offset', 'on_conflict', 'columns'])

function cond(t: string, col: string, expr: string): string {
  let neg = false
  if (expr.startsWith('not.')) { neg = true; expr = expr.slice(4) }
  const dot = expr.indexOf('.')
  const op = expr.slice(0, dot)
  const val = expr.slice(dot + 1)
  const c = `${t}.${ident(col)}`
  let sql: string
  switch (op) {
    case 'eq': sql = `${c} = ${q(val)}`; break
    case 'neq': sql = `${c} <> ${q(val)}`; break
    case 'gt': sql = `${c} > ${q(val)}`; break
    case 'gte': sql = `${c} >= ${q(val)}`; break
    case 'lt': sql = `${c} < ${q(val)}`; break
    case 'lte': sql = `${c} <= ${q(val)}`; break
    case 'like': sql = `${c}::text LIKE ${q(val.replace(/\*/g, '%'))}`; break
    case 'ilike': sql = `${c}::text ILIKE ${q(val.replace(/\*/g, '%'))}`; break
    case 'is': sql = val === 'null' ? `${c} IS NULL` : val === 'true' ? `${c} IS TRUE` : `${c} IS FALSE`; break
    case 'in': {
      const list = val.replace(/^\(|\)$/g, '').split(',').filter((x) => x !== '').map((x) => q(x.replace(/^"|"$/g, '')))
      sql = list.length ? `${c} IN (${list.join(',')})` : 'false'
      break
    }
    case 'cs': sql = `${c} @> ${q(val)}`; break
    default: throw new RestError(400, 'PGRST100', `unsupported operator: ${op}`)
  }
  return neg ? `NOT (${sql})` : sql
}

function orGroup(t: string, raw: string): string {
  const inner = raw.replace(/^\(|\)$/g, '')
  const parts = splitTop(inner).map((p) => {
    const d = p.indexOf('.')
    return cond(t, p.slice(0, d), p.slice(d + 1))
  })
  return `(${parts.join(' OR ')})`
}

function where(t: string, params: URLSearchParams): string {
  const out: string[] = []
  for (const [k, v] of params) {
    if (RESERVED.has(k)) continue
    if (k === 'or') { out.push(orGroup(t, v)); continue }
    if (k.includes('.')) throw new RestError(400, 'PGRST100', `embedded filter unsupported: ${k}`)
    out.push(cond(t, k, v))
  }
  return out.length ? `WHERE ${out.join(' AND ')}` : ''
}

function orderBy(t: string, params: URLSearchParams): string {
  const o = params.get('order')
  if (!o) return ''
  return 'ORDER BY ' + o.split(',').map((part) => {
    const [col, ...mods] = part.split('.')
    let s = `${t}.${ident(col)}`
    if (mods.includes('desc')) s += ' DESC'
    if (mods.includes('nullsfirst')) s += ' NULLS FIRST'
    if (mods.includes('nullslast')) s += ' NULLS LAST'
    return s
  }).join(', ')
}

// ── сесія ──────────────────────────────────────────────────────────────────
/**
 * Клейми ставить DO-блок, а НЕ `SELECT … FROM (SELECT set_config(…)) WHERE false`:
 * константний `false` планувальник відсікає, не обчислюючи підзапит, тож
 * set_config не виконувався НІКОЛИ — і кожен запит ішов без особи, мовчки
 * повертаючи порожнечу. Наступано на першому ж прогоні.
 */
export function prelude(c: Claims): string {
  const claims = JSON.stringify({ sub: c.sub, email: c.email, role: c.role, aud: c.role === 'anon' ? undefined : 'authenticated' })
  return `BEGIN;
SET LOCAL ROLE ${c.role};
DO $pre$ BEGIN
  PERFORM set_config('request.jwt.claims', ${q(claims)}, true);
  PERFORM set_config('request.jwt.claim.sub', ${q(c.sub ?? '')}, true);
  PERFORM set_config('request.jwt.claim.email', ${q(c.email ?? '')}, true);
  PERFORM set_config('request.jwt.claim.role', ${q(c.role)}, true);
END $pre$;
`
}

function wantsObject(headers: Record<string, string>) {
  return (headers['accept'] ?? '').includes('vnd.pgrst.object')
}
function preferOf(headers: Record<string, string>) {
  return (headers['prefer'] ?? '').split(',').map((x) => x.trim())
}

function respond(rows: unknown[], total: number | null, headers: Record<string, string>, status = 200, method = 'GET'): RestResponse {
  const h: Record<string, string> = {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'Content-Range',
  }
  if (total != null) h['content-range'] = `${rows.length ? `0-${rows.length - 1}` : '*'}/${total}`
  if (wantsObject(headers)) {
    if (rows.length !== 1) {
      return { status: 406, headers: h, body: JSON.stringify({ code: 'PGRST116', message: 'JSON object requested, multiple (or no) rows returned', details: `The result contains ${rows.length} rows`, hint: null }) }
    }
    return { status, headers: h, body: method === 'HEAD' ? '' : JSON.stringify(rows[0]) }
  }
  return { status, headers: h, body: method === 'HEAD' ? '' : JSON.stringify(rows) }
}

// ── головний вхід ──────────────────────────────────────────────────────────
export async function handleRest(conn: Conn, claims: Claims, method: string, rawUrl: string,
  headers: Record<string, string>, body: string | null): Promise<RestResponse> {
  try {
    return await handle(conn, claims, method, rawUrl, headers, body)
  } catch (e) {
    const err = e instanceof RestError ? e : new RestError(500, 'XX000', String(e))
    return {
      status: err.status,
      headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
      body: JSON.stringify({ code: err.code, message: err.message, details: err.details, hint: null }),
    }
  }
}

async function handle(conn: Conn, claims: Claims, method: string, rawUrl: string,
  headers: Record<string, string>, body: string | null): Promise<RestResponse> {
  const cat = await catalog(conn)
  const url = new URL(rawUrl)
  const path = url.pathname.replace(/^.*\/rest\/v1\//, '')
  const params = url.searchParams
  const prefer = preferOf(headers)

  if (path.startsWith('rpc/')) return rpc(conn, cat, claims, path.slice(4), method, params, headers, body)

  const table = path
  if (!cat.tables.has(table)) {
    throw new RestError(404, 'PGRST205', `Could not find the table 'public.${table}' in the schema cache`)
  }
  const T = ident(table)
  const items = parseSelect(params.get('select'))
  const proj = projection(cat, table, 't', items)
  const count = prefer.some((p) => p.startsWith('count='))

  if (method === 'GET' || method === 'HEAD') {
    const w = where('t', params)
    const lim = params.get('limit') ? `LIMIT ${Number(params.get('limit'))}` : ''
    const off = params.get('offset') ? `OFFSET ${Number(params.get('offset'))}` : ''
    const sql = `${prelude(claims)}
SELECT json_build_object('rows', COALESCE((SELECT json_agg(r) FROM (SELECT ${proj} FROM ${T} t ${w} ${orderBy('t', params)} ${lim} ${off}) r), '[]'::json),
  'total', ${count ? `(SELECT count(*) FROM ${T} t ${w})` : 'NULL'});
COMMIT;`
    const out = JSON.parse((await psql(conn, sql)).trim())
    return respond(out.rows, out.total, headers, 200, method)
  }

  const returning = prefer.includes('return=representation')
  let mutation: string
  if (method === 'POST') {
    const parsed = body ? JSON.parse(body) : []
    const rows: Record<string, unknown>[] = Array.isArray(parsed) ? parsed : [parsed]
    if (!rows.length) return respond([], null, headers, 201)
    const colsParam = params.get('columns')
    const keys = colsParam ? colsParam.split(',').map((x) => x.replace(/"/g, '')) : [...new Set(rows.flatMap((r) => Object.keys(r)))]
    keys.forEach(ident)
    const values = rows.map((r) => `(${keys.map((k) => (k in r)
      ? `(json_populate_record(NULL::${T}, ${q(JSON.stringify({ [k]: r[k] }))}::json)).${ident(k)}`
      : 'DEFAULT').join(', ')})`).join(',\n')
    let onConflict = ''
    const resolution = prefer.find((p) => p.startsWith('resolution='))
    if (resolution) {
      const target = params.get('on_conflict')
      const tcols = target ? target.split(',').map((x) => ident(x)) : null
      const conflict = tcols ? `(${tcols.join(',')})` : 'ON CONSTRAINT ' + ident(`${table}_pkey`)
      const tset = new Set(target ? target.split(',') : ['id'])
      const upd = keys.filter((k) => !tset.has(k)).map((k) => `${ident(k)} = EXCLUDED.${ident(k)}`)
      onConflict = resolution.includes('ignore') || !upd.length
        ? `ON CONFLICT ${tcols ? conflict : ''} DO NOTHING`
        : `ON CONFLICT ${conflict} DO UPDATE SET ${upd.join(', ')}`
    }
    mutation = `INSERT INTO ${T} AS t (${keys.map(ident).join(', ')}) VALUES ${values} ${onConflict} RETURNING t.*`
  } else if (method === 'PATCH') {
    const patch = body ? JSON.parse(body) : {}
    const keys = Object.keys(patch)
    if (!keys.length) throw new RestError(400, 'PGRST100', 'empty patch')
    const set = keys.map((k) => `${ident(k)} = (json_populate_record(NULL::${T}, ${q(JSON.stringify({ [k]: patch[k] }))}::json)).${ident(k)}`)
    mutation = `UPDATE ${T} AS t SET ${set.join(', ')} ${where('t', params)} RETURNING t.*`
  } else if (method === 'DELETE') {
    mutation = `DELETE FROM ${T} AS t ${where('t', params)} RETURNING t.*`
  } else {
    throw new RestError(405, 'PGRST100', `method ${method}`)
  }

  // `return=minimal` — БЕЗ RETURNING, як у PostgREST: RETURNING вимагає, щоб
  // новий рядок пройшов ще й SELECT-політику, і вставка, яку політика INSERT
  // дозволяє (слід перегляду рієлтора), падала б 42501 лише на стенді.
  if (!returning && !count) {
    await psql(conn, `${prelude(claims)}\n${mutation.replace(/ RETURNING t\.\*$/, '')};\nCOMMIT;`)
    return { status: method === 'POST' ? 201 : 204, headers: { 'access-control-allow-origin': '*' }, body: '' }
  }
  const sql = `${prelude(claims)}
WITH m AS (${mutation})
SELECT json_build_object('rows', COALESCE((SELECT json_agg(r) FROM (SELECT ${returning ? proj : 't.*'} FROM m t) r), '[]'::json),
  'n', (SELECT count(*) FROM m));
COMMIT;`
  if (process.env.LIVE_SQL) console.log('SQL>>', sql)
  const out = JSON.parse((await psql(conn, sql)).trim())
  if (!returning) {
    const h: Record<string, string> = { 'access-control-allow-origin': '*', 'access-control-expose-headers': 'Content-Range' }
    if (count) h['content-range'] = `*/${out.n}`
    return { status: method === 'POST' ? 201 : 204, headers: h, body: '' }
  }
  return respond(out.rows, count ? out.n : null, headers, method === 'POST' ? 201 : 200)
}

async function rpc(conn: Conn, cat: Catalog, claims: Claims, fn: string, method: string,
  params: URLSearchParams, headers: Record<string, string>, body: string | null): Promise<RestResponse> {
  const f = cat.funcs.get(fn)
  if (!f) throw new RestError(404, 'PGRST202', `Could not find the function public.${fn} in the schema cache`)
  const args: Record<string, unknown> = method === 'GET' ? Object.fromEntries(params) : (body ? JSON.parse(body) : {})
  const named = Object.entries(args).filter(([, v]) => v !== undefined).map(([k, v]) => {
    const def = f.args.find((a) => a.name === k)
    if (!def) throw new RestError(404, 'PGRST202', `function ${fn} has no argument ${k}`)
    const lit = v === null ? 'NULL' : typeof v === 'object' ? q(JSON.stringify(v)) : q(String(v))
    return `${ident(k)} => ${lit}::${def.type}`
  })
  const call = `public.${ident(fn)}(${named.join(', ')})`
  const select = f.retset
    ? `SELECT COALESCE(json_agg(r), '[]'::json) FROM ${call} r`
    : f.rettype === 'void' ? `SELECT 'null' FROM (SELECT ${call}) x`
      : f.rettype.startsWith('json') ? `SELECT ${call}::json`
        : `SELECT to_json(${call})`
  // Увесь вивід, а не останній рядок: json_agg розриває масив переносами.
  const out = (await psql(conn, `${prelude(claims)}\n${select};\nCOMMIT;`)).trim()
  const data = JSON.parse(out === '' ? 'null' : out)
  if (wantsObject(headers) && Array.isArray(data)) return respond(data, null, headers)
  return { status: 200, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' }, body: JSON.stringify(data) }
}
