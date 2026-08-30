// deno-lint-ignore-file no-explicit-any
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const BOT_TOKEN = Deno.env.get('TELEGRAM_BOT_TOKEN') ?? ''

// Telegram sendMessage can hang on a stalled connection; without a bound one
// slow/dead socket would block the whole reminder run (and eventually the
// function's wall-clock budget), silently dropping every later reminder.
const TG_TIMEOUT_MS = 10_000

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Constant-time compare for the caller's bearer token — a plain !== leaks the
// SERVICE_KEY prefix/length via response timing. Matches the constant-time
// discipline in telegram-auth's HMAC check and telegram-bot's webhook secret.
function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder()
  const ab = enc.encode(a)
  const bb = enc.encode(b)
  if (ab.length !== bb.length) return false
  let mismatch = 0
  for (let i = 0; i < ab.length; i++) mismatch |= ab[i] ^ bb[i]
  return mismatch === 0
}

async function sendTelegramMessage(chatId: number, text: string): Promise<Response | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TG_TIMEOUT_MS)
  try {
    return await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
      signal: controller.signal,
    })
  } catch (err) {
    // Timeout (abort) or network error — treat as a failed send for this row,
    // don't let it bubble up and kill the remaining reminders.
    console.error('[send-reminders] TG fetch failed for chat', chatId, err instanceof Error ? err.message : String(err))
    return null
  } finally {
    clearTimeout(timer)
  }
}

Deno.serve(async (req) => {
  const auth = req.headers.get('Authorization') ?? ''
  if (!SERVICE_KEY || !timingSafeEqual(auth, `Bearer ${SERVICE_KEY}`)) {
    return new Response('Unauthorized', { status: 401 })
  }
  if (!SUPABASE_URL || !SERVICE_KEY) {
    return new Response('Missing env vars', { status: 500 })
  }
  if (!BOT_TOKEN) {
    return new Response('TELEGRAM_BOT_TOKEN not set', { status: 500 })
  }

  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false },
  })

  type ReminderRow = {
    owner_id: string
    tg_id: number
    property_id: string
    property_name: string
    due_day: number
    tenant_name: string | null
    due_date: string
  }

  type LeaseReminderRow = {
    owner_id: string
    tg_id: number
    property_id: string
    property_name: string
    tenant_name: string | null
    lease_end_date: string
    days_left: number
  }

  type GuestReminderRow = {
    guest_id: string
    tg_id: number
    property_id: string
    property_name: string
    due_day: number
    due_date: string
  }

  // Owner and guest reminders are independent: a failure in one RPC (or one
  // recipient batch) must NOT suppress the other. Each block owns its try/catch
  // and records its own error so the response reflects partial success.
  let sent = 0
  let sentGuests = 0
  let sentLease = 0
  const errors: string[] = []

  // ── Owner reminders ─────────────────────────────────────────────────────────
  try {
    const { data: rows, error } = await admin.rpc('get_due_reminders_today')
    if (error) throw error

    for (const row of (rows ?? []) as ReminderRow[]) {
      const text = [
        '💸 <b>Нагадування про оплату оренди</b>',
        '',
        `🏢 <b>${escapeHtml(row.property_name)}</b>`,
        row.tenant_name ? `👤 Орендар: ${escapeHtml(row.tenant_name)}` : '',
        `📅 Дата оплати: ${row.due_day}-е число місяця`,
        '',
        'Відкрийте PropSpace для підтвердження отримання.',
      ].filter(Boolean).join('\n')

      const res = await sendTelegramMessage(row.tg_id, text)
      if (res?.ok) {
        sent++
        // Insert notification record so the deduplication check works next time
        const { error: notifError } = await admin.from('notifications').insert({
          user_id: row.owner_id,
          type: 'rent_reminder',
          title: `Платіж за ${row.property_name}`,
          body: `${row.due_day}-е число${row.tenant_name ? ` · ${row.tenant_name}` : ''}`,
          is_read: false,
          data: { property_id: row.property_id, due_date: row.due_date },
        })
        if (notifError) console.error('[send-reminders] notification insert failed for property', row.property_id, notifError.message)
      } else if (res) {
        const body = await res.text()
        console.error('[send-reminders] TG error for tg_id', row.tg_id, body)
      }
    }
  } catch (err) {
    console.error('[send-reminders] owner block failed', err instanceof Error ? err.message : String(err))
    errors.push('owner')
  }

  // ── Guest reminders ─────────────────────────────────────────────────────────
  try {
    const { data: guestRows, error: guestError } = await admin.rpc('get_due_guest_reminders')
    if (guestError) throw guestError

    for (const row of (guestRows ?? []) as GuestReminderRow[]) {
      const text = [
        '💸 <b>Нагадування про оплату оренди</b>',
        '',
        `🏢 <b>${escapeHtml(row.property_name)}</b>`,
        `📅 Дата оплати: ${row.due_day}-е число місяця`,
        '',
        'Відкрийте PropSpace для перегляду деталей.',
      ].join('\n')

      const res = await sendTelegramMessage(row.tg_id, text)
      if (res?.ok) {
        sentGuests++
        const { error: notifError } = await admin.from('notifications').insert({
          user_id: row.guest_id,
          type: 'rent_reminder',
          title: `Платіж за ${row.property_name}`,
          body: `${row.due_day}-е число`,
          is_read: false,
          data: { property_id: row.property_id, due_date: row.due_date },
        })
        if (notifError) console.error('[send-reminders] guest notification insert failed', row.property_id, notifError.message)
      } else if (res) {
        const body = await res.text()
        console.error('[send-reminders] TG guest error for tg_id', row.tg_id, body)
      }
    }
  } catch (err) {
    console.error('[send-reminders] guest block failed', err instanceof Error ? err.message : String(err))
    errors.push('guest')
  }

  // ── Кінець договору ─────────────────────────────────────────────────────────
  // Той самий незалежний блок, що й два вище: збій RPC чи одного одержувача не
  // має гасити решту. Пороги {30, 7, 1, 0} задає сама функція; дедуп ключується
  // датою договору, тож продовження відкриває нову серію нагадувань.
  try {
    const { data: leaseRows, error: leaseError } = await admin.rpc('get_due_lease_reminders')
    if (leaseError) throw leaseError

    for (const row of (leaseRows ?? []) as LeaseReminderRow[]) {
      const when = row.days_left === 0 ? 'сьогодні'
        : row.days_left === 1 ? 'завтра'
        : `через ${row.days_left} ${row.days_left >= 5 ? 'днів' : 'дні'}`
      const text = [
        '📄 <b>Договір добігає кінця</b>',
        '',
        `🏢 <b>${escapeHtml(row.property_name)}</b>`,
        row.tenant_name ? `👤 Орендар: ${escapeHtml(row.tenant_name)}` : '',
        `📅 Закінчується ${when} (${row.lease_end_date})`,
        '',
        'Відкрийте PropSpace, щоб продовжити або звільнити обʼєкт.',
      ].filter(Boolean).join('\n')

      const res = await sendTelegramMessage(row.tg_id, text)
      if (res?.ok) {
        sentLease++
        // Рядок пишеться ЛИШЕ на успішній відправці — він і є маркером дедупу
        // для наступного прогону (див. NOT EXISTS у 065).
        const { error: notifError } = await admin.from('notifications').insert({
          user_id: row.owner_id,
          type: 'lease_reminder',
          title: `Договір: ${row.property_name}`,
          body: `Закінчується ${when}${row.tenant_name ? ` · ${row.tenant_name}` : ''}`,
          is_read: false,
          data: {
            property_id: row.property_id,
            lease_end_date: row.lease_end_date,
            days_left: row.days_left,
          },
        })
        if (notifError) console.error('[send-reminders] lease notification insert failed', row.property_id, notifError.message)
      } else if (res) {
        const body = await res.text()
        console.error('[send-reminders] TG lease error for tg_id', row.tg_id, body)
      }
    }
  } catch (err) {
    console.error('[send-reminders] lease block failed', err instanceof Error ? err.message : String(err))
    errors.push('lease')
  }

  return new Response(JSON.stringify({ ok: errors.length === 0, sent, sentGuests, sentLease, failed: errors }), {
    headers: { 'Content-Type': 'application/json' },
  })
})
