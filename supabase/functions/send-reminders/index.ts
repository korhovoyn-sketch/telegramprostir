import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const BOT_TOKEN = Deno.env.get('TELEGRAM_BOT_TOKEN') ?? ''

Deno.serve(async (req) => {
  const auth = req.headers.get('Authorization') ?? ''
  if (auth !== `Bearer ${SERVICE_KEY}`) {
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

  const { data: rows, error } = await admin.rpc('get_due_reminders_today')
  if (error) {
    console.error('[send-reminders] rpc error', error)
    return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500 })
  }

  function escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }

  let sent = 0
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

    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: row.tg_id, text, parse_mode: 'HTML' }),
    })

    if (res.ok) {
      sent++
      // Insert notification record so the deduplication check works next time
      await admin.from('notifications').insert({
        user_id: row.owner_id,
        type: 'rent_reminder',
        title: `Платіж за ${row.property_name}`,
        body: `${row.due_day}-е число${row.tenant_name ? ` · ${row.tenant_name}` : ''}`,
        is_read: false,
        data: { property_id: row.property_id, due_date: row.due_date },
      })
    } else {
      const body = await res.text()
      console.error('[send-reminders] TG error for tg_id', row.tg_id, body)
    }
  }

  return new Response(JSON.stringify({ ok: true, sent }), {
    headers: { 'Content-Type': 'application/json' },
  })
})
