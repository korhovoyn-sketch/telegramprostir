import { z } from 'https://esm.sh/zod@3.23.8'

// ── Telegram bot webhook ──────────────────────────────────────────────────────
// Handles /start (and /start <deep_link_param>) so users who land in the bot
// chat always get an inline button that launches the Mini App — with the
// shared object's start_param preserved.
//
// One-time setup:
//   curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://<project>.supabase.co/functions/v1/telegram-bot&secret_token=<TELEGRAM_WEBHOOK_SECRET>"
//
// Required env (Supabase → Edge Functions → Secrets):
//   TELEGRAM_BOT_TOKEN       — bot API token (already set for telegram-auth)
//   TELEGRAM_WEBHOOK_SECRET  — random string; Telegram echoes it in a header
//   TELEGRAM_BOT_USERNAME    — bot username without @ (e.g. prostirapplbot)
//   TELEGRAM_APP_NAME        — Mini App short name from BotFather /newapp

const UpdateSchema = z.object({
  message: z.object({
    chat: z.object({ id: z.number() }),
    text: z.string().max(512).optional(),
  }).optional(),
})

// Deep-link params our Mini App understands (see src/hooks/useDeepLink.ts).
// Tokens are url-safe — anything else is ignored, never echoed back.
const START_PARAM_RE = /^(db|prop|col)_[A-Za-z0-9_-]{1,128}$/

function buildAppLink(startParam?: string): string {
  const bot = Deno.env.get('TELEGRAM_BOT_USERNAME') ?? ''
  const app = Deno.env.get('TELEGRAM_APP_NAME') ?? ''
  const base = app ? `https://t.me/${bot}/${app}` : `https://t.me/${bot}`
  return startParam ? `${base}?startapp=${encodeURIComponent(startParam)}` : base
}

async function sendMessage(chatId: number, text: string, buttonLabel: string, buttonUrl: string): Promise<void> {
  const token = Deno.env.get('TELEGRAM_BOT_TOKEN')
  if (!token) {
    console.error('[telegram-bot] TELEGRAM_BOT_TOKEN is not set')
    return
  }
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      reply_markup: {
        inline_keyboard: [[{ text: buttonLabel, url: buttonUrl }]],
      },
    }),
  })
  if (!res.ok) {
    console.error(`[telegram-bot] sendMessage failed: ${res.status}`)
  }
}

Deno.serve(async (req) => {
  // Telegram echoes the secret_token registered via setWebhook in this header.
  // Reject anything else — the function is public (--no-verify-jwt).
  const secret = Deno.env.get('TELEGRAM_WEBHOOK_SECRET')
  if (!secret || req.headers.get('x-telegram-bot-api-secret-token') !== secret) {
    return new Response('unauthorized', { status: 401 })
  }

  if (req.method !== 'POST') {
    return new Response('ok', { status: 200 })
  }

  try {
    const parsed = UpdateSchema.safeParse(await req.json())
    const text = parsed.success ? parsed.data.message?.text : undefined
    const chatId = parsed.success ? parsed.data.message?.chat.id : undefined

    if (chatId && text?.startsWith('/start')) {
      const rawParam = text.slice('/start'.length).trim()
      const param = START_PARAM_RE.test(rawParam) ? rawParam : undefined

      if (param) {
        const noun = param.startsWith('db_') ? 'базою нерухомості'
          : param.startsWith('prop_') ? "об'єктом нерухомості"
          : 'підбіркою'
        await sendMessage(
          chatId,
          `З вами поділилися ${noun} у PropSpace. Натисніть кнопку нижче, щоб переглянути 👇`,
          '🏠 Відкрити в PropSpace',
          buildAppLink(param),
        )
      } else {
        await sendMessage(
          chatId,
          'Вітаємо у PropSpace! 🏠\n\nКеруйте нерухомістю, базами об\'єктів та платежами прямо в Telegram. Натисніть кнопку нижче, щоб почати.',
          '🚀 Відкрити PropSpace',
          buildAppLink(),
        )
      }
    }
  } catch (e) {
    // Log server-side only; always return 200 so Telegram doesn't retry-storm.
    console.error('[telegram-bot] update processing failed:', (e as Error).message)
  }

  return new Response('ok', { status: 200 })
})
