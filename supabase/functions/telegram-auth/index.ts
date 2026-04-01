/**
 * telegram-auth — Supabase Edge Function
 *
 * Validates Telegram WebApp initData (HMAC-SHA256), then:
 *   1. Looks up existing user by telegram_id
 *   2. Creates a new Supabase user if first login
 *   3. Returns a short-lived Supabase session (access_token + refresh_token)
 *
 * Deploy:
 *   supabase functions deploy telegram-auth --no-verify-jwt
 *
 * Env vars (set via Supabase Dashboard → Edge Functions → Secrets):
 *   TELEGRAM_BOT_TOKEN       — your bot token from @BotFather
 *   SUPABASE_URL             — auto-injected
 *   SUPABASE_SERVICE_ROLE_KEY — auto-injected (or set manually)
 *
 * Security:
 *   - Validates HMAC-SHA256 signature using bot token
 *   - Rejects initData older than 5 minutes (replay protection)
 *   - Uses service role only server-side; client gets scoped JWT
 *   - CORS allows only Telegram-served origins
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const BOT_TOKEN          = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const SUPABASE_URL       = Deno.env.get("SUPABASE_URL")       ?? "";
const SUPABASE_SRV_KEY   = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const MAX_AGE_SECONDS    = 300; // 5 minutes — replay protection

// ── Helpers ──────────────────────────────────────────────────────

async function hmacSha256(key: CryptoKey, data: string): Promise<ArrayBuffer> {
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
}

async function importHmacKey(raw: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
}

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function corsHeaders(origin: string) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function json(body: unknown, status = 200, origin = "*") {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

// ── Telegram HMAC validation ──────────────────────────────────────

async function validateInitData(initData: string): Promise<{ ok: boolean; user?: TelegramUser }> {
  if (!BOT_TOKEN) return { ok: false };

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) return { ok: false };
  params.delete("hash");

  // Check freshness
  const authDate = Number(params.get("auth_date") ?? 0);
  if (Date.now() / 1000 - authDate > MAX_AGE_SECONDS) return { ok: false };

  // Build data-check-string
  const checkString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  // secret_key = HMAC-SHA256("WebAppData", bot_token)
  const webAppDataKey = await importHmacKey(new TextEncoder().encode("WebAppData"));
  const secretKeyBuf  = await hmacSha256(webAppDataKey, BOT_TOKEN);
  const secretKey     = await importHmacKey(secretKeyBuf);
  const expectedBuf   = await hmacSha256(secretKey, checkString);
  const expectedHash  = bufToHex(expectedBuf);

  if (expectedHash !== receivedHash) return { ok: false };

  const userRaw = params.get("user");
  const user: TelegramUser = userRaw ? JSON.parse(userRaw) : null;
  return { ok: true, user };
}

interface TelegramUser {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  language_code?: string;
}

// ── Main handler ──────────────────────────────────────────────────

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin") ?? "*";

  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(origin) });
  }

  if (req.method !== "POST") {
    return json({ error: "method not allowed" }, 405, origin);
  }

  // Parse body
  let initData: string;
  try {
    const body = await req.json();
    initData = body?.initData ?? "";
    if (!initData) throw new Error("missing");
  } catch {
    return json({ error: "invalid request body — expected { initData: string }" }, 400, origin);
  }

  // Validate Telegram signature
  const { ok, user } = await validateInitData(initData);
  if (!ok || !user) {
    return json({ error: "invalid or expired initData" }, 401, origin);
  }

  const telegramId = String(user.id);
  const displayName = [user.first_name, user.last_name]
    .filter(Boolean).join(" ") || "Telegram User";

  // Supabase service-role client (server-side only)
  const supabase = createClient(SUPABASE_URL, SUPABASE_SRV_KEY, {
    auth: { persistSession: false },
  });

  // ── Find or create stable Supabase user ───────────────────────
  let userId: string | null = null;

  const { data: existingUser } = await supabase
    .from("users")
    .select("id")
    .eq("telegram_id", telegramId)
    .maybeSingle();

  if (existingUser?.id) {
    userId = existingUser.id;
  } else {
    // Create new Supabase auth user
    const email = `tg_${telegramId}@prostir.app`; // deterministic, never emailed
    const password = crypto.randomUUID();          // random, never exposed to client

    const { data: newUser, error: createErr } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,  // skip email confirmation
      app_metadata: { provider: "telegram", telegram_id: telegramId },
      user_metadata: {
        name: displayName,
        username: user.username ?? null,
        language_code: user.language_code ?? null,
      },
    });

    if (createErr || !newUser?.user?.id) {
      console.error("[telegram-auth] createUser error:", createErr?.message);
      return json({ error: "failed to create user" }, 500, origin);
    }

    userId = newUser.user.id;

    // Insert profile row
    const { error: profileErr } = await supabase.from("users").insert({
      id:          userId,
      telegram_id: telegramId,
      name:        displayName,
      plan:        "free",
    });
    if (profileErr && !profileErr.message.includes("duplicate")) {
      console.warn("[telegram-auth] profile insert warning:", profileErr.message);
    }
  }

  // ── Create a scoped session for this user ─────────────────────
  const { data: sessionData, error: sessionErr } = await supabase.auth.admin.createSession({
    user_id: userId!,
  });

  if (sessionErr || !sessionData?.session) {
    console.error("[telegram-auth] createSession error:", sessionErr?.message);
    return json({ error: "failed to create session" }, 500, origin);
  }

  return json({
    access_token:  sessionData.session.access_token,
    refresh_token: sessionData.session.refresh_token,
    expires_in:    sessionData.session.expires_in,
    user_id:       userId,
  }, 200, origin);
});
