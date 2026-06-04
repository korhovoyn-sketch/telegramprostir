-- PropSpace v1.0.0 — Migration 007: Persistent rate limiting table
--
-- Replaces the in-memory Map in the Edge Function (which is reset on every
-- cold start) with a DB-backed counter that survives across invocations.
--
-- APPLY: Supabase Dashboard → SQL Editor → paste and run.

CREATE TABLE IF NOT EXISTS rate_limits (
  ip       TEXT        PRIMARY KEY,
  count    INT         NOT NULL DEFAULT 0,
  reset_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 minute'
);

-- Only service_role should touch this table — no RLS policies needed,
-- but enable RLS so the anon key cannot access it at all.
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
