-- ============================================================================
-- 032_fix_rate_limits_rls.sql — HIGH: Prevent rate_limits enumeration attack
-- Idempotent. Run in Supabase SQL Editor.
--
-- Problem: rate_limits table had NO RLS policy for authenticated users.
-- They could SELECT all rows and enumerate all Telegram user IDs (as ip column).
--
-- Fix: Deny all access to authenticated, allow only service_role.
-- ============================================================================

-- rate_limits is internal-only table, never queried by client
-- Explicitly deny all access to authenticated, allow service_role only
DROP POLICY IF EXISTS "rate_limits_deny_auth" ON rate_limits;
DROP POLICY IF EXISTS "rate_limits_service" ON rate_limits;

-- Deny by default
CREATE POLICY "rate_limits_deny_auth" ON rate_limits
  FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- Allow service_role (Edge Functions calling this)
CREATE POLICY "rate_limits_service" ON rate_limits
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ rate_limits RLS policies (must deny authenticated, allow service_role) ════' AS check;
SELECT policyname, roles, qual, with_check
FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'rate_limits'
ORDER BY policyname;

SELECT '════ DONE — rate_limits RLS fix applied ════' AS result;
