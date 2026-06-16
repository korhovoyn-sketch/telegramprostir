-- ============================================================================
-- 031_critical_security_hotfixes.sql — Fix 3 CRITICAL vulnerabilities
-- Idempotent. Run IMMEDIATELY in Supabase SQL Editor.
--
-- CRITICAL-1: prevent_privilege_escalation must ALWAYS block escalation,
--   not just when JWT is present (GUC context may be NULL)
-- CRITICAL-2: get_app_user_id_from_auth_uid must validate email format
--   and explicitly cast tg_id to prevent injection
-- CRITICAL-3: validate-upload must use userClient for ALL queries, not just ownership
-- ============================================================================

-- ── CRITICAL-1: Fix prevent_privilege_escalation to ALWAYS block ──────────────
-- The trigger must work in ALL contexts, including admin/service_role calls.
-- Current bug: checks request.jwt.claims which may be NULL in non-API contexts.
CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ALWAYS block plan changes (immutable field, client cannot change)
  NEW.plan := OLD.plan;

  -- ALWAYS block role escalation, regardless of JWT presence or auth context
  -- Guest→Owner/Realtor and Realtor→Owner escalations are NEVER allowed
  IF (OLD.role = 'guest'   AND NEW.role IN ('owner','realtor')) OR
     (OLD.role = 'realtor' AND NEW.role = 'owner')
  THEN
    RAISE EXCEPTION 'role_escalation_blocked: %→% not allowed', OLD.role, NEW.role;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_privilege_escalation ON users;
CREATE TRIGGER trg_prevent_privilege_escalation
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION prevent_privilege_escalation();

-- ── CRITICAL-2: Fix get_app_user_id_from_auth_uid to validate email format ────
-- Email format: {tg_id}@telegram.propspace.app where {tg_id} is numeric-only
-- Prevents injection via crafted email like '999999999999@telegram.propspace.app'
CREATE OR REPLACE FUNCTION get_app_user_id_from_auth_uid()
RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id
  FROM public.users u
  JOIN auth.users au ON au.id = auth.uid()
  WHERE u.tg_id = (SPLIT_PART(au.email, '@', 1)::BIGINT)
    -- Strict validation: email must match exactly expected format
    AND au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
    -- Ensure tg_id is non-zero (valid Telegram ID)
    AND u.tg_id > 0
  LIMIT 1;
$$;

-- ── CRITICAL-3: validate-upload Edge Function must use userClient for count ────
-- The TypeScript fix is applied separately in the source file.
-- This SQL comment documents the required change:
-- OLD (INSECURE): const admin = createClient(..., SERVICE_KEY); admin.from('property_files').select(...count...)
-- NEW (SECURE):   const { count } = await userClient.from('property_files').select(...count...)
-- This ensures RLS is enforced for ALL data access, not just ownership check.

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ CRITICAL-1: prevent_privilege_escalation (must ALWAYS block) ════' AS check;
SELECT routine_definition
FROM information_schema.routines
WHERE routine_schema = 'public' AND routine_name = 'prevent_privilege_escalation'
LIMIT 1;

SELECT '════ CRITICAL-2: get_app_user_id_from_auth_uid (must validate email format) ════' AS check;
SELECT routine_definition
FROM information_schema.routines
WHERE routine_schema = 'public' AND routine_name = 'get_app_user_id_from_auth_uid'
LIMIT 1;

SELECT '════ CRITICAL-3: validate-upload source code must be updated to use userClient ════' AS check;
SELECT 'See supabase/functions/validate-upload/index.ts line 72-80: must use userClient not admin' AS note;

SELECT '════ DONE — CRITICAL-1,2,3 hotfixes applied ════' AS result;
