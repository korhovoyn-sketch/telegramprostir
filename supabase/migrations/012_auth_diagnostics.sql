-- ============================================================================
-- PropSpace — AUTH DIAGNOSTICS + FULL RESET  (run in Supabase SQL Editor)
-- ============================================================================
-- Run this script to:
--   1. See exactly what's broken (SELECT queries at the end show current state)
--   2. Apply all fixes in the correct order
--   3. Confirm everything is correct after
--
-- Safe to run multiple times (idempotent).
-- ============================================================================

-- ── STEP 1: Remove legacy auth trigger that breaks GoTrue ────────────────────
DROP TRIGGER  IF EXISTS on_auth_user_created          ON auth.users;
DROP TRIGGER  IF EXISTS on_auth_user_created_trigger   ON auth.users;
DROP TRIGGER  IF EXISTS handle_new_user_trigger        ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user()      CASCADE;

-- ── STEP 2: Ensure current_app_user_id() is correct ─────────────────────────
-- This is the single most important function — ALL RLS checks depend on it.
-- It parses the tg_id from the JWT email claim (format: {tgId}@telegram.propspace.app)
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID AS $$
DECLARE jwt_email TEXT; tg_id_val BIGINT;
BEGIN
  jwt_email := current_setting('request.jwt.claims', true)::jsonb->>'email';
  IF jwt_email IS NULL OR jwt_email NOT LIKE '%@telegram.propspace.app' THEN
    RETURN NULL;
  END IF;
  tg_id_val := SPLIT_PART(jwt_email, '@', 1)::BIGINT;
  RETURN (SELECT id FROM users WHERE tg_id = tg_id_val LIMIT 1);
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public;

-- ── STEP 3: Ensure get_realtor_db_ids / get_owner_db_ids exist ───────────────
CREATE OR REPLACE FUNCTION get_realtor_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT db_id FROM realtor_subscriptions WHERE realtor_id = p_uid
$$;

CREATE OR REPLACE FUNCTION get_owner_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM databases WHERE owner_id = p_uid
$$;

CREATE OR REPLACE FUNCTION get_owner_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM properties WHERE owner_id = p_uid
$$;

CREATE OR REPLACE FUNCTION get_realtor_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id FROM properties p
  WHERE p.db_id IN (SELECT get_realtor_db_ids(p_uid))
$$;

CREATE OR REPLACE FUNCTION get_realtor_collection_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM collections WHERE realtor_id = p_uid
$$;

-- ── STEP 4: Fix prevent_privilege_escalation — allow owner→realtor ───────────
-- Without this: new users who choose "Realtor" stay as "Owner" forever.
CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF current_setting('request.jwt.claims', true) IS NOT NULL
     AND current_setting('request.jwt.claims', true) != '' THEN
    -- Block plan changes from client sessions entirely
    NEW.plan := OLD.plan;
    -- Allow owner→realtor (onboarding), block realtor→owner (escalation)
    IF NEW.role = 'owner' AND OLD.role = 'realtor' THEN
      NEW.role := OLD.role;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_privilege_escalation ON users;
CREATE TRIGGER trg_prevent_privilege_escalation
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION prevent_privilege_escalation();

-- ── STEP 5: Ensure users table has all required columns ─────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_push    BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_weekly  BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_views   BOOLEAN NOT NULL DEFAULT true;

-- ── STEP 6: Ensure rate_limits table exists ──────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
  ip       TEXT        PRIMARY KEY,
  count    INT         NOT NULL DEFAULT 0,
  reset_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 minute'
);
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "rate_limits_service" ON rate_limits;
CREATE POLICY "rate_limits_service" ON rate_limits FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ── STEP 7: Rebuild share_token expiry enforcement ───────────────────────────
DROP POLICY IF EXISTS "db_share_lookup" ON databases;
CREATE POLICY "db_share_lookup" ON databases FOR SELECT
  USING (
    share_token IS NOT NULL
    AND auth.role() = 'authenticated'
    AND (share_expires_at IS NULL OR share_expires_at > now())
  );

-- ── STEP 8: Ensure storage bucket exists ─────────────────────────────────────
INSERT INTO storage.buckets (id, name, public)
VALUES ('photos', 'photos', true)
ON CONFLICT (id) DO NOTHING;

-- Storage policies
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_insert" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete" ON storage.objects;
CREATE POLICY "storage_photos_select" ON storage.objects
  FOR SELECT USING (bucket_id = 'photos');
CREATE POLICY "storage_photos_insert" ON storage.objects
  FOR INSERT WITH CHECK (bucket_id = 'photos' AND auth.role() = 'authenticated');
CREATE POLICY "storage_photos_delete" ON storage.objects
  FOR DELETE USING (bucket_id = 'photos' AND auth.role() = 'authenticated');

-- ── DIAGNOSTICS — read these results to confirm everything is OK ─────────────
-- Run after the script to see the state of the database.

SELECT '=== TRIGGER CHECK (повинно бути 0 рядків) ===' AS check;
SELECT tgname, c.relname
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = 'auth' AND c.relname = 'users' AND NOT t.tgisinternal;

SELECT '=== FUNCTIONS ===' AS check;
SELECT proname, prosecdef
FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'public'
  AND proname IN ('current_app_user_id','get_realtor_db_ids','get_owner_db_ids',
                  'prevent_privilege_escalation','get_owner_property_ids');

SELECT '=== USERS TABLE COLUMNS ===' AS check;
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users'
ORDER BY ordinal_position;

SELECT '=== RLS POLICIES COUNT (повинно бути > 10) ===' AS check;
SELECT tablename, count(*) AS policies
FROM pg_policies WHERE schemaname = 'public'
GROUP BY tablename ORDER BY tablename;

SELECT '=== BUCKETS ===' AS check;
SELECT id, name, public FROM storage.buckets WHERE id = 'photos';

NOTIFY pgrst, 'reload schema';
SELECT 'DONE — all fixes applied' AS result;
