-- ============================================================================
-- 026_security_audit_fixes.sql — Security Audit Remediation
-- Idempotent. Run in Supabase SQL Editor or via migration pipeline.
--
-- AUDIT-1  get_shared_collection(UUID) — add share_expires_at check; revoke
--          anon access (function is only called from authenticated app context)
-- AUDIT-2  pfiles_storage_select — narrow from "any authenticated user" to
--          property owner or subscribed realtor only
-- AUDIT-3  audit_log — add missing indexes (table was created without any)
-- AUDIT-4  rate_limits — auto-prune stale entries via AFTER INSERT/UPDATE trigger
-- ============================================================================

-- ── AUDIT-1: Fix get_shared_collection ───────────────────────────────────────
-- The 018 migration omitted the share_expires_at check, so expired shared
-- collections remained readable indefinitely. Also: the original GRANT included
-- anon, but this function is only called from inside the authenticated Mini App.
CREATE OR REPLACE FUNCTION get_shared_collection(p_collection_id UUID)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_col RECORD;
BEGIN
  SELECT id, name INTO v_col
  FROM collections
  WHERE id = p_collection_id
    AND is_draft = false
    AND (share_expires_at IS NULL OR share_expires_at > now());
  IF NOT FOUND THEN RETURN NULL; END IF;

  RETURN jsonb_build_object(
    'id',   v_col.id,
    'name', v_col.name,
    'properties', COALESCE((
      SELECT jsonb_agg(
        jsonb_build_object(
          'id',          p.id,
          'name',        p.name,
          'status',      p.status,
          'area_useful', p.area_useful,
          'area_total',  p.area_total,
          'rent_rate',   p.rent_rate,
          'rent_type',   p.rent_type,
          'floor',       p.floor,
          'first_photo', (
            SELECT storage_path FROM property_photos
            WHERE property_id = p.id
            ORDER BY sort_order, created_at
            LIMIT 1
          )
        ) ORDER BY p.sort_order, p.created_at
      )
      FROM collection_properties cp
      JOIN properties p ON p.id = cp.property_id
      WHERE cp.collection_id = v_col.id
    ), '[]'::jsonb)
  );
END;
$$;

REVOKE ALL ON FUNCTION get_shared_collection(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_shared_collection(UUID) TO authenticated, service_role;

-- ── AUDIT-2: Restrict pfiles_storage_select to owner / subscribed realtor ────
-- The previous policy (from 023) allowed ANY authenticated user to list and
-- download every file from the private property-files bucket — a full privacy
-- leak of confidential property documents across all tenants.
-- Fix: the first path segment is always the property UUID (upload path convention
-- is {propertyId}/{timestamp}_{rand}.ext); enforce ownership there.
DROP POLICY IF EXISTS "pfiles_storage_select" ON storage.objects;

CREATE POLICY "pfiles_storage_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'property-files'
    AND (
      -- Property owner
      SPLIT_PART(name, '/', 1) IN (
        SELECT p.id::text FROM public.properties p
        WHERE p.owner_id = public.current_app_user_id()
      )
      OR
      -- Realtor subscribed to the property's database
      SPLIT_PART(name, '/', 1) IN (
        SELECT p.id::text FROM public.properties p
        WHERE p.db_id IN (SELECT public.get_realtor_db_ids(public.current_app_user_id()))
      )
    )
  );

-- ── AUDIT-3: audit_log indexes ────────────────────────────────────────────────
-- The table was created in 014 with no indexes. Queries filtering by user_id
-- or looking up a specific record for forensics do full table scans without these.
CREATE INDEX IF NOT EXISTS idx_audit_log_user_created
  ON audit_log(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_table_record
  ON audit_log(table_name, record_id);

-- ── AUDIT-4: rate_limits auto-prune ──────────────────────────────────────────
-- The rate_limits table is an ever-growing accumulation of one row per user.
-- Rows are reset (upserted) on each auth request but never deleted.
-- This AFTER INSERT/UPDATE statement-level trigger prunes rows whose
-- reset_at has been expired for >2 minutes, in batches of up to 50.
CREATE OR REPLACE FUNCTION prune_expired_rate_limits()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  DELETE FROM rate_limits
  WHERE ip IN (
    SELECT ip FROM rate_limits
    WHERE reset_at < now() - INTERVAL '2 minutes'
    LIMIT 50
  );
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_prune_rate_limits ON rate_limits;
CREATE TRIGGER trg_prune_rate_limits
  AFTER INSERT OR UPDATE ON rate_limits
  FOR EACH STATEMENT
  EXECUTE FUNCTION prune_expired_rate_limits();

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ AUDIT-1: get_shared_collection grants (must not include PUBLIC/anon) ════' AS check;
SELECT grantee, privilege_type
FROM information_schema.routine_privileges
WHERE specific_schema = 'public' AND routine_name = 'get_shared_collection'
ORDER BY grantee;

SELECT '════ AUDIT-2: pfiles_storage_select (must reference SPLIT_PART ownership check) ════' AS check;
SELECT policyname, cmd, roles, qual
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'pfiles_storage_select';

SELECT '════ AUDIT-3: audit_log indexes (must have 2 new) ════' AS check;
SELECT indexname FROM pg_indexes
WHERE schemaname = 'public' AND tablename = 'audit_log'
ORDER BY indexname;

SELECT '════ AUDIT-4: rate_limits trigger (must show trg_prune_rate_limits) ════' AS check;
SELECT tgname, tgenabled
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
WHERE c.relname = 'rate_limits' AND NOT tgisinternal;

SELECT '════ DONE — AUDIT-1..4 applied ════' AS result;
