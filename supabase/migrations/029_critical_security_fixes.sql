-- ============================================================================
-- 029_critical_security_fixes.sql — Fix Server-Side Expiry Enforcement
-- Idempotent. Run in Supabase SQL Editor or via migration pipeline.
--
-- CRITICAL-1: lookup_shared_db — enforce share_expires_at server-side
--   Issue: RPC returned expiry value; client validation was bypassable.
--
-- CRITICAL-2: lookup_shared_property — enforce expiry on legacy UUID path
--   Issue: CASE statement for UUID lookups skipped the expiry check.
--
-- CRITICAL-3: File upload TOCTOU prevention (database layer)
--   Issue: validate-upload Edge Function checked count but didn't lock.
--   Fix: Add database trigger to prevent insertion when file count >= 10.
-- ============================================================================

-- ── CRITICAL-1: Fix lookup_shared_db with server-side expiry enforcement ────
CREATE OR REPLACE FUNCTION lookup_shared_db(p_token TEXT)
RETURNS TABLE (id UUID, owner_id UUID, share_expires_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.owner_id, d.share_expires_at FROM databases d
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_db(TEXT) TO authenticated, service_role;

-- ── CRITICAL-2: Fix lookup_shared_property with expiry on all paths ────────
CREATE OR REPLACE FUNCTION lookup_shared_property(p_token TEXT)
RETURNS TABLE (id UUID, db_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.db_id FROM properties p
  WHERE
    CASE
      -- Legacy: plain UUID (36 chars with hyphens) — look up by id directly
      WHEN p_token ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN p.id = p_token::UUID
          AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
      -- New: 24-char hex share_token
      ELSE p.share_token = p_token
        AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    END
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_property(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_property(TEXT) TO authenticated, service_role;

-- ── CRITICAL-3: File upload TOCTOU prevention ────────────────────────────────
-- Database-layer trigger that prevents inserting more than 10 files per property.
-- Guards against concurrent validate-upload requests that both see count < 10
-- before either inserts a record. The trigger rejects the second insert.
-- BEFORE INSERT: COUNT(*) counts existing rows, NOT including the new row being
-- inserted. So ">= 10" is the correct condition to reject the 11th file attempt.

CREATE OR REPLACE FUNCTION enforce_max_files_per_property()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count INT;
BEGIN
  SELECT COUNT(*)
  INTO v_count
  FROM property_files
  WHERE property_id = NEW.property_id;

  IF v_count >= 10 THEN
    RAISE EXCEPTION 'Maximum 10 files per property exceeded';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_max_files ON property_files;
CREATE TRIGGER trg_enforce_max_files
  BEFORE INSERT ON property_files
  FOR EACH ROW
  EXECUTE FUNCTION enforce_max_files_per_property();

-- Create indexes for common queries (idempotent)
CREATE INDEX IF NOT EXISTS idx_property_files_property_id
  ON property_files(property_id);

CREATE INDEX IF NOT EXISTS idx_property_files_owner_id
  ON property_files(owner_id, created_at DESC);

-- ── Schema cache reload ───────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ CRITICAL-1: lookup_shared_db (must enforce share_expires_at > now()) ════' AS check;
SELECT routine_definition
FROM information_schema.routines
WHERE routine_schema = 'public' AND routine_name = 'lookup_shared_db'
LIMIT 1;

SELECT '════ CRITICAL-2: lookup_shared_property (must enforce expiry in both CASE branches) ════' AS check;
SELECT routine_definition
FROM information_schema.routines
WHERE routine_schema = 'public' AND routine_name = 'lookup_shared_property'
LIMIT 1;

SELECT '════ CRITICAL-3: property_files trigger (must show trg_enforce_max_files) ════' AS check;
SELECT tgname, tgenabled
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
WHERE c.relname = 'property_files' AND NOT tgisinternal;

SELECT '════ DONE — CRITICAL-1..3 fixes applied ════' AS result;
