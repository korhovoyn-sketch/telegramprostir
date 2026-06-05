-- ============================================================================
-- PropSpace — Security Hardening (run after 013_master_setup.sql)
-- ============================================================================
-- Fixes:
--   SEC-1  Storage INSERT policy: restore property-ownership check (013 downgraded it)
--   SEC-2  Storage DELETE policy: restrict to property owner (was any authenticated)
--   SEC-3  property_views INSERT: bind viewer_id to current user (prevent view spoof)
--   SEC-4  property_views DELETE: allow owner to purge view records
--   SEC-5  Remove dangerous db_share_lookup policy if it was re-added by 010/012
--   SEC-6  Add VARCHAR length limits on critical user-input columns
--   SEC-7  Audit log table + trigger for role/plan changes
--   SEC-8  GDPR delete_my_account() function
-- ============================================================================

-- ── SEC-1 & SEC-2: Restore strict storage policies ───────────────────────────
-- 013 replaced 007's property-ownership check with a weaker "just be authenticated"
-- policy. This re-adds the ownership verification.

DROP POLICY IF EXISTS "storage_photos_insert"    ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete"    ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_update"    ON storage.objects;
DROP POLICY IF EXISTS "photos_upload_owner"      ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_owner"      ON storage.objects;
DROP POLICY IF EXISTS "photos_update_owner"      ON storage.objects;

-- INSERT: caller must own the property referenced in the first path segment.
-- SPLIT_PART(name, ...) is kept OUTSIDE the EXISTS subquery so `name` is
-- unambiguously storage.objects.name — not properties.name — preventing the
-- "cannot alter type of a column used in a policy definition" error that fires
-- when SEC-6 later changes properties.name to VARCHAR.
CREATE POLICY "storage_photos_insert" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = current_app_user_id()
    )
  );

-- DELETE: same ownership check
CREATE POLICY "storage_photos_delete" ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND SPLIT_PART(name, '/', 1) IN (
      SELECT p.id::text FROM public.properties p
      WHERE p.owner_id = current_app_user_id()
    )
  );

-- UPDATE: photos are immutable — upload new, delete old
CREATE POLICY "storage_photos_update" ON storage.objects
  FOR UPDATE TO authenticated
  USING (false)
  WITH CHECK (false);

-- ── SEC-3: property_views INSERT — bind viewer_id to the actual caller ────────
-- Previous policy: WITH CHECK (auth.role() = 'authenticated') — anyone could
-- insert views with a fake viewer_id or for properties they don't have access to.
-- New policy: viewer_id must be NULL or equal to the caller's public user ID.

DROP POLICY IF EXISTS "views_insert_auth"  ON property_views;
DROP POLICY IF EXISTS "views_insert_all"   ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT
  WITH CHECK (
    auth.role() = 'authenticated'
    AND (viewer_id IS NULL OR viewer_id = current_app_user_id())
  );

-- ── SEC-4: property_views DELETE — owner can purge old records ────────────────
CREATE POLICY "views_owner_delete" ON property_views
  FOR DELETE
  USING (
    property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  );

-- ── SEC-5: Remove db_share_lookup if re-added by 010/012 after 013 ────────────
-- This policy leaks ALL active share_tokens to any authenticated user.
-- Resolution is handled by the SECURITY DEFINER lookup_shared_db() function.
DROP POLICY IF EXISTS "db_share_lookup" ON databases;

-- ── SEC-6: VARCHAR length limits on user-input columns ───────────────────────
-- Prevents oversized payloads that bypass client-side validation.
-- TEXT → VARCHAR does not require table rewrite in Postgres.

ALTER TABLE users       ALTER COLUMN first_name    TYPE VARCHAR(100);
ALTER TABLE users       ALTER COLUMN last_name     TYPE VARCHAR(100);
ALTER TABLE users       ALTER COLUMN tg_username   TYPE VARCHAR(64);
ALTER TABLE users       ALTER COLUMN email         TYPE VARCHAR(254);  -- RFC 5321 max
ALTER TABLE users       ALTER COLUMN phone         TYPE VARCHAR(32);

ALTER TABLE databases   ALTER COLUMN name          TYPE VARCHAR(200);
ALTER TABLE databases   ALTER COLUMN address       TYPE VARCHAR(500);

ALTER TABLE properties  ALTER COLUMN name          TYPE VARCHAR(200);
ALTER TABLE properties  ALTER COLUMN floor         TYPE VARCHAR(32);
ALTER TABLE properties  ALTER COLUMN description   TYPE VARCHAR(4000);
ALTER TABLE properties  ALTER COLUMN tenant_name   TYPE VARCHAR(200);

ALTER TABLE collections ALTER COLUMN name          TYPE VARCHAR(200);

ALTER TABLE notifications ALTER COLUMN title       TYPE VARCHAR(500);
ALTER TABLE notifications ALTER COLUMN body        TYPE VARCHAR(2000);

-- ── SEC-7: Audit log for privileged operations ────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID,
  action     TEXT        NOT NULL,
  table_name TEXT        NOT NULL,
  record_id  UUID,
  old_data   JSONB,
  new_data   JSONB,
  ip_hint    TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Only service_role can read audit log (admins only)
CREATE POLICY "audit_log_service" ON audit_log
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- Trigger: log role and plan changes on users table
CREATE OR REPLACE FUNCTION audit_users_sensitive()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Only log if role or plan changed
  IF NEW.role IS DISTINCT FROM OLD.role OR NEW.plan IS DISTINCT FROM OLD.plan THEN
    INSERT INTO audit_log (user_id, action, table_name, record_id, old_data, new_data)
    VALUES (
      NEW.id,
      'UPDATE',
      'users',
      NEW.id,
      jsonb_build_object('role', OLD.role, 'plan', OLD.plan),
      jsonb_build_object('role', NEW.role, 'plan', NEW.plan)
    );
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_users ON users;
CREATE TRIGGER trg_audit_users
  AFTER UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION audit_users_sensitive();

-- ── SEC-8: GDPR — delete_my_account() ────────────────────────────────────────
-- Allows a user to delete their own account (public.users + auth.users cascade).
-- Note: auth.users deletion requires service_role — this function is SECURITY DEFINER.
-- The function verifies the caller IS the account owner before deletion.
CREATE OR REPLACE FUNCTION delete_my_account()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id   UUID;
  v_auth_uid  UUID;
BEGIN
  v_user_id := current_app_user_id();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  -- Cascade in public.users removes all associated data via FK ON DELETE CASCADE
  DELETE FROM users WHERE id = v_user_id;

  -- Also remove auth.users entry to prevent orphaned JWT sessions
  -- Requires SECURITY DEFINER with admin rights
  SELECT id INTO v_auth_uid FROM auth.users
  WHERE email LIKE (
    SELECT tg_id::text || '@telegram.propspace.app' FROM users WHERE id = v_user_id
  );
  IF v_auth_uid IS NOT NULL THEN
    DELETE FROM auth.users WHERE id = v_auth_uid;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION delete_my_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delete_my_account() TO authenticated;

-- ── Reload PostgREST schema cache ────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '════ STORAGE POLICIES (check for ownership-based insert) ════' AS check;
SELECT policyname, cmd, roles, qual
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
ORDER BY policyname;

SELECT '════ property_views POLICIES ════' AS check;
SELECT policyname, cmd, qual
FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'property_views'
ORDER BY policyname;

SELECT '════ AUDIT LOG TABLE ════' AS check;
SELECT column_name, data_type FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'audit_log'
ORDER BY ordinal_position;

SELECT '════ NO db_share_lookup POLICY (must be 0 rows) ════' AS check;
SELECT policyname FROM pg_policies
WHERE schemaname = 'public' AND tablename = 'databases' AND policyname = 'db_share_lookup';

SELECT '════ VARCHAR LIMITS CHECK ════' AS check;
SELECT column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN ('users', 'databases', 'properties', 'collections', 'notifications')
  AND column_name IN ('first_name', 'name', 'email', 'title', 'description', 'floor')
ORDER BY table_name, column_name;

SELECT '════ DONE — SEC-1..8 applied ════' AS result;
