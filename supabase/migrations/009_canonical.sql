-- ============================================================================
-- PropSpace — CANONICAL STATE v1.0  (safe to run multiple times)
-- ============================================================================
-- Purpose: bring ANY existing database to the exact state the app expects,
-- regardless of which prior migrations were applied or in which order.
--
-- Fixes addressed here:
--   1. views_insert_all (003) was insecure — replaced with views_insert_auth
--   2. db_share_lookup (004) may have been wiped by 003 if 003 ran after 004
--   3. notification_push/weekly/views columns may be missing (006)
--   4. rate_limits table may be missing (007)
--   5. Duplicate tg_id indexes (users_tg_id_unique + users_tg_id_idx)
--   6. storage.objects policies conflicts between 003, 007, 008
-- ============================================================================

-- ── 1. ENSURE NOTIFICATION PREFERENCE COLUMNS EXIST ─────────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS notification_push    BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS notification_weekly  BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS notification_views   BOOLEAN NOT NULL DEFAULT true;

-- ── 2. ENSURE RATE LIMITS TABLE EXISTS ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
  ip       TEXT        PRIMARY KEY,
  count    INT         NOT NULL DEFAULT 0,
  reset_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 minute'
);
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- ── 3. DEDUPLICATE tg_id INDEXES ─────────────────────────────────────────────
-- 003 creates users_tg_id_unique (partial), 005 creates users_tg_id_idx (full).
-- Keep only the unique partial index — it is strictly more useful.
DROP INDEX IF EXISTS users_tg_id_idx;
CREATE UNIQUE INDEX IF NOT EXISTS users_tg_id_unique ON users(tg_id) WHERE tg_id IS NOT NULL;

-- ── 4. DROP ALL PUBLIC RLS POLICIES AND REBUILD CORRECTLY ───────────────────
DO $$ DECLARE r RECORD; BEGIN
  FOR r IN SELECT policyname, tablename
           FROM pg_policies WHERE schemaname = 'public' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', r.policyname, r.tablename);
  END LOOP;
END $$;

ALTER TABLE users                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE databases             ENABLE ROW LEVEL SECURITY;
ALTER TABLE properties            ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_photos       ENABLE ROW LEVEL SECURITY;
ALTER TABLE realtor_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE collections           ENABLE ROW LEVEL SECURITY;
ALTER TABLE collection_properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_views        ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications         ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits           ENABLE ROW LEVEL SECURITY;

-- USERS
CREATE POLICY "users_own"     ON users FOR ALL
  USING (id = current_app_user_id())
  WITH CHECK (id = current_app_user_id());
CREATE POLICY "users_service" ON users FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- DATABASES
CREATE POLICY "db_owner_all"      ON databases FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());
CREATE POLICY "db_realtor_select" ON databases FOR SELECT
  USING (id IN (SELECT get_realtor_db_ids(current_app_user_id())));
-- CRITICAL: allows any authenticated user to find a DB by its share_token
-- (needed before subscription exists, so QR scan / deep-link can work)
CREATE POLICY "db_share_lookup"   ON databases FOR SELECT
  USING (share_token IS NOT NULL AND auth.role() = 'authenticated');
CREATE POLICY "db_service"        ON databases FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- PROPERTIES
CREATE POLICY "props_owner_all"      ON properties FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());
CREATE POLICY "props_realtor_select" ON properties FOR SELECT
  USING (db_id IN (SELECT get_realtor_db_ids(current_app_user_id())));
CREATE POLICY "props_service"        ON properties FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- PROPERTY_PHOTOS
CREATE POLICY "photos_owner_all" ON property_photos FOR ALL
  USING (property_id IN (
    SELECT id FROM properties WHERE owner_id = current_app_user_id()
  ))
  WITH CHECK (property_id IN (
    SELECT id FROM properties WHERE owner_id = current_app_user_id()
  ));
CREATE POLICY "photos_realtor_select" ON property_photos FOR SELECT
  USING (property_id IN (
    SELECT p.id FROM properties p
    WHERE p.db_id IN (SELECT get_realtor_db_ids(current_app_user_id()))
  ));

-- REALTOR_SUBSCRIPTIONS
CREATE POLICY "subs_realtor_all"  ON realtor_subscriptions FOR ALL
  USING (realtor_id = current_app_user_id())
  WITH CHECK (realtor_id = current_app_user_id());
CREATE POLICY "subs_owner_select" ON realtor_subscriptions FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

-- COLLECTIONS
CREATE POLICY "col_realtor_all" ON collections FOR ALL
  USING (realtor_id = current_app_user_id())
  WITH CHECK (realtor_id = current_app_user_id());

-- COLLECTION_PROPERTIES
CREATE POLICY "col_props_realtor_all" ON collection_properties FOR ALL
  USING (collection_id IN (
    SELECT id FROM collections WHERE realtor_id = current_app_user_id()
  ))
  WITH CHECK (collection_id IN (
    SELECT id FROM collections WHERE realtor_id = current_app_user_id()
  ));

-- PROPERTY_VIEWS
CREATE POLICY "views_owner_select" ON property_views FOR SELECT
  USING (property_id IN (
    SELECT id FROM properties WHERE owner_id = current_app_user_id()
  ));
-- Secure insert: viewer_id must be own user (or NULL for anonymous tracking)
CREATE POLICY "views_insert_auth"  ON property_views FOR INSERT
  WITH CHECK (
    viewer_id IS NULL OR viewer_id = current_app_user_id()
  );

-- NOTIFICATIONS
CREATE POLICY "notifs_own"     ON notifications FOR ALL
  USING (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());
CREATE POLICY "notifs_service" ON notifications FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- RATE_LIMITS: service_role only; anon key gets nothing
CREATE POLICY "rate_limits_service" ON rate_limits FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ── 5. STORAGE BUCKET + POLICIES ────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'photos', 'photos', true, 10485760,
  ARRAY['image/jpeg','image/jpg','image/png','image/webp','image/heic','image/heif']
)
ON CONFLICT (id) DO UPDATE
  SET public             = true,
      file_size_limit    = 10485760,
      allowed_mime_types = ARRAY['image/jpeg','image/jpg','image/png','image/webp','image/heic','image/heif'];

-- Drop every known variant of the storage photo policies
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_insert" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_update" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete" ON storage.objects;
DROP POLICY IF EXISTS "photos_upload_owner"   ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_owner"   ON storage.objects;
DROP POLICY IF EXISTS "photos_update_owner"   ON storage.objects;
DROP POLICY IF EXISTS "photos_read_public"    ON storage.objects;
DROP POLICY IF EXISTS "photos_insert_auth"    ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_auth"    ON storage.objects;

CREATE POLICY "photos_read_public" ON storage.objects
  FOR SELECT USING (bucket_id = 'photos');

CREATE POLICY "photos_insert_auth" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'photos');

CREATE POLICY "photos_delete_auth" ON storage.objects
  FOR DELETE TO authenticated
  USING (bucket_id = 'photos');

-- ── 6. RELOAD POSTGREST SCHEMA CACHE ────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── 7. DIAGNOSTICS ──────────────────────────────────────────────────────────
SELECT '--- PUBLIC RLS POLICIES ---' AS section, '' AS detail
UNION ALL
SELECT tablename || '.' || policyname, cmd || ' | ' || COALESCE(qual, '') AS detail
FROM pg_policies WHERE schemaname = 'public'
ORDER BY section, detail;

SELECT '--- STORAGE POLICIES (photos) ---' AS section, '' AS detail
UNION ALL
SELECT policyname, cmd
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
  AND policyname LIKE 'photos%'
ORDER BY section, policyname;

SELECT '--- USERS COLUMNS ---' AS section, string_agg(column_name, ', ' ORDER BY ordinal_position) AS detail
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users';

SELECT '--- TABLES ---' AS section, string_agg(table_name, ', ' ORDER BY table_name) AS detail
FROM information_schema.tables
WHERE table_schema = 'public';
