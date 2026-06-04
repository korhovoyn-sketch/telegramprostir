-- ============================================================================
-- PropSpace — Security & Performance fixes  (safe to run multiple times)
-- ============================================================================
-- Issues fixed here:
--   SEC-1  plan/role self-escalation: trigger prevents authenticated users from
--          upgrading their own plan or changing role via the client API
--   SEC-2  db_share_lookup: add server-side share_expires_at enforcement
--   SEC-3  property_photos RLS: replace correlated subquery with SECURITY DEFINER
--          helper to prevent per-row O(n) plan scans
--   PERF-1 Compound index on property_views(property_id, created_at DESC)
--   PERF-2 Compound index on notifications(user_id, created_at DESC)
--   PERF-3 Index on databases.share_token (covered by UNIQUE — confirmed here)
--   PERF-4 Index on realtor_subscriptions(realtor_id) + (db_id) — confirmed
-- ============================================================================

-- ── SEC-1: Prevent plan/role self-escalation ─────────────────────────────────
-- The RLS WITH CHECK (id = current_app_user_id()) allows updating ANY column on
-- own row, including `plan` (free→pro) and `role` (owner→realtor).
-- This trigger resets both columns to their persisted DB values whenever an
-- update comes from a non-service_role session.
-- Service_role (Edge Function) is not affected — it bypasses RLS entirely.

CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  -- Only apply restriction for regular JWT sessions (not service_role)
  -- current_setting returns '' or errors when not set; both mean no restriction needed
  IF current_setting('request.jwt.claims', true) IS NOT NULL
     AND current_setting('request.jwt.claims', true) != '' THEN
    -- Silently revert plan and role to their existing values
    NEW.plan := OLD.plan;
    NEW.role := OLD.role;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_privilege_escalation ON users;
CREATE TRIGGER trg_prevent_privilege_escalation
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION prevent_privilege_escalation();

-- ── SEC-2: Server-side share token expiration ────────────────────────────────
-- The old db_share_lookup policy let any authenticated user SELECT any database
-- with a non-null share_token regardless of expiry.
-- New policy: share_expires_at must be NULL (never expires) or in the future.

DROP POLICY IF EXISTS "db_share_lookup" ON databases;
CREATE POLICY "db_share_lookup" ON databases FOR SELECT
  USING (
    share_token IS NOT NULL
    AND auth.role() = 'authenticated'
    AND (share_expires_at IS NULL OR share_expires_at > now())
  );

-- ── SEC-3: Replace property_photos subquery policies with helpers ─────────────
-- The per-row correlated subquery:
--   property_id IN (SELECT id FROM properties WHERE owner_id = current_app_user_id())
-- was evaluated for every row in a scan. Replace with a SECURITY DEFINER helper
-- that is planned once and cached.

CREATE OR REPLACE FUNCTION get_owner_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT id FROM properties WHERE owner_id = p_uid
$$;

CREATE OR REPLACE FUNCTION get_realtor_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT p.id FROM properties p
  WHERE p.db_id IN (SELECT get_realtor_db_ids(p_uid))
$$;

-- Re-drop and recreate the photos policies using the helpers
DROP POLICY IF EXISTS "photos_owner_all"      ON property_photos;
DROP POLICY IF EXISTS "photos_realtor_select" ON property_photos;

CREATE POLICY "photos_owner_all" ON property_photos FOR ALL
  USING (property_id IN (SELECT get_owner_property_ids(current_app_user_id())))
  WITH CHECK (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

CREATE POLICY "photos_realtor_select" ON property_photos FOR SELECT
  USING (property_id IN (SELECT get_realtor_property_ids(current_app_user_id())));

-- Same fix for property_views owner policy (views_owner_select)
DROP POLICY IF EXISTS "views_owner_select" ON property_views;
CREATE POLICY "views_owner_select" ON property_views FOR SELECT
  USING (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

-- Same fix for collection_properties policy
DROP POLICY IF EXISTS "col_props_realtor_all" ON collection_properties;

CREATE OR REPLACE FUNCTION get_realtor_collection_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT id FROM collections WHERE realtor_id = p_uid
$$;

CREATE POLICY "col_props_realtor_all" ON collection_properties FOR ALL
  USING (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())))
  WITH CHECK (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())));

-- ── PERF-1: Compound index for analytics queries ──────────────────────────────
-- SharingAnalyticsScreen: WHERE property_id = ? AND created_at >= ?  ORDER BY created_at DESC
-- Without compound index, Postgres uses property_id index then filters + sorts on heap.
CREATE INDEX IF NOT EXISTS idx_property_views_prop_date
  ON property_views(property_id, created_at DESC);

-- ── PERF-2: Compound index for notification queries ───────────────────────────
-- useNotifications: WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
CREATE INDEX IF NOT EXISTS idx_notifications_user_date
  ON notifications(user_id, created_at DESC);

-- ── PERF-3: Confirm share_token index (UNIQUE creates btree automatically) ────
-- databases.share_token is UNIQUE — the constraint index already covers lookups.
-- This SELECT confirms it; no DDL needed.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE tablename = 'databases' AND indexdef LIKE '%share_token%'
  ) THEN
    -- Fallback: create explicit index if constraint was dropped
    CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_share_token ON databases(share_token);
  END IF;
END $$;

-- ── PERF-4: Confirm realtor_subscriptions indexes ────────────────────────────
-- These should already exist from 003_reconcile.sql; create them if missing.
CREATE INDEX IF NOT EXISTS idx_realtor_subs_realtor ON realtor_subscriptions(realtor_id);
CREATE INDEX IF NOT EXISTS idx_realtor_subs_db      ON realtor_subscriptions(db_id);

-- ── Reload PostgREST schema cache ────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── Diagnostics ──────────────────────────────────────────────────────────────
SELECT '=== TRIGGER CHECK ===' AS section, '' AS detail
UNION ALL
SELECT 'triggers on users', string_agg(trigger_name, ', ')
FROM information_schema.triggers
WHERE event_object_table = 'users' AND trigger_schema = 'public'
UNION ALL
SELECT '=== POLICY CHECK ===' AS section, '' AS detail
UNION ALL
SELECT tablename || '.' || policyname, cmd
FROM pg_policies WHERE schemaname = 'public'
  AND tablename IN ('users', 'databases', 'property_photos', 'property_views', 'collection_properties')
ORDER BY section, detail;

SELECT '=== INDEX CHECK ===' AS section, '' AS detail
UNION ALL
SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN (
    'idx_property_views_prop_date',
    'idx_notifications_user_date',
    'idx_databases_share_token',
    'users_tg_id_unique'
  )
ORDER BY section, indexname;
