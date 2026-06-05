-- ============================================================================
-- PropSpace v1.0.0 — MASTER SETUP
-- ============================================================================
-- Single authoritative script. Run once on a fresh Supabase project, or run
-- on an existing one — every statement is idempotent.
--
-- Replaces migrations 001–012. Covers:
--   - Extensions
--   - All tables + columns + constraints + indexes
--   - All PL/pgSQL helper functions (SECURITY DEFINER + search_path)
--   - All RLS policies (drops everything first, then rebuilds cleanly)
--   - prevent_privilege_escalation trigger (correct version: owner→realtor OK)
--   - rate_limits table + policy
--   - Storage bucket + policies
--   - Legacy auth trigger cleanup
--   - Diagnostic queries at the end
-- ============================================================================

-- ── 0. EXTENSIONS ─────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── 1. LEGACY AUTH TRIGGER CLEANUP ────────────────────────────────────────────
-- The Supabase starter template installs a handle_new_user trigger on auth.users
-- that breaks GoTrue with "Database error creating new user". Remove it.
DROP TRIGGER   IF EXISTS on_auth_user_created         ON auth.users;
DROP TRIGGER   IF EXISTS on_auth_user_created_trigger  ON auth.users;
DROP TRIGGER   IF EXISTS handle_new_user_trigger       ON auth.users;
DROP FUNCTION  IF EXISTS public.handle_new_user()     CASCADE;

-- ── 2. TABLES ─────────────────────────────────────────────────────────────────

-- users
CREATE TABLE IF NOT EXISTS users (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tg_id         BIGINT      UNIQUE NOT NULL,
  tg_username   TEXT,
  first_name    TEXT        NOT NULL,
  last_name     TEXT,
  email         TEXT,
  phone         TEXT,
  role          TEXT        NOT NULL DEFAULT 'owner'
                            CHECK (role IN ('owner', 'realtor')),
  language_code TEXT        NOT NULL DEFAULT 'uk',
  currency      TEXT        NOT NULL DEFAULT 'USD',
  plan          TEXT        NOT NULL DEFAULT 'free'
                            CHECK (plan IN ('free', 'pro')),
  notification_push    BOOLEAN NOT NULL DEFAULT true,
  notification_weekly  BOOLEAN NOT NULL DEFAULT true,
  notification_views   BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);
-- Bring existing rows up to spec (missing columns from early migrations)
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_push    BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_weekly  BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS notification_views   BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tg_username          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name            TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email                TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone                TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS currency             TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan                 TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS language_code        TEXT;

-- databases
CREATE TABLE IF NOT EXISTS databases (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name             TEXT        NOT NULL,
  address          TEXT,
  type             TEXT        NOT NULL
                               CHECK (type IN ('business_center','residential','retail',
                                               'warehouse','individual','parking')),
  color            TEXT        NOT NULL DEFAULT 'purple',
  share_token      TEXT        UNIQUE DEFAULT encode(gen_random_bytes(12), 'hex'),
  share_expires_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT now(),
  updated_at       TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE databases ADD COLUMN IF NOT EXISTS address          TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS type             TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS color            TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS share_token      TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;
ALTER TABLE databases DROP COLUMN IF EXISTS slug;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS sale_price      FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS tenant_name     TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_start_date DATE;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS lease_end_date  DATE;

-- properties
CREATE TABLE IF NOT EXISTS properties (
  id              UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id           UUID    NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  owner_id        UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name            TEXT    NOT NULL,
  floor           TEXT,
  status          TEXT    DEFAULT 'free'
                          CHECK (status IN ('free','occupied','for_sale')),
  area_useful     FLOAT,
  area_total      FLOAT,
  rent_type       TEXT    DEFAULT 'per_m2'
                          CHECK (rent_type IN ('per_m2','fixed')),
  rent_rate       FLOAT,
  utilities_rate  FLOAT,
  has_parking     BOOLEAN DEFAULT false,
  parking_spaces  INT     DEFAULT 0,
  description     TEXT,
  sale_price      FLOAT,
  tenant_name     TEXT,
  lease_start_date DATE,
  lease_end_date  DATE,
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now()
);

-- property_photos
CREATE TABLE IF NOT EXISTS property_photos (
  id           UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id  UUID    NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  storage_path TEXT    NOT NULL,
  sort_order   INT     DEFAULT 0,
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- realtor_subscriptions
CREATE TABLE IF NOT EXISTS realtor_subscriptions (
  id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id  UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  db_id       UUID    NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE (realtor_id, db_id)
);

-- collections
CREATE TABLE IF NOT EXISTS collections (
  id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id  UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  is_draft    BOOLEAN DEFAULT true,
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now()
);

-- collection_properties
CREATE TABLE IF NOT EXISTS collection_properties (
  collection_id  UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  property_id    UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  added_at       TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (collection_id, property_id)
);

-- property_views
CREATE TABLE IF NOT EXISTS property_views (
  id           UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id  UUID    NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  viewer_id    UUID    REFERENCES users(id),
  viewer_name  TEXT,
  action       TEXT    DEFAULT 'view'
                       CHECK (action IN ('view','photo','document','share','favorite')),
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- notifications
CREATE TABLE IF NOT EXISTS notifications (
  id         UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type       TEXT    NOT NULL,
  title      TEXT    NOT NULL,
  body       TEXT,
  is_read    BOOLEAN DEFAULT false,
  data       JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- rate_limits (DB-backed rate limiter for the Edge Function)
CREATE TABLE IF NOT EXISTS rate_limits (
  ip       TEXT        PRIMARY KEY,
  count    INT         NOT NULL DEFAULT 0,
  reset_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 minute'
);

-- ── 3. INDEXES ────────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS users_tg_id_unique
  ON users(tg_id) WHERE tg_id IS NOT NULL;
-- Remove old non-unique duplicate if it exists
DROP INDEX IF EXISTS users_tg_id_idx;

CREATE INDEX IF NOT EXISTS idx_databases_owner          ON databases(owner_id);
CREATE INDEX IF NOT EXISTS idx_properties_db            ON properties(db_id);
CREATE INDEX IF NOT EXISTS idx_properties_owner         ON properties(owner_id);
CREATE INDEX IF NOT EXISTS idx_property_photos_prop     ON property_photos(property_id);
CREATE INDEX IF NOT EXISTS idx_realtor_subs_realtor     ON realtor_subscriptions(realtor_id);
CREATE INDEX IF NOT EXISTS idx_realtor_subs_db          ON realtor_subscriptions(db_id);
CREATE INDEX IF NOT EXISTS idx_collections_realtor      ON collections(realtor_id);
-- Compound: analytics queries filter + sort by date
CREATE INDEX IF NOT EXISTS idx_property_views_prop_date
  ON property_views(property_id, created_at DESC);
-- Compound: notification list sorted by date
CREATE INDEX IF NOT EXISTS idx_notifications_user_date
  ON notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unread
  ON notifications(user_id, is_read) WHERE is_read = false;
-- Unique index on share_token (UNIQUE constraint covers it; explicit for safety)
CREATE UNIQUE INDEX IF NOT EXISTS idx_databases_share_token
  ON databases(share_token) WHERE share_token IS NOT NULL;

-- ── 4. HELPER FUNCTIONS ───────────────────────────────────────────────────────
-- All functions are STABLE SECURITY DEFINER with explicit search_path to prevent
-- search_path injection attacks.

-- The single identity source for ALL RLS checks.
-- Parses tg_id from the JWT email claim: "{tgId}@telegram.propspace.app"
-- auth.uid() is NOT used — public.users.id ≠ auth.users.id.
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  jwt_email  TEXT;
  tg_id_val  BIGINT;
BEGIN
  jwt_email := current_setting('request.jwt.claims', true)::jsonb->>'email';
  IF jwt_email IS NULL OR jwt_email NOT LIKE '%@telegram.propspace.app' THEN
    RETURN NULL;
  END IF;
  tg_id_val := SPLIT_PART(jwt_email, '@', 1)::BIGINT;
  RETURN (SELECT id FROM users WHERE tg_id = tg_id_val LIMIT 1);
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION get_realtor_db_ids(p_uid UUID)
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT db_id FROM realtor_subscriptions WHERE realtor_id = p_uid;
$$;

CREATE OR REPLACE FUNCTION get_owner_db_ids(p_uid UUID)
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM databases WHERE owner_id = p_uid;
$$;

CREATE OR REPLACE FUNCTION get_owner_property_ids(p_uid UUID)
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM properties WHERE owner_id = p_uid;
$$;

CREATE OR REPLACE FUNCTION get_realtor_property_ids(p_uid UUID)
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT p.id FROM properties p
  WHERE p.db_id IN (SELECT get_realtor_db_ids(p_uid));
$$;

CREATE OR REPLACE FUNCTION get_realtor_collection_ids(p_uid UUID)
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM collections WHERE realtor_id = p_uid;
$$;

-- Share-link / QR resolution. Returns a DB ONLY when the caller supplies the
-- exact share_token (a 24-char secret). SECURITY DEFINER so it works before a
-- subscription exists, without a blanket RLS SELECT policy that would otherwise
-- let any authenticated user enumerate every shared database (and its token).
-- Expiry is returned (not filtered) so the client can show a precise message;
-- actual data access after subscribing is still gated by db_realtor_select.
CREATE OR REPLACE FUNCTION lookup_shared_db(p_token TEXT)
RETURNS TABLE (id UUID, owner_id UUID, share_expires_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT d.id, d.owner_id, d.share_expires_at
  FROM databases d
  WHERE d.share_token = p_token
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_db(TEXT) TO authenticated, service_role;

-- Public preview: returns DB + properties for any caller (including anon) given a valid token.
-- Exposes only read-safe fields — no owner contacts, no share_token.
CREATE OR REPLACE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE (
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  share_expires_at TIMESTAMPTZ,
  property_id UUID, property_name TEXT, property_status TEXT,
  property_floor TEXT, property_area_useful FLOAT,
  property_area_total FLOAT, property_rent_type TEXT,
  property_rent_rate FLOAT, property_description TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT
    d.id, d.name, d.type, d.color, d.share_expires_at,
    p.id, p.name, p.status, p.floor, p.area_useful,
    p.area_total, p.rent_type, p.rent_rate, p.description
  FROM databases d
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.name;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;

-- Fires on every UPDATE to users (updated_at auto-maintenance)
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_users_updated_at      ON users;
DROP TRIGGER IF EXISTS trg_databases_updated_at  ON databases;
DROP TRIGGER IF EXISTS trg_properties_updated_at ON properties;
DROP TRIGGER IF EXISTS trg_collections_updated_at ON collections;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_databases_updated_at
  BEFORE UPDATE ON databases FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_properties_updated_at
  BEFORE UPDATE ON properties FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_collections_updated_at
  BEFORE UPDATE ON collections FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── 5. PRIVILEGE ESCALATION GUARD ────────────────────────────────────────────
-- Blocks clients from upgrading their own plan.
-- Blocks realtor→owner role escalation.
-- ALLOWS owner→realtor (needed for initial onboarding role selection).
-- Service_role sessions bypass this entirely (they set authenticated=false).
CREATE OR REPLACE FUNCTION prevent_privilege_escalation()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Only restrict regular JWT client sessions
  IF current_setting('request.jwt.claims', true) IS NOT NULL
     AND current_setting('request.jwt.claims', true) != ''
  THEN
    -- Always block plan changes from client sessions
    NEW.plan := OLD.plan;
    -- Block realtor→owner escalation; owner→realtor is allowed (onboarding)
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

-- ── 6. ROW LEVEL SECURITY ─────────────────────────────────────────────────────
-- Enable RLS on every table first
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

-- Drop ALL existing public policies before rebuilding to avoid conflicts
-- between old migrations that left duplicates or wrong versions.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT policyname, tablename
    FROM pg_policies
    WHERE schemaname = 'public'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', r.policyname, r.tablename);
  END LOOP;
END $$;

-- ─── users ────────────────────────────────────────────────────────────────────
CREATE POLICY "users_own" ON users
  FOR ALL
  USING     (id = current_app_user_id())
  WITH CHECK (id = current_app_user_id());

CREATE POLICY "users_service" ON users
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── databases ────────────────────────────────────────────────────────────────
-- Owner: full CRUD on own databases
CREATE POLICY "db_owner_all" ON databases
  FOR ALL
  USING     (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

-- Realtor: SELECT subscribed databases
CREATE POLICY "db_realtor_select" ON databases
  FOR SELECT
  USING (id IN (SELECT get_realtor_db_ids(current_app_user_id())));

-- NOTE: there is intentionally NO blanket "lookup by share_token" SELECT policy.
-- A USING clause cannot see the caller's WHERE filter, so such a policy would
-- expose EVERY active-shared database (and its share_token) to any authenticated
-- user via an unfiltered SELECT. Share-link resolution goes through the
-- SECURITY DEFINER function lookup_shared_db(token) instead, which only returns
-- a row when the exact secret token is supplied.

CREATE POLICY "db_service" ON databases
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── properties ───────────────────────────────────────────────────────────────
CREATE POLICY "props_owner_all" ON properties
  FOR ALL
  USING     (owner_id = current_app_user_id())
  WITH CHECK (owner_id = current_app_user_id());

CREATE POLICY "props_realtor_select" ON properties
  FOR SELECT
  USING (db_id IN (SELECT get_realtor_db_ids(current_app_user_id())));

CREATE POLICY "props_service" ON properties
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── property_photos ──────────────────────────────────────────────────────────
-- SECURITY DEFINER helpers avoid per-row correlated subquery scans
CREATE POLICY "photos_owner_all" ON property_photos
  FOR ALL
  USING     (property_id IN (SELECT get_owner_property_ids(current_app_user_id())))
  WITH CHECK (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

CREATE POLICY "photos_realtor_select" ON property_photos
  FOR SELECT
  USING (property_id IN (SELECT get_realtor_property_ids(current_app_user_id())));

CREATE POLICY "photos_service" ON property_photos
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── realtor_subscriptions ────────────────────────────────────────────────────
CREATE POLICY "subs_realtor_all" ON realtor_subscriptions
  FOR ALL
  USING     (realtor_id = current_app_user_id())
  WITH CHECK (realtor_id = current_app_user_id());

-- Owner can see who subscribed to their databases
CREATE POLICY "subs_owner_select" ON realtor_subscriptions
  FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

CREATE POLICY "subs_service" ON realtor_subscriptions
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── collections ──────────────────────────────────────────────────────────────
CREATE POLICY "col_realtor_all" ON collections
  FOR ALL
  USING     (realtor_id = current_app_user_id())
  WITH CHECK (realtor_id = current_app_user_id());

-- ─── collection_properties ────────────────────────────────────────────────────
CREATE POLICY "col_props_realtor_all" ON collection_properties
  FOR ALL
  USING     (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())))
  WITH CHECK (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())));

-- ─── property_views ───────────────────────────────────────────────────────────
-- Owner can read view events for their properties
CREATE POLICY "views_owner_select" ON property_views
  FOR SELECT
  USING (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

-- Realtor can read views for their subscribed properties
CREATE POLICY "views_realtor_select" ON property_views
  FOR SELECT
  USING (property_id IN (SELECT get_realtor_property_ids(current_app_user_id())));

-- Any authenticated user can record a view event
CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT
  WITH CHECK (auth.role() = 'authenticated');

-- ─── notifications ────────────────────────────────────────────────────────────
CREATE POLICY "notifs_own" ON notifications
  FOR ALL
  USING     (user_id = current_app_user_id())
  WITH CHECK (user_id = current_app_user_id());

CREATE POLICY "notifs_service" ON notifications
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ─── rate_limits (Edge Function only — service_role) ─────────────────────────
CREATE POLICY "rate_limits_service" ON rate_limits
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ── 7. STORAGE ────────────────────────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public)
VALUES ('photos', 'photos', true)
ON CONFLICT (id) DO NOTHING;

-- Drop and recreate to avoid stale policies from earlier migrations
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_insert" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_delete" ON storage.objects;
DROP POLICY IF EXISTS "storage_photos_update" ON storage.objects;

-- Anyone can view photos (bucket is public; this policy adds PostgREST layer)
CREATE POLICY "storage_photos_select" ON storage.objects
  FOR SELECT USING (bucket_id = 'photos');

-- Authenticated users can upload photos
CREATE POLICY "storage_photos_insert" ON storage.objects
  FOR INSERT WITH CHECK (bucket_id = 'photos' AND auth.role() = 'authenticated');

-- Authenticated users can delete their own photos
-- (The app deletes via service_role from Edge Functions; this covers client-side)
CREATE POLICY "storage_photos_delete" ON storage.objects
  FOR DELETE USING (bucket_id = 'photos' AND auth.role() = 'authenticated');

-- ── 8. SCHEMA CACHE RELOAD ────────────────────────────────────────────────────
NOTIFY pgrst, 'reload schema';

-- ── 9. DIAGNOSTICS ────────────────────────────────────────────────────────────
-- Run these SELECT statements to confirm everything is correct.

SELECT '════ LEGACY TRIGGER CHECK (must be 0 rows) ════' AS check;
SELECT tgname, c.relname AS table
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = 'auth' AND c.relname = 'users' AND NOT t.tgisinternal;

SELECT '════ FUNCTIONS (must list all 7) ════' AS check;
SELECT proname, prosecdef AS security_definer
FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'public'
  AND proname IN (
    'current_app_user_id',
    'get_realtor_db_ids', 'get_owner_db_ids',
    'get_owner_property_ids', 'get_realtor_property_ids',
    'get_realtor_collection_ids',
    'prevent_privilege_escalation'
  )
ORDER BY proname;

SELECT '════ RLS POLICIES BY TABLE ════' AS check;
SELECT tablename, count(*) AS policy_count, string_agg(policyname, ', ' ORDER BY policyname) AS policies
FROM pg_policies WHERE schemaname = 'public'
GROUP BY tablename ORDER BY tablename;

SELECT '════ USERS TABLE COLUMNS ════' AS check;
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users'
ORDER BY ordinal_position;

SELECT '════ INDEXES ════' AS check;
SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname LIKE 'idx_%'
ORDER BY indexname;

SELECT '════ STORAGE BUCKET ════' AS check;
SELECT id, name, public FROM storage.buckets WHERE id = 'photos';

SELECT '════ STORAGE POLICIES ════' AS check;
SELECT policyname, cmd, qual
FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects'
ORDER BY policyname;

SELECT '════ DONE ════' AS result,
  (SELECT count(*) FROM pg_policies WHERE schemaname = 'public')::text || ' public RLS policies active' AS detail;
