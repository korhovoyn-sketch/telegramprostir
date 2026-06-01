-- ============================================================
-- PropSpace v1 — Idempotent full schema setup
-- Safe to run on any DB state: creates tables/columns that
-- are missing, skips ones that already exist.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── users ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tg_id         BIGINT UNIQUE NOT NULL,
  tg_username   TEXT,
  first_name    TEXT NOT NULL DEFAULT 'User',
  last_name     TEXT,
  email         TEXT,
  phone         TEXT,
  role          TEXT NOT NULL DEFAULT 'owner',
  language_code TEXT NOT NULL DEFAULT 'uk',
  currency      TEXT NOT NULL DEFAULT 'USD',
  plan          TEXT NOT NULL DEFAULT 'free',
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS tg_username   TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name    TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name     TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email         TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone         TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS language_code TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS currency      TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at    TIMESTAMPTZ DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ DEFAULT now();

-- Back-fill NULLs before adding NOT NULL constraints
UPDATE users SET first_name    = 'User'  WHERE first_name IS NULL;
UPDATE users SET role          = 'owner' WHERE role IS NULL;
UPDATE users SET language_code = 'uk'    WHERE language_code IS NULL;
UPDATE users SET currency      = 'USD'   WHERE currency IS NULL;
UPDATE users SET plan          = 'free'  WHERE plan IS NULL;

ALTER TABLE users ALTER COLUMN first_name    SET NOT NULL;
ALTER TABLE users ALTER COLUMN role          SET NOT NULL;
ALTER TABLE users ALTER COLUMN language_code SET NOT NULL;
ALTER TABLE users ALTER COLUMN currency      SET NOT NULL;
ALTER TABLE users ALTER COLUMN plan          SET NOT NULL;

-- Add CHECK constraints only if they don't already exist
DO $$ BEGIN
  ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner','realtor'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE users ADD CONSTRAINT users_plan_check
    CHECK (plan IN ('free','pro'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── databases ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS databases (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id        UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name            TEXT NOT NULL,
  address         TEXT,
  type            TEXT NOT NULL DEFAULT 'individual',
  color           TEXT NOT NULL DEFAULT 'purple',
  share_token     TEXT UNIQUE DEFAULT encode(gen_random_bytes(12),'hex'),
  share_expires_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE databases ADD COLUMN IF NOT EXISTS address          TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS type             TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS color            TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS share_token      TEXT;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS share_expires_at TIMESTAMPTZ;
ALTER TABLE databases ADD COLUMN IF NOT EXISTS created_at       TIMESTAMPTZ DEFAULT now();
ALTER TABLE databases ADD COLUMN IF NOT EXISTS updated_at       TIMESTAMPTZ DEFAULT now();

UPDATE databases SET type  = 'individual' WHERE type IS NULL;
UPDATE databases SET color = 'purple'     WHERE color IS NULL;
ALTER TABLE databases ALTER COLUMN type  SET NOT NULL;
ALTER TABLE databases ALTER COLUMN color SET NOT NULL;

DO $$ BEGIN
  ALTER TABLE databases ADD CONSTRAINT databases_type_check
    CHECK (type IN ('business_center','residential','retail','warehouse','individual','parking'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── properties ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS properties (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id          UUID REFERENCES databases(id) ON DELETE CASCADE NOT NULL,
  owner_id       UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name           TEXT NOT NULL,
  floor          TEXT,
  status         TEXT DEFAULT 'free',
  area_useful    FLOAT,
  area_total     FLOAT,
  rent_type      TEXT DEFAULT 'per_m2',
  rent_rate      FLOAT,
  utilities_rate FLOAT,
  has_parking    BOOLEAN DEFAULT false,
  parking_spaces INT DEFAULT 0,
  description    TEXT,
  created_at     TIMESTAMPTZ DEFAULT now(),
  updated_at     TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE properties ADD COLUMN IF NOT EXISTS floor          TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS status         TEXT DEFAULT 'free';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS area_useful    FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS area_total     FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS rent_type      TEXT DEFAULT 'per_m2';
ALTER TABLE properties ADD COLUMN IF NOT EXISTS rent_rate      FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS utilities_rate FLOAT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS has_parking    BOOLEAN DEFAULT false;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS parking_spaces INT DEFAULT 0;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS description    TEXT;
ALTER TABLE properties ADD COLUMN IF NOT EXISTS created_at     TIMESTAMPTZ DEFAULT now();
ALTER TABLE properties ADD COLUMN IF NOT EXISTS updated_at     TIMESTAMPTZ DEFAULT now();

-- ── property_photos ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS property_photos (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  storage_path TEXT NOT NULL,
  sort_order  INT DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ── realtor_subscriptions ────────────────────────────────────
CREATE TABLE IF NOT EXISTS realtor_subscriptions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id  UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  db_id       UUID REFERENCES databases(id) ON DELETE CASCADE NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT now(),
  UNIQUE(realtor_id, db_id)
);

-- ── collections ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS collections (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  realtor_id  UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  name        TEXT NOT NULL,
  is_draft    BOOLEAN DEFAULT true,
  created_at  TIMESTAMPTZ DEFAULT now(),
  updated_at  TIMESTAMPTZ DEFAULT now()
);

-- ── collection_properties ────────────────────────────────────
CREATE TABLE IF NOT EXISTS collection_properties (
  collection_id UUID REFERENCES collections(id) ON DELETE CASCADE NOT NULL,
  property_id   UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  added_at      TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (collection_id, property_id)
);

-- ── property_views ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS property_views (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id UUID REFERENCES properties(id) ON DELETE CASCADE NOT NULL,
  viewer_id   UUID REFERENCES users(id),
  viewer_name TEXT,
  action      TEXT DEFAULT 'view',
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- ── notifications ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  type       TEXT NOT NULL,
  title      TEXT NOT NULL,
  body       TEXT,
  is_read    BOOLEAN DEFAULT false,
  data       JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ── Indexes (safe to recreate) ───────────────────────────────
CREATE INDEX IF NOT EXISTS idx_databases_owner      ON databases(owner_id);
CREATE INDEX IF NOT EXISTS idx_properties_db        ON properties(db_id);
CREATE INDEX IF NOT EXISTS idx_properties_owner     ON properties(owner_id);
CREATE INDEX IF NOT EXISTS idx_property_photos_prop ON property_photos(property_id);
CREATE INDEX IF NOT EXISTS idx_realtor_subs_realtor ON realtor_subscriptions(realtor_id);
CREATE INDEX IF NOT EXISTS idx_realtor_subs_db      ON realtor_subscriptions(db_id);
CREATE INDEX IF NOT EXISTS idx_collections_realtor  ON collections(realtor_id);
CREATE INDEX IF NOT EXISTS idx_property_views_prop  ON property_views(property_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user   ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, is_read)
  WHERE is_read = false;

-- ── updated_at trigger ───────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
  CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE TRIGGER trg_databases_updated_at
    BEFORE UPDATE ON databases FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE TRIGGER trg_properties_updated_at
    BEFORE UPDATE ON properties FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
  CREATE TRIGGER trg_collections_updated_at
    BEFORE UPDATE ON collections FOR EACH ROW EXECUTE FUNCTION update_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── RLS ──────────────────────────────────────────────────────
ALTER TABLE users                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE databases              ENABLE ROW LEVEL SECURITY;
ALTER TABLE properties             ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_photos        ENABLE ROW LEVEL SECURITY;
ALTER TABLE realtor_subscriptions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE collections            ENABLE ROW LEVEL SECURITY;
ALTER TABLE collection_properties  ENABLE ROW LEVEL SECURITY;
ALTER TABLE property_views         ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications          ENABLE ROW LEVEL SECURITY;

-- Helper: resolves tg_id from JWT email claim
-- email format: {tgId}@telegram.propspace.app
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID AS $$
DECLARE
  jwt_email TEXT;
  tg_id_val BIGINT;
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
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Drop and recreate all policies cleanly
DO $$ DECLARE r RECORD;
BEGIN
  FOR r IN SELECT policyname, tablename FROM pg_policies
           WHERE schemaname = 'public' LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', r.policyname, r.tablename);
  END LOOP;
END $$;

-- users
CREATE POLICY "users_own"     ON users FOR ALL USING (id = current_app_user_id());
CREATE POLICY "users_service" ON users FOR ALL TO service_role USING (true);

-- databases
CREATE POLICY "db_owner_all"     ON databases FOR ALL USING (owner_id = current_app_user_id());
CREATE POLICY "db_realtor_select" ON databases FOR SELECT USING (
  id IN (SELECT db_id FROM realtor_subscriptions WHERE realtor_id = current_app_user_id())
);
CREATE POLICY "db_service" ON databases FOR ALL TO service_role USING (true);

-- properties
CREATE POLICY "props_owner_all"     ON properties FOR ALL USING (owner_id = current_app_user_id());
CREATE POLICY "props_realtor_select" ON properties FOR SELECT USING (
  db_id IN (SELECT db_id FROM realtor_subscriptions WHERE realtor_id = current_app_user_id())
);
CREATE POLICY "props_service" ON properties FOR ALL TO service_role USING (true);

-- property_photos
CREATE POLICY "photos_owner_all" ON property_photos FOR ALL USING (
  property_id IN (SELECT id FROM properties WHERE owner_id = current_app_user_id())
);
CREATE POLICY "photos_realtor_select" ON property_photos FOR SELECT USING (
  property_id IN (
    SELECT p.id FROM properties p
    JOIN realtor_subscriptions rs ON rs.db_id = p.db_id
    WHERE rs.realtor_id = current_app_user_id()
  )
);

-- realtor_subscriptions
CREATE POLICY "subs_realtor_all"   ON realtor_subscriptions FOR ALL USING (realtor_id = current_app_user_id());
CREATE POLICY "subs_owner_select"  ON realtor_subscriptions FOR SELECT USING (
  db_id IN (SELECT id FROM databases WHERE owner_id = current_app_user_id())
);

-- collections
CREATE POLICY "col_realtor_all" ON collections FOR ALL USING (realtor_id = current_app_user_id());

-- collection_properties
CREATE POLICY "col_props_realtor_all" ON collection_properties FOR ALL USING (
  collection_id IN (SELECT id FROM collections WHERE realtor_id = current_app_user_id())
);

-- property_views
CREATE POLICY "views_owner_select" ON property_views FOR SELECT USING (
  property_id IN (SELECT id FROM properties WHERE owner_id = current_app_user_id())
);
CREATE POLICY "views_insert_all" ON property_views FOR INSERT WITH CHECK (true);

-- notifications
CREATE POLICY "notifs_own"     ON notifications FOR ALL USING (user_id = current_app_user_id());
CREATE POLICY "notifs_service" ON notifications FOR ALL TO service_role USING (true);

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
