-- Мінімальний скелет Supabase, потрібний, щоб міграції ВЗАГАЛІ виконались.
-- Не емуляція платформи — лише ті обʼєкти, на які міграції посилаються.
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Ролі Supabase.
DO $$ BEGIN
  CREATE ROLE anon NOLOGIN;            EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE authenticated NOLOGIN;   EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE service_role NOLOGIN;    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE supabase_auth_admin NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE ROLE authenticator NOINHERIT NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- auth.users: міграції читають email і id.
CREATE TABLE IF NOT EXISTS auth.users (
  id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE
);

-- auth.uid()/auth.role() — у проді їх дає GoTrue через JWT-клейми.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID
  LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::UUID $$;
CREATE OR REPLACE FUNCTION auth.role() RETURNS TEXT
  LANGUAGE sql STABLE AS $$ SELECT current_setting('request.jwt.claim.role', true) $$;
CREATE OR REPLACE FUNCTION auth.email() RETURNS TEXT
  LANGUAGE sql STABLE AS $$ SELECT current_setting('request.jwt.claim.email', true) $$;
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS JSONB
  LANGUAGE sql STABLE AS $$ SELECT COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb) $$;

-- storage.objects: політики й 051 працюють саме з нею.
CREATE TABLE IF NOT EXISTS storage.buckets (
  id TEXT PRIMARY KEY, name TEXT, public BOOLEAN DEFAULT false,
  file_size_limit    BIGINT,
  allowed_mime_types TEXT[],
  owner              UUID,
  created_at         TIMESTAMPTZ DEFAULT now(),
  updated_at         TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS storage.objects (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id  TEXT REFERENCES storage.buckets(id),
  name       TEXT,
  owner      UUID,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  metadata   JSONB
);
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
INSERT INTO storage.buckets (id, name, public) VALUES
  ('photos', 'photos', true), ('property-files', 'property-files', false)
  ON CONFLICT (id) DO NOTHING;

-- Публікація для realtime (міграції додають до неї таблиці).
DO $$ BEGIN
  CREATE PUBLICATION supabase_realtime; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
