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

-- auth.users: міграції читають email і id; з 076 — ще й засвідчення особи.
-- `raw_app_meta_data` пише лише адмін-API (службовий ключ), тобто наша
-- edge-функція; рядок, вставлений без нього, моделює акаунт, створений НЕ
-- нею (самореєстрація, зміна email) — саме таким він і мусить лишатись.
CREATE TABLE IF NOT EXISTS auth.users (
  id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE,
  raw_app_meta_data  JSONB,
  email_confirmed_at TIMESTAMPTZ,
  is_anonymous       BOOLEAN NOT NULL DEFAULT false
);
-- Що робить edge-функція `telegram-auth` при створенні користувача:
-- `admin.createUser({ email, email_confirm: true, app_metadata: { tg_id } })`.
-- Перевірки сіють своїх користувачів цією функцією, а не голим INSERT, —
-- інакше вони моделювали б не наших користувачів, а самозванців.
CREATE OR REPLACE FUNCTION auth.shim_create_user(p_id UUID, p_email TEXT) RETURNS UUID
LANGUAGE sql AS $$
  INSERT INTO auth.users (id, email, email_confirmed_at, raw_app_meta_data)
  VALUES (COALESCE(p_id, gen_random_uuid()), p_email, now(),
          CASE WHEN p_email ~ '^\d{1,20}@telegram\.propspace\.app$'
               THEN jsonb_build_object('tg_id', split_part(p_email, '@', 1)) END)
  RETURNING id
$$;

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

-- Права на ТАБЛИЦІ дає сама платформа Supabase, а не міграції: у проді
-- `anon`/`authenticated` мають повний доступ до схеми `public`, і єдине, що
-- їх обмежує, — RLS. Без цього рядка RLS-перевірки нижче падали б на
-- `permission denied for table`, тобто проходили б із ХИБНОЇ причини:
-- «доступу немає» через привілеї, а не через політику.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO anon, authenticated, service_role;

-- І на ФУНКЦІЇ — цього рядка тут не було, і саме ця прогалина сховала діру,
-- знайдену лише на живій базі: Supabase видає EXECUTE на КОЖНУ нову функцію
-- `anon` і `authenticated` ПРЯМИМ грантом, тож `REVOKE ... FROM PUBLIC` у
-- міграції його не знімає. Без емуляції стенд показував службову функцію
-- закритою, а прод віддавав її анонімно (get_due_lease_reminders, 065).
-- Знімає це 075 — так само, як у проді.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;

-- Схема storage теж належить платформі: у проді `anon`/`authenticated` мають
-- USAGE і права на `storage.objects`, а обмежує їх RLS. Без цього перевірка
-- storage-політик «проходила» б із ХИБНОЇ причини — `permission denied for
-- schema storage` замість роботи політики. Наступано.
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO anon, authenticated, service_role;
GRANT SELECT ON storage.buckets TO anon, authenticated, service_role;
