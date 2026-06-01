-- Patch users table to match PropSpace v1 schema.
-- Uses ADD COLUMN IF NOT EXISTS so it's safe to run multiple times.

ALTER TABLE users ADD COLUMN IF NOT EXISTS tg_username    TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name     TEXT NOT NULL DEFAULT 'User';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name      TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone          TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS language_code  TEXT NOT NULL DEFAULT 'uk';
ALTER TABLE users ADD COLUMN IF NOT EXISTS currency       TEXT NOT NULL DEFAULT 'USD';
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan           TEXT NOT NULL DEFAULT 'free'
  CHECK (plan IN ('free', 'pro'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at     TIMESTAMPTZ DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at     TIMESTAMPTZ DEFAULT now();

-- Remove the DEFAULT after back-fill so future inserts must supply first_name
ALTER TABLE users ALTER COLUMN first_name DROP DEFAULT;

-- Reload PostgREST schema cache so new columns are visible immediately
NOTIFY pgrst, 'reload schema';
