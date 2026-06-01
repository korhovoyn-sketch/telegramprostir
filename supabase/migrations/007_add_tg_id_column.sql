-- Add tg_id column which was missing from the old users table.
-- Added nullable first (existing rows can't get a tg_id value),
-- then unique constraint on non-null values.

ALTER TABLE users ADD COLUMN IF NOT EXISTS tg_id BIGINT;

-- Drop old unique constraint if it exists from a previous attempt
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tg_id_key;

-- Add unique constraint (NULL values are excluded from uniqueness check)
CREATE UNIQUE INDEX IF NOT EXISTS users_tg_id_unique ON users(tg_id)
  WHERE tg_id IS NOT NULL;

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
