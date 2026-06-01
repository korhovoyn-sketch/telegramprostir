-- Rename telegram_id → tg_id to match the new schema.
-- Handles all possible states:
--   A) telegram_id exists, tg_id doesn't  → simple rename
--   B) both exist (migration 007 already ran) → copy + drop old column
--   C) only tg_id exists → nothing to do

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'users'
      AND column_name = 'telegram_id'
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'users'
        AND column_name = 'tg_id'
    ) THEN
      -- Case A: safe rename
      ALTER TABLE users RENAME COLUMN telegram_id TO tg_id;
    ELSE
      -- Case B: 007 already added tg_id; copy data then drop the old column
      UPDATE users SET tg_id = telegram_id WHERE tg_id IS NULL AND telegram_id IS NOT NULL;
      ALTER TABLE users DROP COLUMN telegram_id;
    END IF;
  END IF;
END $$;

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
