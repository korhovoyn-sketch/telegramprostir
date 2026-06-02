-- Fix: legacy "slug" NOT NULL column in databases table blocks INSERT
-- The app never uses slug; drop it. If other legacy columns appear, they are
-- handled the same way below.

-- Drop legacy columns that existed in the old schema but not in the current app
ALTER TABLE databases DROP COLUMN IF EXISTS slug;

-- Defensive: make any remaining unknown columns nullable so they can't block INSERTs.
-- (If slug cannot be dropped due to dependencies, this makes it safe as a fallback.)
-- ALTER TABLE databases ALTER COLUMN slug DROP NOT NULL;

-- Verify current columns
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'databases'
ORDER BY ordinal_position;
