-- Add role column that was missing from patch 004.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'owner'
  CHECK (role IN ('owner', 'realtor'));

NOTIFY pgrst, 'reload schema';
