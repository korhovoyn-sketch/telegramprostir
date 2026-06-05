-- 015: Add utilities (tap-selectable tags) and address to properties
-- Apply in Supabase Dashboard → SQL Editor

ALTER TABLE properties
  ADD COLUMN IF NOT EXISTS address     TEXT,
  ADD COLUMN IF NOT EXISTS utilities   TEXT[] DEFAULT '{}';

COMMENT ON COLUMN properties.address   IS 'Optional street address of the space';
COMMENT ON COLUMN properties.utilities IS 'Selected utility services: electricity, water, heating, gas, backup';
