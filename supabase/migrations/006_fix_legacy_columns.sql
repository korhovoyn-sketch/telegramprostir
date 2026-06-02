-- Fix: detect and neutralize ALL legacy NOT NULL columns that block INSERTs.
-- The app only requires specific columns to be NOT NULL (listed below).
-- Any OTHER NOT NULL column without a default is a legacy artifact that must
-- be made nullable so INSERTs don't fail.

-- ── 1. Drop known legacy columns ─────────────────────────────────────────────
ALTER TABLE databases   DROP COLUMN IF EXISTS slug;
ALTER TABLE databases   DROP COLUMN IF EXISTS city;
ALTER TABLE databases   DROP COLUMN IF EXISTS district;
ALTER TABLE properties  DROP COLUMN IF EXISTS title;
ALTER TABLE properties  DROP COLUMN IF EXISTS type;      -- legacy, app uses status+rent_type
ALTER TABLE users       DROP COLUMN IF EXISTS username;  -- legacy, app uses tg_username

-- ── 2. Auto-fix: make any unexpected NOT NULL/no-default column nullable ──────
-- The whitelist below are columns the app truly requires to be NOT NULL.
-- Everything else that is NOT NULL + no default is a legacy artifact.
DO $$
DECLARE
  r RECORD;
  required_not_null TEXT[] := ARRAY[
    'users.id', 'users.first_name', 'users.role', 'users.language_code',
    'users.currency', 'users.plan',
    'databases.id', 'databases.owner_id', 'databases.name',
    'databases.type', 'databases.color',
    'properties.id', 'properties.db_id', 'properties.owner_id', 'properties.name',
    'property_photos.id', 'property_photos.property_id', 'property_photos.storage_path',
    'realtor_subscriptions.id', 'realtor_subscriptions.realtor_id', 'realtor_subscriptions.db_id',
    'collections.id', 'collections.realtor_id', 'collections.name',
    'collection_properties.collection_id', 'collection_properties.property_id',
    'property_views.id', 'property_views.property_id',
    'notifications.id', 'notifications.user_id', 'notifications.type', 'notifications.title'
  ];
BEGIN
  FOR r IN
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name IN (
        'users', 'databases', 'properties', 'property_photos',
        'realtor_subscriptions', 'collections', 'collection_properties',
        'property_views', 'notifications'
      )
      AND is_nullable = 'NO'
      AND column_default IS NULL
      AND NOT (table_name || '.' || column_name = ANY(required_not_null))
  LOOP
    RAISE NOTICE 'Making nullable: %.%', r.table_name, r.column_name;
    EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP NOT NULL', r.table_name, r.column_name);
  END LOOP;
END $$;

-- ── 3. Diagnostic: confirm no unexpected NOT NULL columns remain ──────────────
SELECT
  table_name,
  column_name,
  data_type,
  is_nullable,
  column_default
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN (
    'users', 'databases', 'properties', 'property_photos',
    'realtor_subscriptions', 'collections', 'collection_properties',
    'property_views', 'notifications'
  )
  AND is_nullable = 'NO'
  AND column_default IS NULL
  AND column_name <> 'id'
ORDER BY table_name, column_name;
-- Expected result: only the whitelisted required columns above should appear.
