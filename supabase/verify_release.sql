-- ============================================================================
-- verify_release.sql — одна перевірка готовності БД до публікації.
-- Запусти в Supabase Dashboard → SQL Editor. Кожен рядок результату має бути
-- OK; будь-який MISSING = відповідна міграція не застосована (файл вказано).
-- ============================================================================

WITH checks(ord, item, migration, ok) AS (VALUES
  -- 026: security audit fixes
  (1,  'get_shared_collection перевіряє share_expires_at', '026_security_audit_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_shared_collection'
              AND prosrc LIKE '%share_expires_at%')),
  (2,  'індекс idx_audit_log_user_created', '026_security_audit_fixes.sql',
      EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='idx_audit_log_user_created')),

  -- 036/037: share management + db share fixes
  (3,  'RPC subscribe_to_shared_db', '036/037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='subscribe_to_shared_db')),
  (4,  'RPC manage_share', '036/037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='manage_share')),
  (5,  'databases.share_token NOT NULL', '037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_name='databases' AND column_name='share_token' AND is_nullable='NO')),

  -- 038: storage write hardening (пермісивні політики МАЮТЬ зникнути)
  (6,  'photos: пермісивна photos_insert_auth ВИДАЛЕНА', '038_storage_write_hardening.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='storage'
                  AND tablename='objects' AND policyname='photos_insert_auth')),
  (7,  'photos: строга storage_photos_insert існує', '038_storage_write_hardening.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='storage'
              AND tablename='objects' AND policyname='storage_photos_insert')),
  (8,  'property_files: INSERT вимагає володіння об''єктом', '038_storage_write_hardening.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='property_files'
              AND cmd='INSERT' AND with_check LIKE '%properties%')),

  -- 039: parking
  (9,  'properties.parking_type + ev_charger', '039_parking_fields.sql',
      (SELECT count(*)=2 FROM information_schema.columns
       WHERE table_name='properties' AND column_name IN ('parking_type','ev_charger'))),
  (10, 'rent_type CHECK містить per_day', '039_parking_fields.sql',
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname='properties_rent_type_check'
              AND pg_get_constraintdef(oid) LIKE '%per_day%')),

  -- 040: public preview fixes
  (11, 'get_public_property_preview віддає owner_currency', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_property_preview'
              AND pg_get_function_result(oid) LIKE '%owner_currency%')),
  (12, 'get_public_db_preview віддає sale_price + currency', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_db_preview'
              AND pg_get_function_result(oid) LIKE '%property_sale_price%')),
  (13, 'record_public_view(p_token, p_kind)', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='record_public_view'
              AND pg_get_function_arguments(oid) LIKE '%p_kind%')),
  (14, 'property_views.db_id/collection_id', '040_public_preview_fixes.sql',
      (SELECT count(*)=2 FROM information_schema.columns
       WHERE table_name='property_views' AND column_name IN ('db_id','collection_id'))),

  -- 041: team members
  (18, 'db_members існує з RLS', '041_team_members.sql',
      EXISTS (SELECT 1 FROM pg_class WHERE relname='db_members' AND relrowsecurity)),
  (19, 'редакторські політики на properties/payments', '041_team_members.sql',
      (SELECT count(*)>=2 FROM pg_policies WHERE policyname IN ('props_editor_all','rent_payments_editor_all'))),
  (20, 'RPC claim_team_invite', '041_team_members.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='claim_team_invite')),

  -- Наскрізні інваріанти
  (15, 'RLS увімкнено на всіх 15 таблицях', 'будь-яка пропущена',
      (SELECT count(*)>=15 FROM pg_tables t JOIN pg_class c ON c.relname=t.tablename
       WHERE t.schemaname='public' AND c.relrowsecurity)),
  (16, 'handle_new_user тригер на auth.users ВІДСУТНІЙ', '003_reconcile.sql',
      NOT EXISTS (SELECT 1 FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid
                  JOIN pg_namespace n ON n.oid=c.relnamespace
                  WHERE n.nspname='auth' AND c.relname='users' AND tg.tgname LIKE '%handle_new_user%')),
  (17, 'current_app_user_id парсить email-claim', '002_rls/003_reconcile.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='current_app_user_id'
              AND prosrc LIKE '%email%'))
)
SELECT
  CASE WHEN ok THEN '✅ OK     ' ELSE '❌ MISSING' END AS status,
  item,
  CASE WHEN ok THEN '' ELSE '→ виконай ' || migration END AS action
FROM checks ORDER BY ord;
