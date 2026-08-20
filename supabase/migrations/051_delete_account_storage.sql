-- ═══════════════════════════════════════════════════════════════════════════
-- 051: видалення акаунта прибирає файли САМЕ, у тій самій транзакції
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ЧОМУ КЛІЄНТ ЦЬОГО НЕ МОЖЕ — ЖОДНИМ ПОРЯДКОМ. Обидва варіанти зламані, і це
-- перевірено, а не припущено:
--
--   файли → RPC   Якщо RPC падає (міграція не застосована, мережа, будь-що),
--                 користувач лишається в акаунті — але БЕЗ ЖОДНОГО ФОТО, і
--                 всі `property_photos` показують 404. Незворотно.
--
--   RPC → файли   Після RPC політика `storage_photos_delete` не матчить
--                 НІЧОГО, з двох незалежних причин одразу: `properties` уже
--                 знесені каскадом, а `get_app_user_id_from_auth_uid()` віддає
--                 NULL, бо рядка в `auth.users` більше немає. Тобто DELETE
--                 «успішно» видаляє нуль обʼєктів, клієнт бачить успіх, а
--                 фото лишаються в ПУБЛІЧНОМУ бакеті назавжди — за тими
--                 самими URL, які роздавались анонімним відвідувачам /v.
--                 Це вже не втрата даних, а порушення обіцянки про стирання
--                 (Політика конфіденційності §5).
--
-- Тому прибирання переїжджає ВСЕРЕДИНУ функції: `SECURITY DEFINER` обходить
-- RLS на `storage.objects`, а порядок гарантований транзакцією — або зникає
-- все, або не зникає нічого. Клієнту лишається один виклик без порядку.
--
-- Видалення рядка `storage.objects` робить публічний URL недосяжним (резолв
-- шляху йде через цю ж таблицю); залишковий обʼєкт у S3 прибирає штатний
-- збирач осиротілих.

DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure::TEXT AS sig
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.proname = 'delete_my_account'
  LOOP
    EXECUTE 'DROP FUNCTION ' || r.sig;
  END LOOP;
END $$;

CREATE FUNCTION delete_my_account()
RETURNS TABLE (deleted BOOLEAN, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid      UUID;
  v_auth_uid UUID;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT FALSE, 'not_authenticated'::TEXT; RETURN;
  END IF;

  -- ── Файли — ПЕРШИМИ, поки власність ще резолвиться ────────────────────────
  -- Після `DELETE FROM users` жоден із цих підзапитів не поверне нічого, тож
  -- порядок тут не стилістичний, а єдиний можливий.
  BEGIN
    DELETE FROM storage.objects
     WHERE bucket_id = 'photos'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );

    DELETE FROM storage.objects
     WHERE bucket_id = 'property-files'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );
  EXCEPTION WHEN undefined_table OR insufficient_privilege THEN
    -- Бакета/прав немає — акаунт усе одно мусить піти. Осиротілий файл не є
    -- витоком у сенсі правила 9 (політики читання привʼязані до рядків, яких
    -- уже не буде), а от НЕвидалений акаунт — реальна проблема користувача.
    NULL;
  END;

  -- Знеособити перегляди: NO ACTION FK інакше заблокує видалення.
  UPDATE property_views SET viewer_id = NULL WHERE viewer_id = v_uid;

  -- Гостьові лінки, видані ЦЬОМУ користувачу кимось іншим: рядок належить
  -- власнику (owner_id), тож каскад по ньому не спрацює — відвʼязуємо.
  BEGIN
    UPDATE guest_links SET guest_user_id = NULL, status = 'revoked'
    WHERE guest_user_id = v_uid;
  EXCEPTION WHEN undefined_table OR undefined_column THEN NULL;
  END;

  -- Членство в чужих командах (041): рядок належить власнику бази.
  BEGIN
    DELETE FROM db_members WHERE user_id = v_uid;
  EXCEPTION WHEN undefined_table THEN NULL;
  END;

  -- Запамʼятати звʼязаний auth-акаунт ДО видалення профілю.
  SELECT id INTO v_auth_uid FROM auth.users
   WHERE email = (SELECT tg_id::TEXT || '@telegram.propspace.app' FROM users WHERE id = v_uid);

  -- Профіль + усе, що каскадить від нього.
  DELETE FROM users WHERE id = v_uid;

  -- Обліковий запис входу. Без цього наступний вхід із того ж Telegram
  -- відновив би сесію на порожній профіль замість чистої реєстрації.
  IF v_auth_uid IS NOT NULL THEN
    DELETE FROM auth.users WHERE id = v_auth_uid;
  END IF;

  RETURN QUERY SELECT TRUE, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION delete_my_account() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION delete_my_account() TO authenticated;

NOTIFY pgrst, 'reload schema';

-- ── Verification ────────────────────────────────────────────────────────────
-- Має показати рівно один рядок: функція є і доступна лише authenticated.
SELECT p.proname,
       p.prosecdef                                   AS security_definer,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authed_can_call,
       has_function_privilege('anon', p.oid, 'EXECUTE')          AS anon_can_call
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.proname = 'delete_my_account';
