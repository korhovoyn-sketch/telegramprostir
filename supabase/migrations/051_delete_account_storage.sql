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
-- Тому прибирання переїжджає ВСЕРЕДИНУ функції, у ту саму транзакцію: або
-- зникає все, або не зникає нічого. Клієнту лишається один виклик без порядку.
--
-- ДВІ ТОЧНОСТІ, ЯКІ ТУТ ВАЖЛИВІ (перше формулювання було хибним):
--
--   1. `SECURITY DEFINER` НЕ обходить RLS. Він лише міняє ефективну роль;
--      політики далі діють, якщо роль не володіє таблицею і не має BYPASSRLS.
--      `storage.objects` належить `supabase_storage_admin`, а обидві delete-
--      політики (038, 023) видані `TO authenticated` — тобто до `postgres`
--      вони не застосовуються взагалі. Працює це тому, що в Supabase
--      `postgres` має `rolbypassrls`. Це ЗОВНІШНЯ залежність, і саме тому
--      нижче стоїть перевірка кількості: якщо припущення колись зміниться,
--      функція мусить СКАЗАТИ про це, а не тихо лишити файли.
--
--   2. Видалення рядка `storage.objects` робить публічний URL недосяжним
--      (резолв шляху йде через цю ж таблицю). Байти в S3 при цьому
--      ЛИШАЮТЬСЯ — штатного збирача осиротілих у Supabase Storage немає.
--      Через API вони недосяжні без рядка, тож живим лінком це не є, але
--      стверджувати «прибере збирач» було вигадкою.

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
  v_uid         UUID;
  v_auth_uid    UUID;
  v_want_photos BIGINT := 0;
  v_want_files  BIGINT := 0;
  v_got_photos  BIGINT := 0;
  v_got_files   BIGINT := 0;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT FALSE, 'not_authenticated'::TEXT; RETURN;
  END IF;

  -- ── Файли — ПЕРШИМИ, поки власність ще резолвиться ────────────────────────
  -- Після `DELETE FROM users` жоден із цих підзапитів не поверне нічого, тож
  -- порядок тут не стилістичний, а єдиний можливий.
  -- Скільки файлів МАЄ зникнути — рахуємо ДО видалення.
  SELECT count(*) INTO v_want_photos
    FROM property_photos ph JOIN properties p ON p.id = ph.property_id
   WHERE p.owner_id = v_uid;
  SELECT count(*) INTO v_want_files
    FROM property_files f JOIN properties p ON p.id = f.property_id
   WHERE p.owner_id = v_uid;

  BEGIN
    DELETE FROM storage.objects
     WHERE bucket_id = 'photos'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );
    GET DIAGNOSTICS v_got_photos = ROW_COUNT;

    DELETE FROM storage.objects
     WHERE bucket_id = 'property-files'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );
    GET DIAGNOSTICS v_got_files = ROW_COUNT;
  EXCEPTION WHEN undefined_table THEN
    -- Бакета немає взагалі (свіжа БД без storage) — лічильники лишаються 0,
    -- і перевірка нижче пропустить, бо чекати теж нема чого.
    v_got_photos := v_want_photos;
    v_got_files  := v_want_files;
  END;

  -- ДОВЕСТИ, а не припустити. Відмова RLS не є помилкою: DELETE просто
  -- зачепить нуль рядків і поверне успіх. Без цієї перевірки функція
  -- рапортувала б `deleted = true`, лишивши фото в ПУБЛІЧНОМУ бакеті — рівно
  -- те порушення обіцянки про стирання, заради якого міграція й пишеться.
  -- Акаунт при цьому НЕ видаляється: стан «є акаунт і є файли» оборотний,
  -- «немає акаунта, є файли» — ні.
  IF v_got_photos < v_want_photos OR v_got_files < v_want_files THEN
    RETURN QUERY SELECT FALSE, 'storage_not_cleared'::TEXT; RETURN;
  END IF;

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
       has_function_privilege('anon', p.oid, 'EXECUTE')          AS anon_can_call,
       -- Припущення, на якому тримається стирання файлів (див. шапку §1).
       -- Якщо `owner_bypasses_rls` = false, функція не зможе чистити storage —
       -- і тепер СКАЖЕ про це через `storage_not_cleared`, а не змовчить.
       (SELECT r.rolbypassrls FROM pg_roles r WHERE r.rolname = pg_get_userbyid(p.proowner))
         AS owner_bypasses_rls
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.proname = 'delete_my_account';
