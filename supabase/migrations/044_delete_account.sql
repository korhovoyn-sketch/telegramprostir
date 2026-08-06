-- ============================================================================
-- 044_delete_account.sql — самостійне видалення акаунта (GDPR / вимоги Telegram).
-- Ідемпотентна. Виконувати в Supabase Dashboard → SQL Editor.
--
-- Політика конфіденційності обіцяє право на видалення; ця RPC робить його
-- самостійним, без листування з підтримкою.
--
-- ВАЖЛИВО про порядок: майже все посилається на users(id) з ON DELETE CASCADE
-- (databases → properties → photos/files/payments, collections, subscriptions,
-- notifications, guest_links, db_members). ВИНЯТОК — property_views.viewer_id:
-- він оголошений БЕЗ ON DELETE, тобто NO ACTION, і одна чужа переглядова
-- позначка заблокувала б увесь DELETE. Тому спершу знеособлюємо її (NULL),
-- зберігаючи лічильник переглядів власнику обʼєкта, але прибираючи звʼязок
-- із видаленим користувачем.
--
-- Файли в storage видаляє КЛІЄНТ перед викликом (SQL-видалення storage.objects
-- лишило б самі файли в бакеті). Осиротілі файли — не витік: політики читання
-- прив'язані до рядків, яких уже немає.
-- ============================================================================

CREATE OR REPLACE FUNCTION delete_my_account()
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

-- ── Діагностика ──────────────────────────────────────────────────────────────
SELECT '════ delete_my_account ════' AS check;
SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args, p.prosecdef AS security_definer
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.proname = 'delete_my_account';

SELECT '════ DONE — 044 delete account applied ════' AS result;
