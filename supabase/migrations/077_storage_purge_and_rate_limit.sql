-- ============================================================================
-- 077: ФАЙЛИ ЗНИКАЮТЬ РАЗОМ ІЗ РЯДКОМ, ЛІМІТЕР — ОДНИМ ЗАПИТОМ
-- ============================================================================
-- Три речі, знайдені читанням живої бази (жовтень 2026).
--
-- 1. ВИДАЛЕННЯ АКАУНТА В ПРОДІ ПАДАЛО ДЛЯ ВСІХ. Supabase Storage тримає на
--    `storage.objects` тригер `protect_objects_delete`: статементний BEFORE
--    DELETE, що кидає 42501, якщо в транзакції не виставлено
--    `storage.allow_delete_query = 'true'`. Сервер Storage ставить цей прапорець
--    перед власними видаленнями; SQL-функція мусить зробити це сама.
--    `delete_my_account()` (051) робила два прямі DELETE без прапорця, а
--    тригер СТАТЕМЕНТНИЙ — тобто спрацьовує й тоді, коли жоден рядок не
--    підпадає під умову. Отже кожен виклик падав, навіть у користувача без
--    жодного файлу, і самостійне стирання з §5 Політики в проді не працювало.
--    Стенд цього не бачив: його модель сховища тригера не мала (тепер має,
--    `scripts/pg-shim.sql`).
--
-- 2. ФОТО ВИДАЛЕНОГО ОБʼЄКТА ЛИШАЛИСЬ ПУБЛІЧНИМИ. Клієнт чистить сховище ПІСЛЯ
--    видалення рядка (правило 9), але політики сховища дозволяють видалення
--    лише щодо ІСНУЮЧОГО обʼєкта (`get_owner_property_ids(...)`). Після
--    каскаду `remove()` не матчить нічого й віддає порожній список без
--    помилки, а фото лишаються в публічному бакеті за URL, які роздавались на
--    /v, — назавжди й без способу їх знайти. Порядку, який це лікує на
--    клієнті, не існує: той самий аналіз, що для акаунта в 051.
--    Тому прибирання переїжджає в тригер AFTER DELETE на `properties`: лише
--    для рядків, які РЕАЛЬНО видалились (RLS пропустив), і в тій самій
--    транзакції. Покриває всі шляхи — обʼєкт, пакет, базу й акаунт (каскади).
--
-- 3. ЛІМІТЕР ВХОДУ НЕ БУВ АТОМАРНИМ. Edge-функція читала `count` і писала
--    `count + 1`, тож N паралельних запитів читали те саме значення, і стеля
--    обходилась паралелізмом. `rate_limit_hit` робить це одним
--    INSERT … ON CONFLICT DO UPDATE … RETURNING під блокуванням рядка.
--
-- МЕЖА, НАЗВАНА ЧЕСНО: прямий DELETE прибирає РЯДКИ МЕТАДАНИХ. Через API і
-- публічний URL файл після цього не віддається (резолв іде через ту саму
-- таблицю), але байти в S3 лишаються — саме від цього тригер платформи
-- застерігає. Обмін свідомий: недосяжний залишок проти фото видаленого обʼєкта,
-- яке будь-хто відкриває за старим посиланням. Кешована CDN-копія може
-- віддаватись до спливу свого TTL.
-- ============================================================================

BEGIN;

-- ── 1. Видалення акаунта з прапорцем платформи ──────────────────────────────
-- Тіло — 051 дослівно, крім прапорця і гілки `insufficient_privilege`. Сигнатура
-- і тип результату ті самі, тож CREATE OR REPLACE без DROP.
CREATE OR REPLACE FUNCTION delete_my_account()
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

  -- Файли — ПЕРШИМИ, поки власність ще резолвиться (див. 051).
  BEGIN
    -- Передумова 051: власник функції обходить RLS, інакше «файлів немає» і
    -- «файлів не видно» нерозрізненні.
    IF NOT COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), FALSE)
       AND COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid = 'storage.objects'::regclass), FALSE)
    THEN
      RETURN QUERY SELECT FALSE, 'storage_not_verifiable'::TEXT; RETURN;
    END IF;

    -- 077: без прапорця тригер платформи кидає 42501 на БУДЬ-ЯКИЙ прямий
    -- DELETE. Локально для транзакції: далі в ній він потрібен ще й каскаду
    -- (тригер обʼєктів нижче), а сама транзакція — це один виклик RPC.
    PERFORM set_config('storage.allow_delete_query', 'true', true);

    SELECT count(*) INTO v_want_photos FROM storage.objects
     WHERE bucket_id = 'photos'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );
    SELECT count(*) INTO v_want_files FROM storage.objects
     WHERE bucket_id = 'property-files'
       AND SPLIT_PART(name, '/', 1) IN (
         SELECT p.id::TEXT FROM properties p WHERE p.owner_id = v_uid
       );

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
  EXCEPTION
    WHEN undefined_table THEN
      v_want_photos := 0; v_got_photos := 0;
      v_want_files  := 0; v_got_files  := 0;
    -- Платформа змінила механізм захисту (інша назва прапорця тощо). Акаунт
    -- лишається живим з ІМЕНОВАНОЮ причиною, а не загальною помилкою: стан
    -- «є акаунт і є файли» оборотний, «немає акаунта, є файли» — ні.
    WHEN insufficient_privilege THEN
      RETURN QUERY SELECT FALSE, 'storage_protected'::TEXT; RETURN;
  END;

  IF v_got_photos < v_want_photos OR v_got_files < v_want_files THEN
    RETURN QUERY SELECT FALSE, 'storage_not_cleared'::TEXT; RETURN;
  END IF;

  UPDATE property_views SET viewer_id = NULL WHERE viewer_id = v_uid;

  BEGIN
    UPDATE guest_links SET guest_user_id = NULL, status = 'revoked'
    WHERE guest_user_id = v_uid;
  EXCEPTION WHEN undefined_table OR undefined_column THEN NULL;
  END;

  BEGIN
    DELETE FROM db_members WHERE user_id = v_uid;
  EXCEPTION WHEN undefined_table THEN NULL;
  END;

  SELECT id INTO v_auth_uid FROM auth.users
   WHERE email = (SELECT tg_id::TEXT || '@telegram.propspace.app' FROM users WHERE id = v_uid);

  DELETE FROM users WHERE id = v_uid;

  IF v_auth_uid IS NOT NULL THEN
    DELETE FROM auth.users WHERE id = v_auth_uid;
  END IF;

  RETURN QUERY SELECT TRUE, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION delete_my_account() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION delete_my_account() TO authenticated;

-- ── 2. Файли видаленого обʼєкта зникають разом із ним ───────────────────────
-- Статементний тригер з таблицею переходу: пакетне видалення й каскад бази
-- дають ОДИН запит до сховища, а не по запиту на обʼєкт.
--
-- Чого тригер свідомо НЕ робить — не валить видалення обʼєкта, якщо платформа
-- змінила механізм захисту: недоступне видалення обʼєкта — видимий збій
-- основної функції, а лишені файли — той самий стан, що був до 077. Для
-- акаунта навпаки (вище): там обіцянка стирання сильніша, і краще відмовити.
CREATE OR REPLACE FUNCTION purge_deleted_property_files()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_prev TEXT := current_setting('storage.allow_delete_query', true);
BEGIN
  BEGIN
    PERFORM set_config('storage.allow_delete_query', 'true', true);
    DELETE FROM storage.objects o
     WHERE o.bucket_id IN ('photos', 'property-files')
       AND SPLIT_PART(o.name, '/', 1) IN (SELECT g.id::TEXT FROM gone g);
    -- Прапорець повертається до попереднього значення: решта транзакції
    -- (наприклад, `delete_my_account`, що поставила його сама) не мусить
    -- залежати від того, чи спрацював цей тригер.
    PERFORM set_config('storage.allow_delete_query', COALESCE(v_prev, ''), true);
  EXCEPTION
    WHEN undefined_table OR invalid_schema_name THEN NULL;
    WHEN insufficient_privilege THEN
      RAISE WARNING '[077] файли видалених обʼєктів не прибрано: сховище відхилило прямий DELETE';
  END;
  RETURN NULL;
END;
$$;

-- Тригерна функція — нікому (075): Postgres не питає EXECUTE при спрацюванні.
REVOKE ALL ON FUNCTION purge_deleted_property_files() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS trg_purge_deleted_property_files ON properties;
CREATE TRIGGER trg_purge_deleted_property_files
  AFTER DELETE ON properties
  REFERENCING OLD TABLE AS gone
  FOR EACH STATEMENT
  EXECUTE FUNCTION purge_deleted_property_files();

-- ── 3. Лімітер одним запитом ────────────────────────────────────────────────
-- Повертає TRUE, якщо запит у межах стелі. Конфлікт по ключу блокує рядок, тож
-- паралельні виклики бачать результат один одного, а не той самий `count`.
-- `LEAST` — щоб лічильник під флудом не ріс без меж (INT переповнився б
-- помилкою, а помилка лімітера — це відмова у вході для справжнього
-- користувача).
--
-- SECURITY INVOKER: кличе лише службовий ключ, у якого й так є права на
-- таблицю, тож definer нічого не дає, а розширив би периметр.
CREATE OR REPLACE FUNCTION rate_limit_hit(p_key TEXT, p_max INT, p_window_ms INT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  v_count INT;
BEGIN
  IF p_key IS NULL OR p_key = '' OR p_max IS NULL OR p_max < 1
     OR p_window_ms IS NULL OR p_window_ms < 1 THEN
    RAISE EXCEPTION 'rate_limit_hit: invalid arguments' USING ERRCODE = '22023';
  END IF;

  INSERT INTO rate_limits AS r (ip, count, reset_at)
  VALUES (p_key, 1, now() + make_interval(secs => p_window_ms / 1000.0))
  ON CONFLICT (ip) DO UPDATE
     SET count    = CASE WHEN r.reset_at <= now() THEN 1
                         ELSE LEAST(r.count + 1, p_max + 1) END,
         reset_at = CASE WHEN r.reset_at <= now() THEN EXCLUDED.reset_at
                         ELSE r.reset_at END
  RETURNING r.count INTO v_count;

  RETURN v_count <= p_max;
END;
$$;

REVOKE ALL ON FUNCTION rate_limit_hit(TEXT, INT, INT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION rate_limit_hit(TEXT, INT, INT) TO service_role;

NOTIFY pgrst, 'reload schema';

COMMIT;
