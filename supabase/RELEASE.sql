-- ============================================================================
-- PropSpace — ОДИН файл для накату в Supabase Dashboard → SQL Editor
--
-- ЗГЕНЕРОВАНО: scripts/build-release-sql.sh. РУКАМИ НЕ ПРАВИТИ.
-- Джерело правди — supabase/migrations/; CI звіряє, що цей файл їм
-- відповідає (робота `migrations`, крок «RELEASE.sql не розійшовся»).
--
-- Містить міграції 28 шт., від 48 і далі:
--   * 048_guest_name.sql
--   * 049_drop_idor_get_shared_collection.sql
--   * 050_guest_preview_owner_check.sql
--   * 051_delete_account_storage.sql
--   * 052_reminders_fix_and_lockdown.sql
--   * 053_owner_policies_target_ownership.sql
--   * 054_storage_single_identity.sql
--   * 055_fix_subscribe_ambiguous_db_id.sql
--   * 056_collection_target_access.sql
--   * 057_helper_identity_guard.sql
--   * 058_reminders_require_tg_id.sql
--   * 059_drop_legacy_uuid_tokens.sql
--   * 060_revoke_destroys_token.sql
--   * 061_public_phone_opt_in.sql
--   * 062_legacy_permissive_and_acl.sql
--   * 063_view_insert_editors_and_dbs.sql
--   * 064_landlord_name.sql
--   * 065_lease_reminders.sql
--   * 066_identity_anchor_storage_enum_guest_target.sql
--   * 067_tenancies.sql
--   * 068_tenancies_read_only.sql
--   * 069_access_integrity.sql
--   * 070_reminders_skip_paid.sql
--   * 071_partial_payments.sql
--   * 072_rent_terms_history.sql
--   * 073_db_activity.sql
--   * 074_account_erasure.sql
--   * 075_function_acl_supabase_defaults.sql
--
-- ЯК НАКОЧУВАТИ: вставити цілком і виконати ОДИН раз.
--   * усе загорнуте в BEGIN/COMMIT — при будь-якій помилці НІЧОГО не
--     застосується, тобто напівстану не буде. Це не декларація: CI
--     підставляє збій у зоні ОСТАННЬОЇ міграції і вимагає, щоб у базі
--     не лишилось обʼєктів попередніх (verify-migrations.sh);
--   * файл ІДЕМПОТЕНТНИЙ (перевірено повторним накатом у CI), тож
--     повторний запуск безпечний;
--   * ПЕРЕВІРКА ВБУДОВАНА: після COMMIT файл сам виконує
--     supabase/verify_release.sql, і редактор показує її таблицю —
--     74 рядків, кожен має бути ✅ OK. Якщо замість таблиці помилка,
--     НІЧОГО не застосовано: усуньте причину й запустіть файл ще раз.
-- ============================================================================

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────
-- ПЕРЕДПОЛЬОТНА ПЕРЕВІРКА
-- ─────────────────────────────────────────────────────────────────────────
-- Накат у проді робився ВРУЧНУ і з прогалинами: реальний випадок — файл упав
-- на `mark_overdue_payments() does not exist`, бо міграція 024 туди так і не
-- потрапила. Помилка від Postgres називає лише сам обʼєкт, не кажучи ані що
-- саме бракує в цілому, ані яку міграцію запустити.
--
-- Тому спершу перевіряємо ВСЕ, на що спирається цей файл, і при потребі
-- падаємо ОДИН раз зі списком. Транзакція все одно відкотиться, тож стан бази
-- не змінюється — просто ви одразу бачите повну картину.
DO $$
DECLARE missing TEXT := '';
BEGIN
  -- Таблиці, на яких створюються політики або додаються колонки.
  IF to_regclass('public.users')                 IS NULL THEN missing := missing || E'\n  * таблиця users (001_schema)'; END IF;
  IF to_regclass('public.properties')            IS NULL THEN missing := missing || E'\n  * таблиця properties (001_schema)'; END IF;
  IF to_regclass('public.guest_links')           IS NULL THEN missing := missing || E'\n  * таблиця guest_links (027_guest_role)'; END IF;
  IF to_regclass('public.collection_properties') IS NULL THEN missing := missing || E'\n  * таблиця collection_properties (001_schema)'; END IF;
  IF to_regclass('public.rent_payments')         IS NULL THEN missing := missing || E'\n  * таблиця rent_payments (021_rent_payments)'; END IF;
  IF to_regclass('public.rent_payment_records')  IS NULL THEN missing := missing || E'\n  * таблиця rent_payment_records (021_rent_payments)'; END IF;
  IF to_regclass('public.db_members')            IS NULL THEN missing := missing || E'\n  * таблиця db_members (041_team_members)'; END IF;
  IF to_regclass('public.property_files')        IS NULL THEN missing := missing || E'\n  * таблиця property_files (033_property_files)'; END IF;
  IF to_regclass('public.collections')           IS NULL THEN missing := missing || E'\n  * таблиця collections (001_schema)'; END IF;
  IF to_regclass('public.databases')             IS NULL THEN missing := missing || E'\n  * таблиця databases (001_schema)'; END IF;
  IF to_regclass('public.property_views')        IS NULL THEN missing := missing || E'\n  * таблиця property_views (001_schema)'; END IF;
  IF to_regclass('public.realtor_subscriptions') IS NULL THEN missing := missing || E'\n  * таблиця realtor_subscriptions (001_schema)'; END IF;

  -- Колонки з ПІЗНІХ міграцій, які читають тіла функцій цього файлу. Саме цей
  -- клас і дав збій на `mark_overdue_payments`: прогалина всередині 001-047
  -- проявляється не на початку накату, а посеред нього — і повідомлення
  -- Postgres назве колонку, не сказавши, якої міграції бракує.
  IF to_regclass('public.properties') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='area_basis')
      THEN missing := missing || E'\n  * колонка properties.area_basis (042_area_basis)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='parking_type')
      THEN missing := missing || E'\n  * колонка properties.parking_type (039_parking_fields)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='ev_charger')
      THEN missing := missing || E'\n  * колонка properties.ev_charger (039_parking_fields)'; END IF;
  END IF;
  IF to_regclass('public.property_views') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='property_views' AND column_name='db_id')
      THEN missing := missing || E'\n  * колонка property_views.db_id (040_public_preview_fixes)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='property_views' AND column_name='collection_id')
      THEN missing := missing || E'\n  * колонка property_views.collection_id (040_public_preview_fixes)'; END IF;
  END IF;

  -- Хелпери, які викликаються з тіл функцій і предикатів політик.
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                 WHERE n.nspname='public' AND p.proname='current_app_user_id')
    THEN missing := missing || E'\n  * функція current_app_user_id() (002_rls / 003_reconcile)'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                 WHERE n.nspname='public' AND p.proname='get_app_user_id_from_auth_uid')
    THEN missing := missing || E'\n  * функція get_app_user_id_from_auth_uid() (030 / 045)'; END IF;

  IF missing <> '' THEN
    RAISE EXCEPTION E'У базі бракує того, на що спирається цей файл:%\n\nЗапустіть спершу вказані міграції з supabase/migrations/, потім цей файл ще раз.\nНІЧОГО не застосовано — транзакцію відкочено.', missing;
  END IF;
END $$;


-- ─────────────────────────────────────────────────────────────────────────
-- СКИДАННЯ ФУНКЦІЙ, ЧИЮ СИГНАТУРУ МІНЯЄ ПІЗНІША МІГРАЦІЯ В ЦЬОМУ Ж ФАЙЛІ
-- ─────────────────────────────────────────────────────────────────────────
-- Файл — КОНКАТЕНАЦІЯ, і саме тому тут потрібне те, чого не потрібно жодній
-- окремій міграції. Порядок усередині фіксований номерами: 061 переоголошує
-- публічні превʼю через `CREATE OR REPLACE`, а 064 ДОДАЄ їм колонку, тобто
-- міняє тип результату. Перший накат проходить (061 створює, 064 підміняє),
-- ДРУГИЙ падає: `CREATE OR REPLACE` у 061 наштовхується на функцію з іншим
-- типом результату (42P13, «cannot change return type of existing function»).
--
-- Тобто без цього блоку файл перестає бути ІДЕМПОТЕНТНИМ — властивість, яку
-- обіцяє його ж шапка і яку перевіряє CI повторним накатом.
--
-- Дропаємо перед усім: обидві міграції нижче створюють ці функції заново, а
-- транзакція гарантує, що проміжного стану ззовні не видно.
--
-- ДОДАВАТИ СЮДИ, щойно нова міграція в цьому вікні змінить тип результату
-- функції, яку раніша міграція створює через `CREATE OR REPLACE`. Забути не
-- страшно: повторний накат у CI впаде рівно з цієї причини.
DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);


-- ─────────────────────────────────────────────────────────────────────────
-- 048_guest_name.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 048: імʼя гостя, що прийняв запрошення
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ЩО ЛІКУЄ. `db_members` має `member_name` — його заповнює `claim_team_invite`
-- (041), тож у розділі «Команда» власник бачить РЕАЛЬНЕ імʼя людини. У
-- `guest_links` такої колонки не було взагалі: лишався `guest_user_id` (UUID,
-- який ніде не показати) і `label` — підпис, який власник вигадав САМ ще до
-- того, як лінк хтось прийняв.
--
-- Наслідок для власника: список гостей відповідав на питання «як я назвав ці
-- запрошення», але не на питання «хто цим користується». Для доступу до
-- нерухомості це різні питання, і важливе саме друге.
--
-- Дзеркалить 041 буквально: та сама колонка, той самий спосіб зібрати імʼя,
-- той самий момент запису — щоб два розділи не розійшлись знову.

ALTER TABLE guest_links ADD COLUMN IF NOT EXISTS guest_name TEXT;

-- ── Клейм тепер фіксує імʼя ─────────────────────────────────────────────────
-- Повне тіло, а не патч: `CREATE OR REPLACE` замінює функцію цілком, тож усі
-- наявні гарди (заборона клейму власного лінка, ідемпотентність, revoked)
-- мусять лишитись ТУТ. Копія з 028 плюс `guest_name`.
CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
  v_name TEXT;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status, owner_id
  INTO v_link
  FROM guest_links
  WHERE invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_link.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  -- Owner must never claim their own invite: it would demote them to guest role,
  -- locking them out of all their databases with no client-side recovery path.
  IF v_uid = v_link.owner_id THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Already claimed by this user → idempotent success
  IF v_link.status = 'active' AND v_link.guest_user_id = v_uid THEN
    RETURN jsonb_build_object(
      'property_id', v_link.property_id,
      'db_id',       v_link.db_id
    );
  END IF;

  -- Already claimed by someone else
  IF v_link.status = 'active' AND v_link.guest_user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  SELECT NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
  INTO v_name
  FROM users u WHERE u.id = v_uid;

  UPDATE guest_links
  SET guest_user_id = v_uid,
      status        = 'active',
      claimed_at    = now(),
      guest_name    = v_name
  WHERE id = v_link.id;

  -- Ensure user has guest role (onboarding may have left them as owner default)
  UPDATE users SET role = 'guest' WHERE id = v_uid AND role = 'owner';

  RETURN jsonb_build_object(
    'property_id', v_link.property_id,
    'db_id',       v_link.db_id
  );
END;
$$;
REVOKE ALL ON FUNCTION claim_guest_link(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_guest_link(TEXT) TO authenticated;

-- ── Backfill для вже прийнятих лінків ───────────────────────────────────────
-- Без нього власник побачив би імена лише в НОВИХ гостей, а наявні лишились би
-- безіменними назавжди — тобто фіча виглядала б зламаною саме там, де в неї
-- найбільше даних.
UPDATE guest_links g
SET guest_name = NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
FROM users u
WHERE g.guest_user_id = u.id
  AND g.guest_name IS NULL;

NOTIFY pgrst, 'reload schema';

-- ── Verification ────────────────────────────────────────────────────────────
-- Має показати named = скільки прийнятих лінків уже мають імʼя.
SELECT count(*) FILTER (WHERE guest_user_id IS NOT NULL)               AS claimed,
       count(*) FILTER (WHERE guest_user_id IS NOT NULL
                          AND guest_name IS NOT NULL)                  AS named
FROM guest_links;

-- ─────────────────────────────────────────────────────────────────────────
-- 049_drop_idor_get_shared_collection.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 049: прибрати get_shared_collection — IDOR через пряме посилання на обʼєкт
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ЩО БУЛО. `get_shared_collection(p_collection_id UUID)` (018, уточнена 026) —
-- SECURITY DEFINER, виданий `anon` І `authenticated`, приймав UUID підбірки і
-- віддавав її вміст, перевіряючи ЛИШЕ `is_draft = false` і термін дії.
-- Жодного share-токена в сигнатурі не було взагалі.
--
-- ЧОМУ ЦЕ IDOR, А НЕ «просто нездогадний ідентифікатор». Авторизація стояла в
-- ІНШІЙ функції: `lookup_shared_collection(p_token)` перевіряла токен і
-- віддавала id, а дані повертала ця. Тобто перевірку можна було просто
-- ОБМИНУТИ, викликавши другу функцію напряму з публічним anon-ключем, який за
-- задумом лежить у клієнтському бандлі.
--
-- НАЙГІРШИЙ НАСЛІДОК — не витік сам по собі, а ЗЛАМАНА ОБІЦЯНКА. Ротація
-- посилання (`manage_share … 'rotate'`) міняє лише `share_token` і не чіпає
-- термін дії, а ця функція токен ігнорувала. Тож після «Оновити посилання»
-- кожен, хто колись відкривав підбірку і зберіг її UUID, читав її далі — хоч
-- підтвердження в застосунку дослівно каже: «Старе посилання та QR-код
-- перестануть працювати. Усі, з ким ви ділились, втратять доступ».
--
-- ЧИМ ЗАМІНЕНО. Нічим новим: правильний двійник уже існував — токенний
-- `get_public_collection_preview(p_token TEXT)` (040), яким і так користується
-- публічна /v. `SharedCollectionScreen` переведений на нього; токен носить
-- `screenParams.colToken` від самого deep link.
--
-- ПОРЯДОК ДЕПЛОЮ. Спершу фронт, потім ця міграція — інакше вікно між ними
-- лишить екран без робочого RPC. Фронт від 049 не залежить.

DROP FUNCTION IF EXISTS get_shared_collection(UUID);

NOTIFY pgrst, 'reload schema';

-- ── Верифікація ─────────────────────────────────────────────────────────────
-- Має показати 0. Якщо 1 — функція десь перестворена, і діра відкрита знову.
SELECT count(*) AS must_be_zero
FROM pg_proc
WHERE proname = 'get_shared_collection'
  AND pronamespace = 'public'::regnamespace;

-- ─────────────────────────────────────────────────────────────────────────
-- 050_guest_preview_owner_check.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 050: доробки після наскрізного код-рев'ю
--   1. get_guest_property_preview — третій, пропущений 046 споживач
--   2. get_public_collection_preview — база розрахунку площі
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 1. Залишкова експозиція гостьових лінків ────────────────────────────────
--
-- 046 закрила діру З ДВОХ БОКІВ — і запис (політика `guest_links`), і читання
-- (`is_guest_of_property`), бо «вже посаджені рядки продовжували б діяти».
-- Але споживачів читання виявилось ТРИ: `get_guest_property_preview` —
-- SECURITY DEFINER, виданий `anon` — джойнить guest_links → databases БЕЗ
-- перевірки, що лінк створив саме власник цілі.
--
-- Наслідок для рядка, посадженого ДО 046 (`owner_id` зловмисника, `db_id`
-- жертви): анонімний виклик із токеном і досі віддає повний список обʼєктів
-- жертви. Нові такі рядки вже неможливі (`WITH CHECK` з 046), тож це саме
-- залишок, а не відкритий вектор.
CREATE OR REPLACE FUNCTION get_guest_property_preview(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_link   RECORD;
  v_result JSONB;
BEGIN
  SELECT id, property_id, db_id, status, owner_id INTO v_link
    FROM guest_links WHERE invite_token = p_token;

  IF NOT FOUND OR v_link.status = 'revoked' THEN
    RETURN NULL;
  END IF;

  IF v_link.property_id IS NOT NULL THEN
    SELECT jsonb_build_object(
      'type',        'property',
      'status',      v_link.status,
      'owner_first', u.first_name,
      'property', jsonb_build_object(
        'id',          p.id,
        'name',        p.name,
        'status',      p.status,
        'floor',       p.floor,
        'area_useful', p.area_useful,
        'area_total',  p.area_total,
        'description', p.description,
        'db_name',     d.name,
        'db_type',     d.type,
        'db_color',    d.color
      )
    )
    INTO v_result
    FROM guest_links gl
    JOIN properties p ON p.id = gl.property_id
    JOIN databases  d ON d.id = p.db_id
    JOIN users      u ON u.id = gl.owner_id
    WHERE gl.invite_token = p_token
      -- ЄДИНА ЗМІНА ПРОТИ 027, і вона вся тут: ціль лінка мусить належати
      -- тому, хто лінк видав. Рядок із ЧУЖИМ property_id, посаджений до 046,
      -- інакше й далі віддавав би вміст жертви анонімному викликачу.
      AND p.owner_id = gl.owner_id;
  ELSE
    SELECT jsonb_build_object(
      'type',        'database',
      'status',      gl.status,
      'owner_first', u.first_name,
      'database', jsonb_build_object(
        'id',    d.id,
        'name',  d.name,
        'type',  d.type,
        'color', d.color
      ),
      'properties', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
          'id',          p.id,
          'name',        p.name,
          'status',      p.status,
          'floor',       p.floor,
          'area_useful', p.area_useful,
          'area_total',  p.area_total
        ) ORDER BY p.sort_order, p.created_at)
        FROM properties p
        WHERE p.db_id = d.id
      ), '[]'::jsonb)
    )
    INTO v_result
    FROM guest_links gl
    JOIN databases d ON d.id = gl.db_id
    JOIN users     u ON u.id = gl.owner_id
    WHERE gl.invite_token = p_token
      AND d.owner_id = gl.owner_id;   -- та сама перевірка для лінка на базу
  END IF;

  RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION get_guest_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_guest_property_preview(TEXT) TO anon, authenticated, service_role;

-- ── 2. Аудит рядків, посаджених ДО 046 ──────────────────────────────────────
-- Має показати 0. Ненульовий результат = у базі лежать лінки, чия ціль НЕ
-- належить їхньому власнику; після цієї міграції вони мертві, але їх варто
-- побачити й видалити вручну.
SELECT count(*) AS mismatched_guest_links
FROM guest_links gl
LEFT JOIN databases  d  ON d.id  = gl.db_id
LEFT JOIN properties p  ON p.id  = gl.property_id
LEFT JOIN databases  pd ON pd.id = p.db_id
WHERE gl.owner_id <> COALESCE(d.owner_id, pd.owner_id);

-- ── 3. База розрахунку площі в публічній підбірці ───────────────────────────
--
-- `get_public_collection_preview` не віддавала `area_basis`, тож клієнт
-- фолбечився на розрахункову площу. Для обʼєкта з базою «корисна» (50 м²
-- корисної проти 100 розрахункової) картка в застосунку каже $900, а спільна
-- підбірка — $1 800. Той самий клас, який для валюти закрила 040.
--
-- Тип результату міняється, тож потрібен DROP: `CREATE OR REPLACE` не змінює
-- сигнатуру наявної функції (42P13) — та сама пастка, що в 042 і 044.
DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);

CREATE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT,
  realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful FLOAT, property_area_total FLOAT, property_area_basis TEXT,
  property_rent_type TEXT, property_rent_rate FLOAT, property_sale_price FLOAT,
  property_description TEXT, owner_currency TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username, r.phone,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  LEFT JOIN properties p ON p.id = cp.property_id
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$$;
REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 051_delete_account_storage.sql
-- ─────────────────────────────────────────────────────────────────────────
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
  BEGIN
    -- Скільки обʼєктів ЛЕЖИТЬ У STORAGE — рахуємо там же, а НЕ по
    -- `property_photos`. Різниця принципова: рядок БД і файл у бакеті законно
    -- розходяться (файл прибрали раніше, аплоуд не дописав рядок, осиротілий
    -- залишок давнього бага). Порівняння з `property_photos` означало б, що
    -- ОДНЕ таке розходження робить акаунт НЕВИДАЛЬНИМ НАЗАВЖДИ — відмова в
    -- праві на стирання, гірша за ту, яку перевірка мала спіймати.
    --
    -- Питання, на яке ми відповідаємо, інше: чи DELETE зачепив усе, що БАЧИВ.
    -- Саме це й ловить відмову RLS, заради якої перевірка існує.
    -- ПЕРЕДУМОВА: чи ми взагалі БАЧИМО storage. Без неї перевірка нижче
    -- безсила проти ПОВНОЇ невидимості: `count` і `DELETE` фільтруються
    -- ОДНАКОВО, тож якщо RLS ховає обʼєкти, обидва дають 0, різниця нульова —
    -- і функція звітує `deleted = true` при цілих файлах. Тобто вона ловила
    -- лише ЧАСТКОВУ відмову, хоч коментар обіцяв ловити відмову взагалі.
    --
    -- Довести, що бачимо все, можна лише одним: власник функції обходить RLS.
    -- У Supabase функція належить `postgres`, у якого є BYPASSRLS, тож у
    -- нормальній конфігурації це просто проходить. Якщо ж ні — ми НЕ МОЖЕМО
    -- відрізнити «файлів немає» від «файлів не видно», і єдина безпечна
    -- відповідь — відмовитись, лишивши акаунт живим: стан «є акаунт і є
    -- файли» оборотний, «немає акаунта, є файли» — ні.
    IF NOT COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), FALSE)
       AND COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid = 'storage.objects'::regclass), FALSE)
    THEN
      RETURN QUERY SELECT FALSE, 'storage_not_verifiable'::TEXT; RETURN;
    END IF;

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
  EXCEPTION WHEN undefined_table THEN
    -- Схеми storage немає взагалі (свіжа БД) — чекати нема чого, тож
    -- зрівнюємо лічильники, щоб перевірка нижче пропустила.
    v_want_photos := 0; v_got_photos := 0;
    v_want_files  := 0; v_got_files  := 0;
  END;

  -- ЧАСТКОВА відмова: щось видалилось, щось ні. Повну невидимість цей
  -- порівняльний тест не бачить у принципі (обидва лічильники фільтруються
  -- однаково) — її закриває передумова `rolbypassrls` вище. Разом вони дають
  -- те, що обіцяє коментар; поодинці — ні.
  --
  -- МЕЖА, яку треба назвати чесно: `DELETE FROM storage.objects` прибирає
  -- РЯДКИ МЕТАДАНИХ. Саме вони роблять обʼєкт досяжним через Storage API і
  -- публічний URL, тож після цього файл не віддається. Чи звільняє Supabase
  -- сам блоб у S3 — поза досяжністю цієї функції й перевірити звідси
  -- неможливо. Формулювання «файли знищено» тут було б сильнішим за доказ.
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

-- ─────────────────────────────────────────────────────────────────────────
-- 052_reminders_fix_and_lockdown.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 052 — нагадування про платежі: функція, ЯКА НІКОЛИ НЕ ПОВЕРТАЛА ЖОДНОГО
--       РЯДКА, плюс два ACL-недогляди на тих самих функціях
-- ============================================================================
-- Знайдено ВИКОНАННЯМ міграцій на справжньому Postgres (scripts/verify-
-- migrations.sh), не читанням: усі три дефекти невидимі для будь-якого
-- джерельного гарда.
--
-- ── 1. ЗЛАМАНИЙ ТИП РЕЗУЛЬТАТУ (обидві функції, з моменту створення) ────────
-- `014_security_hardening.sql` звузив `properties.name`/`tenant_name` до
-- VARCHAR(200). `021_rent_payments.sql` (пізніша!) оголосила
-- `RETURNS TABLE(... property_name TEXT ...)` і повертає `p.name` без касту.
-- plpgsql звіряє тип КОЛОНКИ, а не тільки родину типів, тож кожен виклик
-- падає з
--     structure of query does not match function result type
--     Returned type character varying(200) does not match expected type text
-- Наслідок: `send-reminders` не міг створити ЖОДНОГО рядка `notifications`
-- за весь час існування — а `notifications` наповнює ВИКЛЮЧНО ця функція.
-- Тобто причин, чому сповіщень у проді не було, було ДВІ, а не одна:
-- відсутній планувальник (полагоджено раніше) і ця помилка.
--
-- ── 2. КЛАМП ДНЯ МІСЯЦЯ — ЗАХИСТ, А НЕ ФІКС (гіпотезу СПРОСТОВАНО) ─────────
-- `get_due_reminders_today` кладе сирий `rp.due_day` у `make_date`, тобто
-- `make_date(2026,4,31)` дав би `date field value out of range` і вбив би
-- ВЕСЬ прогін, а не один рядок. Виглядає як третій дефект — і саме так це
-- тут спершу й було записано. Перевірка на живій БД його НЕ підтвердила:
-- `rent_payments_due_day_check` тримає `due_day BETWEEN 1 AND 28`, тож
-- значення, яке переповнює будь-який місяць, у таблицю не потрапляє в
-- принципі. Кламп (той самий, що вже мала `get_due_guest_reminders`)
-- лишається як симетрія між двома функціями, а не як виправлення живої
-- помилки — щоб наступний, хто помітить розбіжність, не шукав дефекту там,
-- де його немає.
--
-- ── 3. PUBLIC МАВ EXECUTE на обох service-role функціях ────────────────────
-- `GRANT ... TO service_role` НЕ знімає дефолтний грант PUBLIC, який Postgres
-- вішає на кожну функцію при створенні — він лише матеріалізує його в ACL
-- (`{=X/postgres,postgres=X/postgres,service_role=X/postgres}`, де порожній
-- грантополучач і є PUBLIC). Решта чутливих функцій проєкту мають явний
-- `REVOKE ALL ... FROM PUBLIC` (див. 013/014/020/023/026/027); ці дві його
-- не отримали.
--   • `get_due_reminders_today()` — SECURITY DEFINER, повертає `owner_id`,
--     `tg_id`, назву обʼєкта та ІМʼЯ ОРЕНДАРЯ по ВСІХ власниках одразу, без
--     жодного параметра. З anon-ключем, що за задумом лежить у клієнтському
--     бандлі, це наскрізний дамп PII без автентифікації.
--   • `mark_overdue_payments()` — глобальний UPDATE по `rent_payment_records`
--     усіх власників, теж із anon.
--
-- ПОРЯДОК ФІКСІВ ТУТ НЕ ДОВІЛЬНИЙ: поки тип результату зламаний, витік
-- (3) не експлуатується — виклик падає раніше, ніж віддасть рядок. Тобто
-- виправити ЛИШЕ тип означало б УВІМКНУТИ дамп. Обидві частини мусять
-- їхати одним файлом.
-- ============================================================================

CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           LEAST(
             rp.due_day,
             EXTRACT(DAY FROM (
               DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
               + INTERVAL '1 month' - INTERVAL '1 day'
             ))::INT
           )
         )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;

CREATE OR REPLACE FUNCTION get_due_guest_reminders()
RETURNS TABLE (
  guest_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT DISTINCT ON (u.id, rp.property_id)
    u.id, u.tg_id, rp.property_id,
    p.name::TEXT,
    rp.due_day::INT,
    make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN guest_links gl ON (gl.property_id = rp.property_id OR gl.db_id = p.db_id)
                      AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = u.id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    )
  ORDER BY u.id, rp.property_id;
END;
$$;

-- Дефолтний грант PUBLIC знімається ЯВНО — `GRANT ... TO service_role` його
-- не чіпає.
REVOKE ALL ON FUNCTION get_due_reminders_today()  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_due_guest_reminders()  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;

-- `mark_overdue_payments` створює 024, і в проді її може НЕ БУТИ: накат там
-- історично робився вручну, з прогалинами. `REVOKE`/`GRANT` на неіснуючу
-- функцію — це помилка 42883, яка валить УВЕСЬ файл накату (перевірено на
-- живій базі власника). Замикати ACL тут — річ корисна, але не обовʼязкова:
-- якщо функції немає, то й замикати нічого. Тому умовно.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'mark_overdue_payments'
  ) THEN
    EXECUTE 'REVOKE ALL ON FUNCTION mark_overdue_payments() FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION mark_overdue_payments() TO service_role';
  ELSE
    RAISE NOTICE '052: mark_overdue_payments() немає (міграція 024 не застосована) — ACL пропущено';
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 053_owner_policies_target_ownership.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 053 — КРИТИЧНО: політика власника перевіряла ЛИШЕ `owner_id = я`,
--       але не те, що ЦІЛЬ (база / обʼєкт) належить мені
-- ============================================================================
-- Той самий клас, що вже виправляла 046 для `guest_links`, і рівно те, що
-- Security rules описують правилом 11 — але на ЦЕНТРАЛЬНІЙ таблиці застосунку.
-- Знайдено ВИКОНАННЯМ політик (`scripts/verify-rls.sql`): RLS у цьому проєкті
-- досі не виконувалась жодного разу — e2e ганяються проти герметичного мока,
-- де політик не існує, а юніт-гарди читають SQL як текст.
--
-- Асиметрія видно неозброєним оком, щойно політики покласти поруч:
--   props_editor_all (041): db_id IN get_editor_db_ids(...) AND owner_id = <власник бази>
--   props_owner_all  (009): owner_id = current_app_user_id()          ← і все
-- Тобто редакторський бік, написаний пізніше, робить перевірку правильно, а
-- власницький — ні.
--
-- ── ЩО ЦЕ ДАВАЛО (перевірено, не припущено) ────────────────────────────────
-- Будь-який автентифікований власник вставляє СВІЙ рядок у ЧУЖУ базу:
--   INSERT INTO properties (db_id, owner_id, …) VALUES (<чужа база>, <я>, …)
-- `WITH CHECK` проходить, бо owner_id справді мій. Далі:
--   • рядок ВИДНО на публічній /v сторінці жертви (`get_public_db_preview` —
--     SECURITY DEFINER, вибирає по db_id, тобто RLS її не обмежує);
--   • рядок ВИДНО кожному підписаному рієлтору жертви — як обʼєкт власника;
--   • жертва його НЕ БАЧИТЬ (її політика фільтрує по owner_id), тобто не може
--     ні знайти, ні видалити з застосунку.
-- `db_id` жертви для цього не треба вгадувати: його віддає
-- `get_public_db_preview(token)` — тобто досить будь-якого шер-лінка, а це і
-- є призначення фічі.
--
-- ── ТОЙ САМИЙ КЛАС НА ПЛАТЕЖАХ, І ВІН ЛЕДЬ НЕ СТАВ ЖИВИМ ───────────────────
-- `rent_payments`/`rent_payment_records` мають те саме `owner_id = я` без
-- перевірки, що обʼєкт мій. Наслідок конкретний: `get_due_reminders_today()`
-- джойнить `rent_payments → properties → users` по `rp.owner_id`, тож
-- підкинутий на ЧУЖИЙ обʼєкт розклад щомісяця надсилає АТАКУВАЛЬНИКУ в
-- Telegram назву обʼєкта жертви та ІМʼЯ ЇЇ ОРЕНДАРЯ. Перевірено на живій БД:
-- «отримає: Аліса | Офіс Богдана | ТАЄМНИЙ ОРЕНДАР БОГДАНА».
--
-- **Це вмикається рівно тоді, коли 052 полагодить нагадування** — доти
-- функція падала на типі результату і не віддавала нічого. Тобто 052 без 053
-- гірша за жодну з них: вона активує канал витоку. Тому 053 — обовʼязкова
-- пара до 052.
--
-- ── ГІПОТЕЗА, ЯКУ Я СПЕРШУ «СПРОСТУВАВ» ХИБНО (див. 056) ───────────────────
-- `collection_properties` має ту саму форму, і тут спершу було записано, що
-- публічної поверхні в цього немає. **Це було НЕПРАВДОЮ через хибний замір:**
-- тестова підбірка створювалась без `is_draft`, а дефолт цієї колонки TRUE,
-- тоді як превʼю фільтрує `is_draft = false`. Тобто нуль рядків пояснювався
-- ЧЕРНЕТКОЮ. На опублікованій підбірці гіпотеза підтвердилась — виправлено
-- міграцією 056.
-- ============================================================================

-- ── 1. ЗАПИС ───────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS props_owner_all ON properties;
CREATE POLICY props_owner_all ON properties FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
  );

DROP POLICY IF EXISTS "owner manages rent_payments" ON rent_payments;
CREATE POLICY "owner manages rent_payments" ON rent_payments FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  );

DROP POLICY IF EXISTS "owner manages payment_records" ON rent_payment_records;
CREATE POLICY "owner manages payment_records" ON rent_payment_records FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  );

-- ── 2. ВЖЕ ПОСАДЖЕНІ РЯДКИ ─────────────────────────────────────────────────
-- Урок 046 дослівно: правити треба ОБИДВА боки, інакше рядки, вставлені до
-- фікса, продовжують діяти. Тут вони ще й НЕВИДИМІ для жертви, тож самотужки
-- вона їх не прибере.
--
-- Ремонт — ПЕРЕПРИВЛАСНЕННЯ, а не видалення: `owner_id` стає власником бази
-- (для платежів — власником обʼєкта). Так рядок повертається під контроль
-- того, кому належить ціль, і той сам вирішує, лишити чи прибрати. Видалення
-- тут було б необоротним, а серед розбіжностей можуть бути й легасі-рядки
-- від `moveToDatabase` з ненадійним `?? user.id` (описано в CLAUDE.md).
DO $$
DECLARE n_props INT; n_pay INT; n_rec INT;
BEGIN
  UPDATE properties p SET owner_id = d.owner_id
  FROM databases d WHERE d.id = p.db_id AND p.owner_id <> d.owner_id;
  GET DIAGNOSTICS n_props = ROW_COUNT;

  UPDATE rent_payments rp SET owner_id = p.owner_id
  FROM properties p WHERE p.id = rp.property_id AND rp.owner_id <> p.owner_id;
  GET DIAGNOSTICS n_pay = ROW_COUNT;

  UPDATE rent_payment_records rr SET owner_id = p.owner_id
  FROM properties p WHERE p.id = rr.property_id AND rr.owner_id <> p.owner_id;
  GET DIAGNOSTICS n_rec = ROW_COUNT;

  RAISE NOTICE '053: переприсвоєно власника — обʼєктів %, розкладів %, платежів %',
    n_props, n_pay, n_rec;
END $$;

-- ── 3. ГЛИБИННИЙ ЗАХИСТ У САМІЙ ФУНКЦІЇ НАГАДУВАНЬ ─────────────────────────
-- Політика тепер не пропустить нового підкидня, а ремонт вище прибрав старих.
-- Але канал витоку варто закрити і з боку споживача: нагадування має сенс
-- ЛИШЕ коли розклад і обʼєкт належать одній особі. Один рядок, і жодна
-- майбутня діра в записі вже не перетворюється на розсилку чужих даних.
CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           LEAST(
             rp.due_day,
             EXTRACT(DAY FROM (
               DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
               + INTERVAL '1 month' - INTERVAL '1 day'
             ))::INT
           )
         )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;
REVOKE ALL ON FUNCTION get_due_reminders_today() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 054_storage_single_identity.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 054 — storage-політики: ОДНЕ джерело особи замість двох
-- ============================================================================
-- Знайдено ВИКОНАННЯМ політик (`scripts/verify-rls.sql`), і знайдено як
-- ВАКУУМНИЙ ТЕСТ: перевірка «Аліса не зітре фото Богдана» проходила — але
-- Аліса не могла зітерти й ВЛАСНЕ фото. Тобто політика відмовляла всім, і
-- «доказ» не доводив нічого. Антивакуумна пара (те саме, але зі своїм
-- файлом) це й проявила.
--
-- ── ЧОМУ ТАК ВИХОДИЛО ──────────────────────────────────────────────────────
-- `storage_photos_delete` (038) перевіряє власність через
-- `get_app_user_id_from_auth_uid()` — тобто по `sub`-клейму. Але робить це
-- ПІДЗАПИТОМ `FROM properties`, а на `properties` діє RLS, яка резолвить
-- особу через `current_app_user_id()` — тобто по EMAIL-клейму. Отже кожен
-- запис у storage мовчки вимагає ОБИДВА клейми одночасно.
--
-- Заміряно на живій БД:
--   обидва клейми → DELETE 1
--   лише `sub`    → DELETE 0   (мовчки, без помилки)
--
-- Це рівно та крихкість, через яку 030 і завела `*_from_auth_uid`-варіанти:
-- `current_app_user_id()` у storage-контексті ненадійний. 038 замінила
-- ЗОВНІШНІЙ предикат і лишила внутрішній підзапит під тією ж функцією, а
-- `pfiles_storage_insert`/`delete` узагалі лишились на email-клеймі напряму.
--
-- **Це НЕ звіт про живий баг:** чи присутній email-клейм у storage-контексті
-- проду, з цього середовища перевірити неможливо (мережі до Supabase немає).
-- Якщо присутній — усе працює, і 054 просто прибирає непотрібну залежність;
-- якщо ні — 054 лагодить видалення фото й документів. У будь-якому разі
-- політика, що залежить від ДВОХ незалежних джерел особи, не має на це
-- причин: обидва описують ТУ САМУ людину.
--
-- ── ЯК ЛІКУЄТЬСЯ ───────────────────────────────────────────────────────────
-- Підзапит іде через SECURITY DEFINER хелпери (`get_owner_property_ids`,
-- `get_editor_property_ids`, `get_realtor_db_ids`), які обходять RLS на
-- `properties`. Рівно так уже зроблено в політиках `public.property_photos`
-- (`photos_owner_all`) — тобто це не новий прийом, а вирівнювання storage по
-- вже наявному.
--
-- СЕМАНТИКА НЕ МІНЯЄТЬСЯ: ті самі бакети, ті самі ролі, ті самі права.
-- Міняється лише те, ЧИМ політика впізнає людину.
-- ============================================================================

-- ── photos: власник ────────────────────────────────────────────────────────
DROP POLICY IF EXISTS storage_photos_insert ON storage.objects;
CREATE POLICY storage_photos_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS storage_photos_delete ON storage.objects;
CREATE POLICY storage_photos_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── photos: редактор команди (041) ─────────────────────────────────────────
DROP POLICY IF EXISTS storage_photos_editor_insert ON storage.objects;
CREATE POLICY storage_photos_editor_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS storage_photos_editor_delete ON storage.objects;
CREATE POLICY storage_photos_editor_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── property-files ─────────────────────────────────────────────────────────
-- Ці дві були найгіршим випадком: `current_app_user_id()` НАПРЯМУ, без
-- жодного auth_uid-варіанта.
DROP POLICY IF EXISTS pfiles_storage_insert ON storage.objects;
CREATE POLICY pfiles_storage_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'property-files'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS pfiles_storage_delete ON storage.objects;
CREATE POLICY pfiles_storage_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'property-files'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- Читання: власник АБО підписаний рієлтор — той самий набір, що й був
-- (026 + 038), лише без підзапитів під RLS.
DROP POLICY IF EXISTS pfiles_storage_select ON storage.objects;
CREATE POLICY pfiles_storage_select ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'property-files'
    AND (
      split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_realtor_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
      )
    )
  );

-- ─────────────────────────────────────────────────────────────────────────
-- 055_fix_subscribe_ambiguous_db_id.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 055 — КРИТИЧНО: підписка на спільну базу падала НА КОЖНОМУ УСПІШНОМУ виклику
-- ============================================================================
-- Знайдено ВИКОНАННЯМ (`scripts/verify-rls.sql`), і знайдено лише тому, що до
-- негативної перевірки («протермінований токен не пускає») додалась ПОЗИТИВНА
-- («живий — пускає»). Негативна проходила й на зламаному коді: гілка
-- `not_found` виходить із функції РАНІШЕ, ніж доходить до дефектного рядка.
--
-- ── ДЕФЕКТ ─────────────────────────────────────────────────────────────────
-- `subscribe_to_shared_db` оголошена як
--     RETURNS TABLE (db_id UUID, db_name TEXT, error TEXT)
-- тобто plpgsql заводить ЗМІННУ `db_id`. А в тілі стоїть
--     INSERT INTO realtor_subscriptions (realtor_id, db_id)
--     VALUES (v_uid, v_db.id)
--     ON CONFLICT (realtor_id, db_id) DO NOTHING;
-- Список колонок INSERT-а підстановці НЕ підлягає, а от ЦІЛЬ `ON CONFLICT`
-- парситься як вираз — і `db_id` там збігається і з колонкою, і зі змінною:
--     ERROR: column reference "db_id" is ambiguous
--
-- Тобто **кожна успішна підписка рієлтора на спільну базу кидала виняток**, а
-- клієнт показував «Помилка запиту». Це дослівно збігається зі скаргою
-- власника, записаною в Pending manual actions §0 («розділ поділитися базою не
-- працює, підключення бази падає з Помилка запиту») — там причину списали на
-- невідсутні 036/037. Міграції могли бути застосовані: причина в них самих,
-- і обидві (036 і 037) несуть той самий рядок.
--
-- ── ЧОМУ ЦЬОГО НЕ БАЧИВ НІХТО ──────────────────────────────────────────────
--  • e2e мокають RPC через `page.route` — тіла функції там не існує;
--  • `verify_release.sql` перевіряв лише ІСНУВАННЯ функції;
--  • джерельні гарди звіряють підрядки, а тут синтаксис валідний — помилка
--    виникає при ВИКОНАННІ, і лише на успішній гілці.
--
-- ── ФІКС ───────────────────────────────────────────────────────────────────
-- Ціль конфлікту вказується ІМЕНЕМ ОБМЕЖЕННЯ, а не переліком колонок — тоді
-- підставляти нічого й неоднозначності не виникає в принципі. Перейменування
-- OUT-параметра було б ламкою зміною: клієнт читає саме `db_id`.
-- ============================================================================

CREATE OR REPLACE FUNCTION subscribe_to_shared_db(p_token TEXT)
RETURNS TABLE (db_id UUID, db_name TEXT, error TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
-- РОЗВʼЯЗУЄ неоднозначність в КОРЕНІ: у межах цієї функції ідентифікатор, що
-- збігається і з колонкою, і зі змінною, читається як КОЛОНКА. Саме цього
-- бракувало `ON CONFLICT (realtor_id, db_id)`.
--
-- Альтернатива — `ON CONFLICT ON CONSTRAINT <імʼя>` — була в першій редакції і
-- ВІДКИНУТА: вона прив'язує міграцію до автозгенерованого імені з каталогу.
-- Якщо його колись не виявиться (інша історія створення таблиці), запит упаде
-- з `constraint … does not exist` — на ПАРСІ, тобто рівно тим самим класом
-- відмови «лише на успішній гілці», який ця міграція й лікує. Прагма імені не
-- потребує.
--
-- Перевірено, що вона не зачіпає решту тіла: єдиний ідентифікатор, який тут
-- колідує, — `db_id`, і всюди інде він уже кваліфікований (`v_db.id`, `d.id`,
-- `rs.db_id`), а OUT-параметри повертаються через явний `RETURN QUERY SELECT`.
#variable_conflict use_column
DECLARE
  v_uid UUID;
  v_db  RECORD;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_authenticated'::TEXT; RETURN;
  END IF;

  SELECT d.id, d.owner_id, d.name INTO v_db FROM databases d
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  LIMIT 1;

  IF v_db.id IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_found'::TEXT; RETURN;
  END IF;
  IF v_db.owner_id = v_uid THEN
    RETURN QUERY SELECT v_db.id, v_db.name::TEXT, 'own_db'::TEXT; RETURN;
  END IF;

  INSERT INTO realtor_subscriptions (realtor_id, db_id)
  VALUES (v_uid, v_db.id)
  ON CONFLICT (realtor_id, db_id) DO NOTHING;

  -- Той, кому передали базу, діє як рієлтор. Користувач із дефолтною роллю
  -- 'owner', який жодної власної бази не створював, — саме такий випадок;
  -- нормалізуємо, щоб домашній екран збігався з роллю. Усталений власник
  -- (має >= 1 базу) лишається 'owner'. Тригер prevent_privilege_escalation
  -- дозволяє owner->realtor (блокує лише зворотне самопідвищення).
  UPDATE users SET role = 'realtor'
  WHERE id = v_uid
    AND role = 'owner'
    AND NOT EXISTS (SELECT 1 FROM databases d2 WHERE d2.owner_id = v_uid);

  RETURN QUERY SELECT v_db.id, v_db.name::TEXT, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION subscribe_to_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION subscribe_to_shared_db(TEXT) TO authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 056_collection_target_access.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 056 — рієлтор публікував ЧУЖИЙ обʼєкт у власній підбірці
-- ============================================================================
-- ЦЕ ВИПРАВЛЕННЯ МОЄЇ Ж ПОМИЛКОВОЇ «СПРОСТОВАНОЇ ГІПОТЕЗИ».
-- У 053 записано, що цей клас на `collection_properties` перевірено і
-- публічної поверхні він не має. Замір був НЕВАЛІДНИЙ: тестова підбірка
-- створювалась без `is_draft`, а дефолт цієї колонки — TRUE, тоді як
-- `get_public_collection_preview` має `AND c.is_draft = false`. Тобто нуль
-- рядків пояснювався ЧЕРНЕТКОЮ, а не фільтрацією чужого обʼєкта.
--
-- Повторний замір на ОПУБЛІКОВАНІЙ підбірці гіпотезу ПІДТВЕРДИВ:
--   рядків у підбірці: 1
--   ПУБЛІЧНА підбірка Клима показує: ТАЄМНИЙ ОБʼЄКТ ЖЕРТВИ
--
-- ── ЩО ЦЕ ДАЄ ──────────────────────────────────────────────────────────────
-- `col_props_realtor_all` перевіряє лише «підбірка моя?», не питаючи, чи є в
-- мене доступ до ОБʼЄКТА. Тож будь-який рієлтор вставляє чужий `property_id`
-- у свою підбірку, публікує її — і `get_public_collection_preview`
-- (SECURITY DEFINER, тобто повз RLS) віддає назву, площу, ціну, опис і ФОТО
-- чужого обʼєкта анонімам, ще й поруч із контактами ЦЬОГО рієлтора, тобто з
-- хибним авторством.
--
-- UUID вгадувати не треба: `get_public_db_preview(token)` віддає `property_id`
-- кожного обʼєкта бази. Тобто досить одного шер-лінка жертви.
--
-- Той самий клас, що 046 (guest_links) і 053 (properties): політика перевіряє
-- ВЛАСНИКА рядка, але не те, що ЦІЛЬ доступна. Виправляємо ОБИДВА боки —
-- інакше вже посаджені рядки продовжують світитись (урок 046).
--
-- КОНТРАКТ ФУНКЦІЇ НЕ МІНЯЄТЬСЯ: ті самі 24 колонки в тому ж порядку —
-- додається рівно один предикат у JOIN. Це прямий урок 050, де перейменовані
-- ключі зламали б гостьовий екран.
-- ============================================================================

-- ── 1. ЗАПИС: ціль мусить бути доступна рієлтору ───────────────────────────
DROP POLICY IF EXISTS col_props_realtor_all ON collection_properties;
CREATE POLICY col_props_realtor_all ON collection_properties FOR ALL
  USING (collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id())))
  WITH CHECK (
    collection_id IN (SELECT get_realtor_collection_ids(current_app_user_id()))
    AND (
      -- обʼєкт із бази, на яку рієлтор підписаний…
      property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
      -- …або власний обʼєкт (акаунт може бути і власником, і рієлтором)
      OR property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
    )
  );

-- ── 2. ЧИТАННЯ: уже посаджені рядки перестають світитись ───────────────────
CREATE OR REPLACE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE (
  collection_id UUID, collection_name TEXT, share_expires_at TIMESTAMPTZ,
  realtor_first_name TEXT, realtor_last_name TEXT, realtor_tg_username TEXT, realtor_phone TEXT,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful DOUBLE PRECISION, property_area_total DOUBLE PRECISION,
  property_area_basis TEXT, property_rent_type TEXT, property_rent_rate DOUBLE PRECISION,
  property_sale_price DOUBLE PRECISION, property_description TEXT, owner_currency TEXT,
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT, first_photo TEXT
)
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username, r.phone,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  -- 056: показуємо обʼєкт, ЛИШЕ якщо рієлтор досі має до нього доступ —
  -- власний, або через активну підписку на його базу. Це друга половина
  -- фікса: без неї рядки, посаджені до 056, світились би далі.
  LEFT JOIN properties p ON p.id = cp.property_id
    AND (
      p.owner_id = c.realtor_id
      OR EXISTS (
        SELECT 1 FROM realtor_subscriptions rs
        WHERE rs.realtor_id = c.realtor_id AND rs.db_id = p.db_id
      )
    )
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$$;

REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 057_helper_identity_guard.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 057 — сім SECURITY DEFINER хелперів приймали ЧУЖИЙ UUID від будь-кого
-- ============================================================================
-- Знайдено незалежним рев'ю; підтверджено виконанням.
--
-- `get_owner_db_ids(p_uid)`, `get_owner_property_ids`, `get_realtor_db_ids`,
-- `get_realtor_property_ids`, `get_editor_db_ids`, `get_editor_property_ids`,
-- `get_realtor_collection_ids` — усі SECURITY DEFINER (тобто повз RLS), усі
-- беруть UUID КОРИСТУВАЧА параметром і жодна не звіряла його з тим, ХТО
-- дзвонить. EXECUTE вони мають від дефолтного гранта PUBLIC, тож доступні і
-- `anon`, і `authenticated`.
--
-- Це прямо порушує правило 2 чеклісту §5 Audit playbook: «UUID НЕ секрет,
-- функція мусить сама звірити `current_app_user_id()`».
--
-- ── ЧОМУ «UUID ЖЕРТВИ НІХТО НЕ ВІДДАЄ» — ЦЕ БУЛА НЕПРАВДА ──────────────────
-- Саме таким рядком ці функції були внесені в allowlist у
-- `scripts/verify-behaviour.sql`. Твердження хибне:
--   • `GuestHomeScreen` читає `guest_links.owner_id` — тобто ГІСТЬ, найменш
--     довірений принципал, уже тримає `users.id` власника;
--   • `lookup_shared_db(p_token)` віддає `owner_id` і має грант
--     `authenticated` — досить будь-якого `db_`-лінка.
-- Перевірено: гість, запрошений на ОДИН обʼєкт, перелічує всю базу власника.
--
-- Витік — метадані (UUID і кількості), не назви й не контакти. Але це стояча
-- діра з гардом, який її не бачить, і з написаною неправдою замість причини.
--
-- ── ФІКС ───────────────────────────────────────────────────────────────────
-- Функція віддає щось ЛИШЕ якщо питають про себе. Приймаються ОБИДВІ особи:
-- політики кличуть ці хелпери і через `current_app_user_id()` (email-клейм,
-- звичайні PostgREST-запити), і через `get_app_user_id_from_auth_uid()`
-- (sub-клейм, storage-контекст — див. 030/054). Вимагати лише одну означало б
-- зламати другий контекст.
--
-- Для `anon` обидві дають NULL, тож `p_uid IS DISTINCT FROM NULL` істинне і
-- функція повертає порожньо — саме те, що треба.
-- ============================================================================

CREATE OR REPLACE FUNCTION get_owner_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM databases
  WHERE owner_id = p_uid
    AND (p_uid = current_app_user_id() OR p_uid = get_app_user_id_from_auth_uid());
$$;

CREATE OR REPLACE FUNCTION get_owner_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM properties
  WHERE owner_id = p_uid
    AND (p_uid = current_app_user_id() OR p_uid = get_app_user_id_from_auth_uid());
$$;

CREATE OR REPLACE FUNCTION get_realtor_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT db_id FROM realtor_subscriptions
  WHERE realtor_id = p_uid
    AND (p_uid = current_app_user_id() OR p_uid = get_app_user_id_from_auth_uid());
$$;

CREATE OR REPLACE FUNCTION get_realtor_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id FROM properties p WHERE p.db_id IN (SELECT get_realtor_db_ids(p_uid));
$$;

CREATE OR REPLACE FUNCTION get_editor_db_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT db_id FROM db_members
  WHERE user_id = p_uid AND status = 'active' AND role = 'editor'
    AND (p_uid = current_app_user_id() OR p_uid = get_app_user_id_from_auth_uid());
$$;

CREATE OR REPLACE FUNCTION get_editor_property_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id FROM properties p WHERE p.db_id IN (SELECT get_editor_db_ids(p_uid));
$$;

CREATE OR REPLACE FUNCTION get_realtor_collection_ids(p_uid UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM collections
  WHERE realtor_id = p_uid
    AND (p_uid = current_app_user_id() OR p_uid = get_app_user_id_from_auth_uid());
$$;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 058_reminders_require_tg_id.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 058 — нагадування для власника БЕЗ tg_id зациклювались на щоденний ретрай
-- ============================================================================
-- Знайдено власним аудитом `send-reminders` — функції, чия УСПІШНА гілка до
-- 052 не виконувалась у проді жодного разу, тобто весь її happy path був
-- непротестованою територією.
--
-- `users.tg_id` NULLABLE (унікальний індекс частковий: `WHERE tg_id IS NOT
-- NULL`), а обидві функції нагадувань джойнять `users` без цієї умови. Для
-- власника без `tg_id` рядок повертається з `tg_id = NULL`; edge-функція
-- кличе Telegram з `chat_id: null`, дістає 400 — і, оскільки рядок у
-- `notifications` пишеться ЛИШЕ на `res?.ok`, маркер дедуплікації не
-- зʼявляється НІКОЛИ.
--
-- Наслідок: `NOT EXISTS (… DATE_TRUNC('month') …)` не стає істинним, тож той
-- самий рядок віддається ЩОДНЯ до кінця місяця — один провалений виклик і
-- один рядок в лог на добу, безкінечно.
--
-- Заміряно на живій БД до фікса: `рядків для власника БЕЗ tg_id: 1 (tg_id=NULL)`.
--
-- Це НЕ витік і не втрата даних — операційний дефект, який стає досяжним рівно
-- тоді, коли 052 вмикає нагадування. Доти функція падала раніше, ніж встигала
-- віддати такий рядок.
--
-- Фікс — один предикат у кожній функції. Решта тіла (включно з `053`-ним
-- `rp.owner_id = p.owner_id` і клампом дня місяця) переноситься дослівно.
-- ============================================================================

CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           LEAST(
             rp.due_day,
             EXTRACT(DAY FROM (
               DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
               + INTERVAL '1 month' - INTERVAL '1 day'
             ))::INT
           )
         )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND u.tg_id IS NOT NULL        -- 058: інакше вічний щоденний ретрай
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;

CREATE OR REPLACE FUNCTION get_due_guest_reminders()
RETURNS TABLE (
  guest_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT DISTINCT ON (u.id, rp.property_id)
    u.id, u.tg_id, rp.property_id,
    p.name::TEXT,
    rp.due_day::INT,
    make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN guest_links gl ON (gl.property_id = rp.property_id OR gl.db_id = p.db_id)
                      AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND u.tg_id IS NOT NULL        -- 058: див. вище
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = u.id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    )
  ORDER BY u.id, rp.property_id;
END;
$$;

REVOKE ALL ON FUNCTION get_due_reminders_today()  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_due_guest_reminders()  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 059_drop_legacy_uuid_tokens.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 059 — UUID обʼєкта більше не приймається як «токен» (залишок класу 049)
-- ============================================================================
-- Знайдено незалежним рев'ю (як PLAUSIBLE), підтверджено читанням джерела.
--
-- Дві функції приймали СИРИЙ UUID обʼєкта там, де мав бути нездогадний
-- share-токен, — обидві через одну й ту саму «легасі»-гілку:
--
--   WHEN p_token ~ '^[0-9a-f]{8}-…$' THEN p.id = p_token::UUID
--
--   • `lookup_shared_property(TEXT)` — SECURITY DEFINER, грант `authenticated`;
--   • `record_public_view(TEXT, TEXT)` — SECURITY DEFINER, грант **anon**.
--
-- Це дослівно те, що забороняє правило 2 чеклісту §5 Audit playbook: «UUID НЕ
-- секрет — він осідає в історії, скріншотах, логах, `screenParams`». І це той
-- самий клас, який 049 вже прибрала для підбірок, видаливши
-- `get_shared_collection(UUID)`. Тут його просто не довели до кінця.
--
-- ── ЩО САМЕ ДАВАЛА КОЖНА ───────────────────────────────────────────────────
-- `record_public_view` (anon!) — будь-хто, знаючи UUID чужого обʼєкта, пише
-- рядки «Веб-перегляд» у ЧУЖУ аналітику (1/хв через дедуп). Тобто цифри, на
-- які власник дивиться, вирішуючи ціну й канали просування, підробляються без
-- автентифікації.
-- `lookup_shared_property` — автентифікований користувач за UUID дістає
-- `db_id`. Вмісту це не дає (екран вантажиться під звичайною RLS і чужому
-- покаже `RetryState`), але сам UUID секретом не є: його віддає
-- `get_public_db_preview(token)` для КОЖНОГО обʼєкта бази.
--
-- Разом: одного шер-лінка досить, щоб зібрати UUID усіх обʼєктів жертви й
-- накрутити їй перегляди.
--
-- ── ЦІНА, НАЗВАНА ЧЕСНО ────────────────────────────────────────────────────
-- Лінки старого вигляду `prop_<uuid>` перестають резолвитись. Ризик малий:
-- `share_token` існує з 020/023, і 023 форсила `NOT NULL`, тож у КОЖНОГО
-- обʼєкта він є, а поточний шаринг генерує саме його. Ламаються лише
-- посилання, роздані до того. Рівно такий самий обмін уже зроблено в 049.
-- ============================================================================

CREATE OR REPLACE FUNCTION lookup_shared_property(p_token TEXT)
RETURNS TABLE (id UUID, db_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.db_id FROM properties p
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION lookup_shared_property(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_shared_property(TEXT) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION record_public_view(p_token TEXT, p_kind TEXT DEFAULT 'prop')
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_id UUID;
BEGIN
  IF p_kind = 'db' THEN
    SELECT d.id INTO v_id FROM databases d
    WHERE d.share_token = p_token
      AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE db_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, db_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд бази', 'view');
    RETURN TRUE;

  ELSIF p_kind = 'col' THEN
    SELECT c.id INTO v_id FROM collections c
    WHERE c.share_token = p_token
      AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE collection_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, collection_id, viewer_id, viewer_name, action)
    VALUES (NULL, v_id, NULL, 'Веб-перегляд підбірки', 'view');
    RETURN TRUE;

  ELSE
    -- 059: ЛИШЕ share_token. Легасі-гілка по UUID прибрана — див. шапку.
    SELECT p.id INTO v_id FROM properties p
    WHERE p.share_token = p_token
      AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
    LIMIT 1;
    IF v_id IS NULL THEN RETURN FALSE; END IF;
    IF EXISTS (
      SELECT 1 FROM property_views
      WHERE property_id = v_id AND viewer_id IS NULL
        AND created_at > now() - interval '1 minute'
    ) THEN RETURN TRUE; END IF;
    INSERT INTO property_views (property_id, viewer_id, viewer_name, action)
    VALUES (v_id, NULL, 'Веб-перегляд', 'view');
    RETURN TRUE;
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION record_public_view(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_public_view(TEXT, TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 060_revoke_destroys_token.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 060 — «Відкликати» тепер СПРАВДІ знищує доступ, а не лише протермінує
-- ============================================================================
-- Знайдено безпековим аудитом архітектури (заміри на живій БД, серпень 2026).
--
-- `manage_share(…, 'revoke')` ставила `share_expires_at = now()`, але
-- **лишала `share_token` незмінним**. Наслідки:
--
--  1. Токен — це BEARER-креденшл: хто його зберіг, той тримає його назавжди.
--     Після «відкликання» він мертвий лише доти, доки діє перевірка терміну.
--  2. Будь-який наступний `set_expiry`/`clear_expiry` ОЖИВЛЯЄ старий лінк —
--     для ВСІХ, хто його зберіг. Це вже було описане в CLAUDE.md як клас
--     «дії, що скасовують ефект безпекової операції», і закрите на клієнті
--     підтвердженням `askRevive`. Але UI-підтвердження — не механізм безпеки:
--     воно лише питає, тоді як сам креденшл лишається валідним.
--
-- Слово «відкликати» обіцяє знищення доступу. Тепер воно його й робить:
-- revoke ротує токен ОДНОЧАСНО з протермінуванням, тож старе посилання
-- перестає існувати як ключ — оживити його неможливо в принципі, і
-- `clear_expiry` після revoke відкриває вже НОВИЙ токен, якого ні в кого немає.
--
-- Публічна поверхня від цього ще й звужується: превʼю віддає `owner_phone` і
-- `owner_tg_username`, тобто вічний токен = вічний доступ до контактів
-- власника. Після 060 «відкликати» справді забирає його.
--
-- Контракт функції НЕ змінюється: ті самі три колонки, ті самі коди помилок,
-- ті самі чотири дії. Міняється лише те, що робить `revoke`.
-- ============================================================================

CREATE OR REPLACE FUNCTION manage_share(
  p_kind   TEXT,
  p_id     UUID,
  p_action TEXT,
  p_days   INT DEFAULT NULL
)
RETURNS TABLE (share_token TEXT, share_expires_at TIMESTAMPTZ, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid   UUID;
  v_owner UUID;
  v_tok   TEXT;
  v_exp   TIMESTAMPTZ;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'not_authenticated'::TEXT; RETURN;
  END IF;
  IF p_kind NOT IN ('db','prop','col') OR p_action NOT IN ('rotate','set_expiry','clear_expiry','revoke') THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;
  IF p_action = 'set_expiry' AND (p_days IS NULL OR p_days < 1 OR p_days > 365) THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    SELECT owner_id INTO v_owner FROM databases WHERE id = p_id FOR UPDATE;
  ELSIF p_kind = 'prop' THEN
    SELECT owner_id INTO v_owner FROM properties WHERE id = p_id FOR UPDATE;
  ELSE
    SELECT realtor_id INTO v_owner FROM collections WHERE id = p_id FOR UPDATE;
  END IF;

  IF v_owner IS NULL OR v_owner <> v_uid THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'forbidden'::TEXT; RETURN;
  END IF;

  -- 060: `revoke` тепер у списку дій, що ротують токен, поруч із `rotate`.
  IF p_kind = 'db' THEN
    UPDATE databases SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE databases.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE databases.share_expires_at
                         END
    WHERE id = p_id
    RETURNING databases.share_token, databases.share_expires_at INTO v_tok, v_exp;
  ELSIF p_kind = 'prop' THEN
    UPDATE properties SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE properties.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE properties.share_expires_at
                         END
    WHERE id = p_id
    RETURNING properties.share_token, properties.share_expires_at INTO v_tok, v_exp;
  ELSE
    UPDATE collections SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE collections.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE collections.share_expires_at
                         END
    WHERE id = p_id
    RETURNING collections.share_token, collections.share_expires_at INTO v_tok, v_exp;
  END IF;

  RETURN QUERY SELECT v_tok, v_exp, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) TO authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 061_public_phone_opt_in.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 061 — телефон власника на публічній /v стає ОПЦІЄЮ, а не типовим станом
-- ============================================================================
-- Заміряно під час аудиту архітектури: усі три публічні превʼю віддають
-- `owner_phone` кожному, хто має шер-лінк. Разом із тим, що токен не має
-- терміну дії за замовчуванням, це означало просту річ: **людина, якій ви
-- одного разу надіслали посилання, тримає ваш номер телефону назавжди** — і
-- може передати лінк далі.
--
-- Це не діра в контролі доступу: превʼю віддає рівно те, що задумано віддавати
-- власнику лінка. Це надлишок ЗА ЗАМОВЧУВАННЯМ — контакт потрібен, щоб глядач
-- звʼязався, але в застосунку вже є рідний для Telegram канал
-- (`owner_tg_username`), який не розкриває номер.
--
-- Тому: `users.public_phone` DEFAULT **false**, і всі три превʼю віддають
-- `owner_phone` ЛИШЕ коли власник свідомо його увімкнув. Приватність за
-- замовчуванням, а не як налаштування, яке треба знайти.
--
-- КОНТРАКТ НЕ ЗМІНЮЄТЬСЯ: колонка `owner_phone` лишається на місці, у тому ж
-- порядку, того ж типу — просто приходить NULL, коли опція вимкнена. Клієнт
-- уже вміє з цим працювати (`ContactRow` приймає `phone: string | null` і не
-- малює рядок для NULL), тож фронт сумісний в обидва боки — урок 050.
--
-- Хто вже ділився номером свідомо, нічого не втрачає раптово: колонка нова,
-- і власник вмикає її одним перемикачем у Профілі.
-- ============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_phone BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN users.public_phone IS
  'Чи показувати номер телефону на публічних /v сторінках. DEFAULT false — приватність за замовчуванням (061).';

-- ── Три превʼю: телефон під прапорцем ──────────────────────────────────────
-- Тіла беруться з ОСТАННІХ визначень (042 для property, 040 для db/collection,
-- 056 для collection) і змінюються рівно в одному місці кожне.

CREATE OR REPLACE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE (
  db_id UUID, db_name TEXT, db_type TEXT, db_color TEXT,
  share_expires_at TIMESTAMPTZ,
  property_id UUID, property_name TEXT, property_status TEXT, property_floor TEXT,
  property_area_useful DOUBLE PRECISION, property_area_total DOUBLE PRECISION,
  property_rent_type TEXT, property_rent_rate DOUBLE PRECISION,
  property_sale_price DOUBLE PRECISION, property_description TEXT,
  owner_first_name TEXT, owner_last_name TEXT, owner_tg_username TEXT,
  owner_phone TEXT, owner_currency TEXT, first_photo TEXT
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.name, d.type, d.color, d.share_expires_at,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total,
         p.rent_type, p.rent_rate, p.sale_price, p.description,
         o.first_name, o.last_name, o.tg_username,
         CASE WHEN o.public_phone THEN o.phone ELSE NULL END,   -- 061
         o.currency,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM databases d
  JOIN users o ON o.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.sort_order, p.created_at;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;


-- ── Обʼєкт і підбірка: те саме, одна зміна в кожній ────────────────────────
-- Тіла ВЗЯТІ З ЗІБРАНОЇ БД (`pg_get_functiondef`), а не переписані з памʼяті:
-- у property-превʼю 28 рядків і 28 колонок, у collection — 24; ручне
-- відтворення тут — це запрошення до дрейфу, який уже коштував нам 050.

CREATE OR REPLACE FUNCTION public.get_public_property_preview(p_token text)
 RETURNS TABLE(property_id uuid, property_name text, property_status text, property_floor text, property_area_useful double precision, property_area_total double precision, property_area_basis text, property_rent_type text, property_rent_rate double precision, property_utilities_rate double precision, property_description text, property_address text, property_has_parking boolean, property_parking_spaces integer, property_parking_type text, property_ev_charger boolean, property_sale_price double precision, share_expires_at timestamp with time zone, db_id uuid, db_name text, db_type text, db_color text, owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text, owner_currency text, photos text[])
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT
    p.id, p.name, p.status, p.floor,
    p.area_useful, p.area_total, p.area_basis,
    p.rent_type, p.rent_rate, p.utilities_rate,
    p.description, p.address, p.has_parking, p.parking_spaces,
    p.parking_type, p.ev_charger, p.sale_price,
    p.share_expires_at,
    d.id, d.name, d.type, d.color,
    u.first_name, u.last_name, u.tg_username,
    CASE WHEN u.public_phone THEN u.phone ELSE NULL END,   -- 061
    u.currency,
    ARRAY(
      SELECT ph.storage_path FROM property_photos ph
      WHERE ph.property_id = p.id
      ORDER BY ph.sort_order
    )
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$function$;

REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.get_public_collection_preview(p_token text)
 RETURNS TABLE(collection_id uuid, collection_name text, share_expires_at timestamp with time zone, realtor_first_name text, realtor_last_name text, realtor_tg_username text, realtor_phone text, property_id uuid, property_name text, property_status text, property_floor text, property_area_useful double precision, property_area_total double precision, property_area_basis text, property_rent_type text, property_rent_rate double precision, property_sale_price double precision, property_description text, owner_currency text, db_id uuid, db_name text, db_type text, db_color text, first_photo text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username,
         CASE WHEN r.public_phone THEN r.phone ELSE NULL END,   -- 061
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1)
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  -- 056: показуємо обʼєкт, ЛИШЕ якщо рієлтор досі має до нього доступ —
  -- власний, або через активну підписку на його базу. Це друга половина
  -- фікса: без неї рядки, посаджені до 056, світились би далі.
  LEFT JOIN properties p ON p.id = cp.property_id
    AND (
      p.owner_id = c.realtor_id
      OR EXISTS (
        SELECT 1 FROM realtor_subscriptions rs
        WHERE rs.realtor_id = c.realtor_id AND rs.db_id = p.db_id
      )
    )
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$function$;

REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 062_legacy_permissive_and_acl.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 062 — залишок 038 БЕЗ його регресії, плюс ACL, що пережив 052
-- ============================================================================
--
-- ЗНАЙДЕНО НАКАТОМ У ПРОДІ, не аудитом: `verify_release.sql` дав два MISSING
-- на базі, де все інше зелене.
--
-- ── ЧОМУ НЕ ПРОСТО «ВИКОНАЙ 038» ───────────────────────────────────────────
-- Саме це радив `verify_release.sql`, і ця порада НЕБЕЗПЕЧНА. 038 містить
-- власну «самодостатню» копію `get_app_user_id_from_auth_uid()`, узяту ДО
-- 031 — без доменного якоря (`email ~ '^\d{1,20}@telegram\.propspace\.app$'`)
-- і без `tg_id > 0`. Це рівно та регресія, яку лікувала 045 (див. CLAUDE.md
-- §0h): без якоря `SPLIT_PART(email,'@',1) = tg_id` дозволяє самостійну
-- реєстрацію під `<чийсь_tg_id>@будь-що.example` і резолвиться в `users.id`
-- ЖЕРТВИ, тобто дає запис і видалення її фото.
--
-- У базі, де 038 ніколи не застосовувалась, а 045 застосована, запуск 038
-- зараз ВІДКОТИВ БИ фікс. Тому 062 бере з 038 лише те, чого бракує —
-- прибирання пермісивних політик — і не чіпає жодної функції ідентичності.
--
-- Порада в `verify_release.sql` виправлена тим самим дифом: рядок 6 тепер
-- вказує сюди. Гард, що радить небезпечну дію, гірший за відсутній — той
-- самий клас, що вже описаний для стенда, який плутав збій зʼєднання з
-- дефектом міграції.
--
-- ── ЩО САМЕ ЛІКУЄ ──────────────────────────────────────────────────────────
-- 1. `photos_insert_auth` / `photos_delete_auth` (з 008) дозволяють БУДЬ-ЯКОМУ
--    автентифікованому користувачу писати й видаляти БУДЬ-ЯКИЙ шлях у бакеті
--    photos. Політики обʼєднуються через OR, тож строгі правила 054 нічого не
--    обмежують, поки ці двоє живі: строга + пермісивна = пермісивна.
--    А `/v` публічно віддає `storage_path` кожного фото, тож ціль не треба
--    вгадувати.
-- 2. `pfiles_insert_realtor` / `pfiles_update_realtor` — те саме на таблиці
--    `property_files`: підписаний рієлтор вставляє файловий рядок на ЧУЖИЙ
--    обʼєкт. `verify_release` рядок 8 цього не бачив — він перевіряє лише, що
--    СТРОГА політика існує, а не що пермісивної немає.
-- 3. `storage_photos_update` — 054 відтворила insert/delete, але не update.
-- 4. Дефолтний PUBLIC на функціях нагадувань. 052 його знімала, але в проді
--    він лишився — отже там є варіант функції, до якого `REVOKE` за точною
--    сигнатурою не дійшов (інша сигнатура, або перевантаження). Тому тут
--    REVOKE йде ДИНАМІЧНО по ВСІХ перевантаженнях за іменем: так це працює
--    незалежно від того, яка саме форма лежить у базі.
--
-- Ідемпотентна.

-- ── 1. Пермісивні політики запису в storage ─────────────────────────────────
DROP POLICY IF EXISTS "photos_insert_auth" ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_auth" ON storage.objects;

-- ── 2. Пермісивні політики на property_files ────────────────────────────────
DROP POLICY IF EXISTS "pfiles_insert_realtor" ON property_files;
DROP POLICY IF EXISTS "pfiles_update_realtor" ON property_files;

-- ── 3. UPDATE на фото — той самий рецепт, що insert/delete у 054 ────────────
-- Одне джерело особи (sub-клейм через хелпер), без залежності від email-клейма
-- — див. 054 про політику, що впізнавала людину двома незалежними способами.
DROP POLICY IF EXISTS "storage_photos_update" ON storage.objects;
CREATE POLICY storage_photos_update ON storage.objects
  FOR UPDATE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── 4. Дефолтний PUBLIC на службових функціях ───────────────────────────────
-- По ІМЕНІ, а не по сигнатурі: у проді лишився грант, якого точний REVOKE із
-- 052 не зняв, отже там інша форма функції. `oid::regprocedure` дає повний
-- підпис для будь-якого перевантаження.
DO $$
DECLARE r RECORD; n INT := 0;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
       AND p.proname IN ('get_due_reminders_today',
                         'get_due_guest_reminders',
                         'mark_overdue_payments')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', r.sig);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM anon', r.sig);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM authenticated', r.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', r.sig);
    n := n + 1;
    RAISE NOTICE '062: замкнено %', r.sig;
  END LOOP;
  IF n = 0 THEN
    RAISE NOTICE '062: функцій нагадувань не знайдено — 052 не застосована?';
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- ── Verification ────────────────────────────────────────────────────────────
-- Має показати нуль рядків. Кожен рядок = пермісивна політика або відкрита
-- службова функція, що лишились.
SELECT 'політика' AS kind, policyname AS name
  FROM pg_policies
 WHERE policyname IN ('photos_insert_auth','photos_delete_auth',
                      'pfiles_insert_realtor','pfiles_update_realtor')
UNION ALL
SELECT 'функція відкрита для anon', p.oid::regprocedure::TEXT
  FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
 WHERE ns.nspname = 'public'
   AND p.proname IN ('get_due_reminders_today','get_due_guest_reminders','mark_overdue_payments')
   AND has_function_privilege('anon', p.oid, 'EXECUTE');

-- ─────────────────────────────────────────────────────────────────────────
-- 063_view_insert_editors_and_dbs.sql
-- ─────────────────────────────────────────────────────────────────────────
-- 063: `views_insert_auth` пускає перегляди РЕДАКТОРІВ і перегляди БАЗ.
--
-- Політика з 036 дозволяла вставку лише коли `property_id` належить власнику
-- або підписаному рієлтору. Два наслідки, обидва мовчазні (RLS не віддає
-- помилки на заблокований INSERT — рівно клас правила 8 у Security rules):
--
--   1. РЕДАКТОР КОМАНДИ не міг записати перегляд картки: `get_editor_property_ids`
--      у переліку немає. Тобто 041 дала редактору право писати обʼєкти, фото й
--      платежі, але не власний слід перегляду.
--   2. Перегляд БАЗИ не міг записати НІХТО. Рядок бази має `property_id = NULL`
--      (так його пише `record_public_view` з 040), а `NULL IN (...)` дає NULL,
--      не TRUE — тобто предикат не виконувався в принципі.
--
-- Читання цих рядків уже дозволене: `views_owner_select` (картки власника),
-- `views_db_owner_select` (040, рядки баз) і `views_editor_select` (047).
-- Тобто діра була рівно на боці ЗАПИСУ.
--
-- Обидві гілки перевіряють, що ЦІЛЬ доступна тому, хто пише, — той самий урок,
-- що в 046/053/056: політика на таблиці слідів мусить питати не лише «це я?»,
-- а й «чи моя ціль?». Інакше будь-хто садив би сліди в чужу базу.

DROP POLICY IF EXISTS "views_insert_auth" ON property_views;

CREATE POLICY "views_insert_auth" ON property_views
  FOR INSERT WITH CHECK (
    auth.role() = 'authenticated'
    -- Чужу особу підставити не можна (лишається з 036).
    AND (viewer_id IS NULL OR viewer_id = current_app_user_id())
    AND (
      -- Перегляд КАРТКИ: обʼєкт мусить бути досяжний тому, хто пише.
      (
        property_id IS NOT NULL AND (
          property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
          OR property_id IN (SELECT get_realtor_property_ids(current_app_user_id()))
          OR property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
        )
      )
      OR
      -- Перегляд БАЗИ: рядок без обʼєкта. Та сама вимога — база мусить бути
      -- досяжна; `collection_id` тут свідомо НЕ згадується, бо підбірки
      -- рахує `record_public_view` під service_role, а не клієнт.
      (
        property_id IS NULL AND db_id IS NOT NULL AND (
          db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
          OR db_id IN (SELECT get_realtor_db_ids(current_app_user_id()))
          OR db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
        )
      )
    )
  );

-- ─────────────────────────────────────────────────────────────────────────
-- 064_landlord_name.sql
-- ─────────────────────────────────────────────────────────────────────────
-- 064: ОРЕНДОДАВЕЦЬ — той, хто здає.
--
-- У моделі досі було двоє: `tenant_name` (орендар — хто знімає) і `owner_id`
-- (акаунт у застосунку). Того, хто ЗДАЄ, не було ніде — і для власника з
-- однією юрособою це збігалось із ним самим, тож не заважало. Щойно базою
-- керує агенція або приміщення розділені між кількома юрособами, документ
-- перестає відповідати, ХТО саме здає конкретний офіс.
--
-- УСПАДКУВАННЯ ЧЕРЕЗ NULL. Орендодавець задається на БАЗІ (дефолт на всі
-- обʼєкти) і за потреби перевизначається на ОБʼЄКТІ. `properties.landlord_name
-- IS NULL` означає «як у базі», а не «немає»: стан «у цього простору
-- орендодавця немає, хоч у бази є» для назви беззмістовний, а моделювати його
-- довелось би sentinel-значенням або окремим булеаном — ціна без користі.
--
-- Обидві колонки nullable і без DEFAULT — рівно як `tenant_name` у 023.

ALTER TABLE databases  ADD COLUMN IF NOT EXISTS landlord_name VARCHAR(200);
ALTER TABLE properties ADD COLUMN IF NOT EXISTS landlord_name VARCHAR(200);

-- ── Публічні превʼю ─────────────────────────────────────────────────────────
-- Три функції віддають нову колонку ОСТАННЬОЮ, решта лишається на місці, того
-- ж типу й у тому ж порядку. Це не педантизм: 050 перейменувала ключі в
-- гостьовому превʼю, і перший екран, який бачить запрошена людина, показав
-- сірий безіменний тайл. Тіла нижче взяті з `pg_get_functiondef` зібраної БД,
-- а не переписані з памʼяті — з тієї ж причини.
--
-- Значення вже ЗЛИТЕ: клієнту публічної сторінки нема з чим його зливати, бо
-- рядка бази він окремо не отримує.
--
-- Зміна типу результату вимагає DROP + CREATE — `CREATE OR REPLACE` на це не
-- здатна (42P13).

DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
CREATE FUNCTION get_public_property_preview(p_token TEXT)
RETURNS TABLE(
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_area_basis text, property_rent_type text, property_rent_rate double precision,
  property_utilities_rate double precision, property_description text, property_address text,
  property_has_parking boolean, property_parking_spaces integer, property_parking_type text,
  property_ev_charger boolean, property_sale_price double precision,
  share_expires_at timestamptz, db_id uuid, db_name text, db_type text, db_color text,
  owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text,
  owner_currency text, photos text[],
  property_landlord_name text
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    p.id, p.name, p.status, p.floor,
    p.area_useful, p.area_total, p.area_basis,
    p.rent_type, p.rent_rate, p.utilities_rate,
    p.description, p.address, p.has_parking, p.parking_spaces,
    p.parking_type, p.ev_charger, p.sale_price,
    p.share_expires_at,
    d.id, d.name, d.type, d.color,
    u.first_name, u.last_name, u.tg_username,
    CASE WHEN u.public_phone THEN u.phone ELSE NULL END,   -- 061
    u.currency,
    ARRAY(
      SELECT ph.storage_path FROM property_photos ph
      WHERE ph.property_id = p.id
      ORDER BY ph.sort_order
    ),
    COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM properties p
  JOIN databases d ON d.id = p.db_id
  JOIN users u ON u.id = p.owner_id
  WHERE p.share_token = p_token
    AND (p.share_expires_at IS NULL OR p.share_expires_at > now())
  LIMIT 1;
$$;
REVOKE ALL ON FUNCTION get_public_property_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_property_preview(TEXT) TO anon, authenticated, service_role;

DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
CREATE FUNCTION get_public_db_preview(p_token TEXT)
RETURNS TABLE(
  db_id uuid, db_name text, db_type text, db_color text, share_expires_at timestamptz,
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_rent_type text, property_rent_rate double precision,
  property_sale_price double precision, property_description text,
  owner_first_name text, owner_last_name text, owner_tg_username text, owner_phone text,
  owner_currency text, first_photo text,
  property_landlord_name text
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.id, d.name, d.type, d.color, d.share_expires_at,
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total,
         p.rent_type, p.rent_rate, p.sale_price, p.description,
         o.first_name, o.last_name, o.tg_username,
         CASE WHEN o.public_phone THEN o.phone ELSE NULL END,   -- 061
         o.currency,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1),
         COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM databases d
  JOIN users o ON o.id = d.owner_id
  LEFT JOIN properties p ON p.db_id = d.id
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  ORDER BY p.sort_order, p.created_at;
$$;
REVOKE ALL ON FUNCTION get_public_db_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_db_preview(TEXT) TO anon, authenticated, service_role;

DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);
CREATE FUNCTION get_public_collection_preview(p_token TEXT)
RETURNS TABLE(
  collection_id uuid, collection_name text, share_expires_at timestamptz,
  realtor_first_name text, realtor_last_name text, realtor_tg_username text, realtor_phone text,
  property_id uuid, property_name text, property_status text, property_floor text,
  property_area_useful double precision, property_area_total double precision,
  property_area_basis text, property_rent_type text, property_rent_rate double precision,
  property_sale_price double precision, property_description text, owner_currency text,
  db_id uuid, db_name text, db_type text, db_color text, first_photo text,
  property_landlord_name text
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id, c.name, c.share_expires_at,
         r.first_name, r.last_name, r.tg_username,
         CASE WHEN r.public_phone THEN r.phone ELSE NULL END,   -- 061
         p.id, p.name, p.status, p.floor,
         p.area_useful, p.area_total, COALESCE(p.area_basis, 'total'),
         p.rent_type, p.rent_rate, p.sale_price,
         p.description, po.currency,
         d.id, d.name, d.type, d.color,
         (SELECT ph.storage_path FROM property_photos ph
          WHERE ph.property_id = p.id ORDER BY ph.sort_order, ph.created_at LIMIT 1),
         COALESCE(p.landlord_name, d.landlord_name)::TEXT       -- 064
  FROM collections c
  JOIN users r ON r.id = c.realtor_id
  LEFT JOIN collection_properties cp ON cp.collection_id = c.id
  -- 056: показуємо обʼєкт, ЛИШЕ якщо рієлтор досі має до нього доступ —
  -- власний, або через активну підписку на його базу.
  LEFT JOIN properties p ON p.id = cp.property_id
    AND (
      p.owner_id = c.realtor_id
      OR EXISTS (
        SELECT 1 FROM realtor_subscriptions rs
        WHERE rs.realtor_id = c.realtor_id AND rs.db_id = p.db_id
      )
    )
  LEFT JOIN databases  d ON d.id = p.db_id
  LEFT JOIN users     po ON po.id = p.owner_id
  WHERE c.share_token = p_token
    AND c.is_draft = false
    AND (c.share_expires_at IS NULL OR c.share_expires_at > now())
  ORDER BY cp.added_at;
$$;
REVOKE ALL ON FUNCTION get_public_collection_preview(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_public_collection_preview(TEXT) TO anon, authenticated, service_role;

NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 065_lease_reminders.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 065 — нагадування про КІНЕЦЬ ДОГОВОРУ в Telegram
-- ============================================================================
-- Прогалина, названа продуктово: `useLeaseAlerts` рахує наближення кінця
-- договору НА КЛІЄНТІ, тобто власник дізнається про це, лише якщо сам відкрив
-- застосунок. Поза застосунком іде рівно один тип — `rent_reminder`, і пише
-- його виключно `send-reminders`. Договір, що спливає через тиждень, не
-- доходить до людини нічим.
--
-- Похідний блок на екрані лишається як є (він показує СТАН і зникає сам, щойно
-- договір продовжили) — ця функція додає поруч ПОДІЮ: разове повідомлення на
-- кожному з порогів.
--
-- ── Пороги, і чому саме такі ───────────────────────────────────────────────
-- {30, 7, 1, 0} днів. Щоденна розсилка все 30-денне вікно перетворила б
-- нагадування на шум, після якого його вимикають; один поріг за 30 днів —
-- запізно для «встигнути передомовитись». Нуль — це «сьогодні останній день».
--
-- ── Дедуп ключується ДАТОЮ ДОГОВОРУ, а не лише обʼєктом ────────────────────
-- Інакше продовжений договір ніколи більше не нагадав би про себе: рядок
-- `notifications` про старий поріг лишається назавжди. Ключ
-- (property_id, lease_end_date, days_left) дає рівно одне повідомлення на
-- кожен поріг КОЖНОГО договору, і продовження автоматично відкриває нову
-- серію.
--
-- ── Три вже оплачені уроки, застосовані тут одразу ─────────────────────────
--  • 052: `properties.name`/`tenant_name` — VARCHAR(200), а plpgsql звіряє тип
--    КОЛОНКИ. Без `::TEXT` кожен виклик падає з «structure of query does not
--    match function result type», і жодного рядка не зʼявляється НІКОЛИ.
--  • 058: `users.tg_id` NULLABLE. Без `IS NOT NULL` edge-функція кличе
--    Telegram із `chat_id: null`, дістає 400, а рядок `notifications`
--    пишеться лише на `res.ok` — тобто маркер дедупу не зʼявляється, і той
--    самий рядок віддається ЩОДНЯ.
--  • правило 12: `GRANT ... TO service_role` НЕ знімає дефолтного PUBLIC.
--    Функція віддає `tg_id`, назву обʼєкта та ІМʼЯ ОРЕНДАРЯ по всіх власниках
--    без параметрів — з anon-ключем це наскрізний дамп PII. Тому явний
--    `REVOKE ALL ... FROM PUBLIC` ПЕРЕД грантом.
-- ============================================================================


DROP FUNCTION IF EXISTS get_due_lease_reminders();

CREATE FUNCTION get_due_lease_reminders()
RETURNS TABLE (
  owner_id        UUID,
  tg_id           BIGINT,
  property_id     UUID,
  property_name   TEXT,
  tenant_name     TEXT,
  lease_end_date  DATE,
  days_left       INT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT p.owner_id,
         u.tg_id,
         p.id,
         p.name::TEXT,
         p.tenant_name::TEXT,
         p.lease_end_date,
         (p.lease_end_date - v_today)::INT
  FROM properties p
  JOIN users u ON u.id = p.owner_id
  WHERE p.status = 'occupied'
    AND p.lease_end_date IS NOT NULL
    AND u.tg_id IS NOT NULL
    AND (p.lease_end_date - v_today)::INT IN (30, 7, 1, 0)
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = p.owner_id
        AND n.type = 'lease_reminder'
        AND (n.data->>'property_id')::UUID = p.id
        AND (n.data->>'lease_end_date') = p.lease_end_date::TEXT
        AND (n.data->>'days_left')::INT = (p.lease_end_date - v_today)::INT
    );
END;
$$;

REVOKE ALL ON FUNCTION get_due_lease_reminders() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_lease_reminders() TO service_role;


NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 066_identity_anchor_storage_enum_guest_target.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 066 — три залишки, знайдені наскрізним безпековим рев'ю
--   1. current_app_user_id() без якоря — єдине джерело особи для ВСІХ політик
--   2. storage_photos_select без ролі — масове перелічення бакета
--   3. db_guest_select не перевіряє, що ЦІЛЬ належить видавцю лінка
-- ═══════════════════════════════════════════════════════════════════════════


-- ── 1. ЯКІР ОСОБИ ──────────────────────────────────────────────────────────
--
-- `current_app_user_id()` резолвить особу для КОЖНОЇ політики в схемі, і
-- робить це найслабшою з двох наявних перевірок:
--
--     jwt_email NOT LIKE '%@telegram.propspace.app'      ← суфікс, без якоря
--     SPLIT_PART(jwt_email, '@', 1)::BIGINT              ← ПЕРШИЙ сегмент
--
-- Загартований близнюк `get_app_user_id_from_auth_uid()` має і якір, і
-- `tg_id > 0` — їх додала 031 (CRITICAL-2) саме проти самостійної реєстрації
-- під `<чийсь_tg_id>@будь-що`, а 045 відновила після регресії 038. Ширше
-- вживана функція їх не отримала жодного разу.
--
-- ЧЕСНО ПРО ЕКСПЛУАТОВАНІСТЬ: адреса, що обходить суфікс і дає потрібний
-- перший сегмент, потребує ДВОХ `@` (`123@x.com@telegram.propspace.app`), а
-- GoTrue таку найімовірніше відхилить — підтвердити це з нашого середовища
-- неможливо. Тобто це не звіт про живу діру, а усунення АСИМЕТРІЇ: дві
-- функції з однією роллю не мають різнитись у тому, наскільки суворо вони
-- впізнають людину. Ціна зміни нульова, ціна помилки — весь граф RLS.
CREATE OR REPLACE FUNCTION current_app_user_id()
RETURNS UUID
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  jwt_email TEXT;
  tg_id_val BIGINT;
BEGIN
  jwt_email := current_setting('request.jwt.claims', true)::jsonb->>'email';
  -- Якір з обох боків + рівно цифри в локальній частині. `{1,20}` — стеля
  -- BIGINT; довше все одно впало б на касті, але падати мовчки не треба.
  IF jwt_email IS NULL OR jwt_email !~ '^\d{1,20}@telegram\.propspace\.app$' THEN
    RETURN NULL;
  END IF;
  tg_id_val := SPLIT_PART(jwt_email, '@', 1)::BIGINT;
  IF tg_id_val <= 0 THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT id FROM users WHERE tg_id = tg_id_val LIMIT 1);
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$$;


-- ── 2. ПЕРЕЛІЧЕННЯ БАКЕТА ФОТО ─────────────────────────────────────────────
--
-- Останнє визначення (016) — `FOR SELECT USING (bucket_id = 'photos')`, БЕЗ
-- `TO`, тобто для PUBLIC: `anon` включно. Anon-ключ за задумом лежить у
-- клієнтському бандлі, отже будь-хто міг перелічити ВСІ обʼєкти бакета через
-- Storage list API. Імена — `{propertyId}/{timestamp}_{rand}.ext`, тож це
-- повний список UUID обʼєктів системи плюс прямі URL кожного фото.
--
-- 054 і 062 перебудували insert/update/delete на цьому бакеті, а select не
-- чіпали — тому й лишився.
--
-- МЕЖА ЦЬОГО ФІКСА, названа прямо: бакет `photos` — ПУБЛІЧНИЙ (`public=true`,
-- 008/016), і саме на цьому стоїть `/v`: `photoUrl()` будує
-- `/object/public/photos/...`, який читається БЕЗ політик і без сесії. Тобто
-- ця міграція прибирає ПЕРЕЛІЧЕННЯ (знайти шляхи), а не читання за вже
-- відомим шляхом. Закрити друге можна лише зробивши бакет приватним і
-- перевівши публічну сторінку на підписані URL — це продуктова зміна з
-- власною ціною (термін життя посилань у розданих оголошеннях), тож вона
-- свідомо не тут.
--
-- Форма — та сама, що в `pfiles_storage_select` (054): без підзапитів під
-- RLS, через SECURITY DEFINER хелпери, з ОДНИМ джерелом особи.
DROP POLICY IF EXISTS "storage_photos_select" ON storage.objects;
CREATE POLICY "storage_photos_select" ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'photos'
    AND (
      split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_realtor_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
      )
    )
  );


-- ── 3. ГОСТЬОВИЙ ЛІНК: ЦІЛЬ МУСИТЬ НАЛЕЖАТИ ВИДАВЦЮ ────────────────────────
--
-- Пʼятий інстанс класу, який 046 / 050 / 053 / 056 / 063 виправляли скрізь,
-- крім цієї політики. 046 закрила ЗАПИС (`guest_links` з чужим `db_id`) і
-- читання через `is_guest_of_property`; 050 — третього споживача
-- (`get_guest_property_preview`). `db_guest_select` лишилась із предикатом
-- ДО 046: питає лише «лінк мій?», не питаючи, чи ціль належить тому, хто
-- лінк видав.
--
-- Наслідок для рядка, посадженого ДО 046 (`owner_id` зловмисника, `db_id`
-- жертви): гість читає рядок бази жертви цілком — назву, адресу, тип,
-- `landlord_name` І `share_token` з `share_expires_at`, тобто вічний
-- публічний /v-лінк, який переживе відкликання його ж гостьового доступу.
-- Нові такі рядки неможливі з 046, отже це ЗАЛИШОК, а не відкритий вектор —
-- рівно того класу, заради якого 050 і писалась.
DROP POLICY IF EXISTS "db_guest_select" ON databases;
CREATE POLICY "db_guest_select" ON databases
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM guest_links gl
      WHERE gl.guest_user_id = current_app_user_id()
        AND gl.status = 'active'
        AND gl.db_id = databases.id
        -- ЄДИНА ЗМІНА, і вона вся тут.
        AND gl.owner_id = databases.owner_id
    )
  );


-- ── Аудит: чи лежать у базі лінки з чужою ціллю ─────────────────────────────
-- Має показати 0. Ненульове означає, що такі рядки посаджено до 046 — після
-- цієї міграції вони мертві, але їх варто прибрати руками.
DO $$
DECLARE n INT;
BEGIN
  SELECT COUNT(*) INTO n
  FROM guest_links gl
  JOIN databases d ON d.id = gl.db_id
  WHERE gl.db_id IS NOT NULL AND d.owner_id <> gl.owner_id;
  IF n > 0 THEN
    RAISE WARNING '066: гостьових лінків із ЧУЖОЮ базою: % — вони більше не діють, але рядки лишились', n;
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────
-- 067_tenancies.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 067_tenancies.sql — АРХІВ ПРАВОВІДНОСИН З ОРЕНДАРЯМИ.
-- Ідемпотентна. Виконувати в Supabase Dashboard → SQL Editor.
--
-- ЩО ЛІКУЄ. Звільнення обʼєкта ОБНУЛЯЄ `tenant_name`, `lease_start_date`,
-- `lease_end_date` просто в рядку `properties` — тобто правовідносини
-- ЗНИКАЮТЬ БЕЗСЛІДНО. Єдиний шлях назад сьогодні — кнопка «Скасувати» в
-- тості, і вона живе в памʼяті сторінки: перезавантажив — втрачено назавжди.
--
-- ОРЕНДА СТАЄ СУТНІСТЮ: рядок ВІДКРИВАЄТЬСЯ, коли обʼєкт стає зайнятим, і
-- ЗАКРИВАЄТЬСЯ, коли перестає. `properties.tenant_name` лишається як був —
-- тепер це КЕШ активної оренди, тож жоден наявний екран, експорт і публічна
-- `/v` не потребують правок.
--
-- ЧОМУ ТРИГЕР, А НЕ КОД ЕКРАНА. Орендаря обнуляють ТРИ різні шляхи:
--   1. «Звільнити обʼєкт»            — PropertyDetailScreen
--   2. пакетне «Вільно»              — useProperties.batchUpdateStatus
--   3. збереження форми зі статусом ≠ «Зайнято» — PropertyFormScreen
-- Тригер — єдине місце, де вони сходяться, і він накриває ще й ті шляхи,
-- яких сьогодні немає (прямий UPDATE, майбутній імпорт). Запис в обробнику
-- кнопки покрив би один шлях із трьох — рівно той клас дефекту, який у цьому
-- проєкті вже повторювався (див. правило 8 у Security rules).
--
-- ФАКТИЧНИЙ ПЕРІОД ≠ ДОГОВІРНИЙ, і це не педантизм: дати договору
-- НЕОБОВʼЯЗКОВІ (`RentPropertyScreen` пише `leaseStart || undefined`), тож
-- оренда цілком може не мати жодної дати. Тому `started_at`/`ended_at` —
-- моменти САМИХ ДІЙ, а `lease_*` зберігаються поруч як окремі факти.
-- Наслідок, заради якого це й зроблено: «платежі цієї оренди» = записи,
-- чий `due_date` потрапляє в `[started_at, ended_at)`. Це правило ТОЧНЕ, а
-- не наближене — обʼєкт має рівно один статус, тож дві оренди не можуть
-- перекриватись у часі, — і воно працює для ВЖЕ НАЯВНИХ платежів, чого
-- колонка `tenancy_id` на `rent_payment_records` не вміла б.
-- ============================================================================

-- ── Таблиця ──────────────────────────────────────────────────────────────────
-- `db_id` CASCADE, а `property_id` SET NULL — і ця пара не випадкова:
-- архів ЖИВЕ В БАЗІ (рішення власника), тож без бази він недосяжний за
-- побудовою; а от видалення ОДНОГО обʼєкта не сміє стирати фінансову
-- історію — назва обʼєкта заморожена в самому рядку.
CREATE TABLE IF NOT EXISTS tenancies (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      UUID NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  db_id         UUID NOT NULL REFERENCES databases(id)  ON DELETE CASCADE,
  property_id   UUID          REFERENCES properties(id) ON DELETE SET NULL,

  -- ЗАМОРОЖЕНІ факти: архівна картка мусить читатись і тоді, коли обʼєкт
  -- перейменували, змінили ставку або видалили зовсім.
  property_name TEXT NOT NULL,
  tenant_name   TEXT,
  landlord_name TEXT,
  rent_rate     DOUBLE PRECISION,
  rent_type     TEXT,
  utilities_rate DOUBLE PRECISION,
  area_basis    TEXT,
  area_useful   DOUBLE PRECISION,
  area_total    DOUBLE PRECISION,
  currency      TEXT,

  -- Договірні дати — окремо від фактичних, обидві можуть бути NULL.
  lease_start_date DATE,
  lease_end_date   DATE,

  -- ФАКТИЧНИЙ період: моменти дій.
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenancies ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_tenancies_db    ON tenancies (db_id, ended_at DESC NULLS FIRST, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenancies_prop  ON tenancies (property_id, started_at DESC);

-- Рівно ОДНА відкрита оренда на обʼєкт. Часткового унікального індексу тут
-- досить: закритих може бути скільки завгодно.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenancies_one_open
  ON tenancies (property_id) WHERE ended_at IS NULL AND property_id IS NOT NULL;

-- ── RLS: власник бази + редактор команди ────────────────────────────────────
-- Дзеркалить `property_folders` (043). `WITH CHECK` форсить, що `owner_id` —
-- це власник БАЗИ, а не той, хто пише: редактор не привласнить історію собі.
-- Рієлтор і гість не мають політики ВЗАГАЛІ — комерційна історія власника не
-- є частиною лістингу.
DROP POLICY IF EXISTS "tenancies_owner_all" ON tenancies;
CREATE POLICY "tenancies_owner_all" ON tenancies
  FOR ALL
  USING      (db_id IN (SELECT get_owner_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

DROP POLICY IF EXISTS "tenancies_editor_all" ON tenancies;
CREATE POLICY "tenancies_editor_all" ON tenancies
  FOR ALL
  USING      (db_id IN (SELECT get_editor_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

-- ── Тригер ───────────────────────────────────────────────────────────────────
-- SECURITY DEFINER: це СЛУЖБОВИЙ облік, а не дія користувача. Усі значення
-- виводяться з рядка `properties`, жодного вводу ззовні немає, тож
-- розширення прав тут нічого не відкриває — зате редактор команди може
-- звільнити обʼєкт, не впираючись у власну політику запису.
CREATE OR REPLACE FUNCTION public.sync_tenancy_on_property_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  -- ВІКНО СКАСУВАННЯ. «Скасувати» в тості повертає обʼєкт у «Зайнято», тобто
  -- з погляду тригера це НОВА здача — і наївна гілка відкриття створила б
  -- ДРУГУ оренду замість повернення першої. Тому щойно закрита оренда з ТИМ
  -- САМИМ орендарем повертається, а не дублюється. Тост живе ~6 секунд;
  -- двох хвилин вистачає з запасом на повільну мережу, а збіг орендаря
  -- робить хибне спрацювання практично неможливим.
  undo_window CONSTANT INTERVAL := INTERVAL '2 minutes';
  reopened    UUID;
  was_occupied BOOLEAN := (TG_OP = 'UPDATE' AND OLD.status = 'occupied');
  is_occupied  BOOLEAN := (NEW.status = 'occupied');
BEGIN
  -- ── ЗАКРИТТЯ ──────────────────────────────────────────────────────────────
  -- Факти беруться з OLD: та сама операція, що міняє статус, ОДНОЧАСНО
  -- обнуляє орендаря й дати, тож у NEW їх уже немає.
  IF was_occupied AND NOT is_occupied THEN
    UPDATE tenancies SET
      ended_at         = now(),
      tenant_name      = OLD.tenant_name,
      lease_start_date = OLD.lease_start_date,
      lease_end_date   = OLD.lease_end_date,
      rent_rate        = OLD.rent_rate,
      rent_type        = OLD.rent_type,
      utilities_rate   = OLD.utilities_rate,
      area_basis       = OLD.area_basis,
      area_useful      = OLD.area_useful,
      area_total       = OLD.area_total,
      landlord_name    = OLD.landlord_name,
      property_name    = OLD.name,
      updated_at       = now()
    WHERE property_id = NEW.id AND ended_at IS NULL;
    RETURN NEW;
  END IF;

  -- ── ВІДКРИТТЯ ─────────────────────────────────────────────────────────────
  IF is_occupied AND (TG_OP = 'INSERT' OR NOT was_occupied) THEN
    UPDATE tenancies SET ended_at = NULL, updated_at = now()
    WHERE id = (
      SELECT t.id FROM tenancies t
      WHERE t.property_id = NEW.id
        AND t.ended_at IS NOT NULL
        AND t.ended_at > now() - undo_window
        AND t.tenant_name IS NOT DISTINCT FROM NEW.tenant_name
      ORDER BY t.ended_at DESC
      LIMIT 1
    )
    RETURNING id INTO reopened;

    IF reopened IS NULL THEN
      INSERT INTO tenancies (
        owner_id, db_id, property_id, property_name, tenant_name, landlord_name,
        rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total,
        currency, lease_start_date, lease_end_date, started_at
      )
      SELECT
        NEW.owner_id, NEW.db_id, NEW.id, NEW.name, NEW.tenant_name, NEW.landlord_name,
        NEW.rent_rate, NEW.rent_type, NEW.utilities_rate, NEW.area_basis,
        NEW.area_useful, NEW.area_total,
        (SELECT u.currency FROM users u WHERE u.id = NEW.owner_id),
        NEW.lease_start_date, NEW.lease_end_date,
        COALESCE(NEW.lease_start_date::timestamptz, now());
    END IF;
    RETURN NEW;
  END IF;

  -- ── ЗМІНА ВСЕРЕДИНІ ОРЕНДИ ────────────────────────────────────────────────
  -- Перейменування орендаря при живій оренді НЕ ділить її надвоє, і це
  -- рішення, а не спрощення: у застосунку немає дії «замінити орендаря» —
  -- справжня зміна йде через звільнення й нову здачу. Розділяти тут означало
  -- б, що виправлення одруківки в імені ФАБРИКУЄ неіснуючі правовідносини.
  -- Відкритий рядок просто тримається в актуальному стані, тож на момент
  -- закриття він несе фінальні значення.
  IF was_occupied AND is_occupied THEN
    UPDATE tenancies SET
      tenant_name      = NEW.tenant_name,
      lease_start_date = NEW.lease_start_date,
      lease_end_date   = NEW.lease_end_date,
      rent_rate        = NEW.rent_rate,
      rent_type        = NEW.rent_type,
      utilities_rate   = NEW.utilities_rate,
      area_basis       = NEW.area_basis,
      area_useful      = NEW.area_useful,
      area_total       = NEW.area_total,
      landlord_name    = NEW.landlord_name,
      property_name    = NEW.name,
      updated_at       = now()
    WHERE property_id = NEW.id AND ended_at IS NULL;
  END IF;

  RETURN NEW;
END;
$$;

-- Правило 12 Security rules: дефолтний грант PUBLIC знімається ЯВНО. Тригерну
-- функцію не викликають напряму, але гард ACL сканує ВСІ SECURITY DEFINER.
REVOKE ALL ON FUNCTION public.sync_tenancy_on_property_change() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_sync_tenancy ON properties;
CREATE TRIGGER trg_sync_tenancy
  AFTER INSERT OR UPDATE OF status, tenant_name, lease_start_date, lease_end_date,
                            rent_rate, rent_type, utilities_rate, area_basis,
                            area_useful, area_total, landlord_name, name
  ON properties
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_tenancy_on_property_change();

-- ── Бекфіл ───────────────────────────────────────────────────────────────────
-- Без нього історія почалась би з нуля, а вже зайняті обʼєкти не мали б
-- ЖОДНОГО запису — тобто фіча виглядала б зламаною саме там, де в неї
-- найбільше даних (той самий урок, що з іменами гостей у 048).
INSERT INTO tenancies (
  owner_id, db_id, property_id, property_name, tenant_name, landlord_name,
  rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total,
  currency, lease_start_date, lease_end_date, started_at
)
SELECT
  p.owner_id, p.db_id, p.id, p.name, p.tenant_name, p.landlord_name,
  p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis,
  p.area_useful, p.area_total,
  (SELECT u.currency FROM users u WHERE u.id = p.owner_id),
  p.lease_start_date, p.lease_end_date,
  COALESCE(p.lease_start_date::timestamptz, p.created_at, now())
FROM properties p
WHERE p.status = 'occupied'
  AND NOT EXISTS (
    SELECT 1 FROM tenancies t WHERE t.property_id = p.id AND t.ended_at IS NULL
  );

-- ─────────────────────────────────────────────────────────────────────────
-- 068_tenancies_read_only.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 068 — архів оренд стає ЛИШЕ ДЛЯ ЧИТАННЯ з боку клієнтів
-- ═══════════════════════════════════════════════════════════════════════════
--
-- 067 завела `tenancies` з політиками FOR ALL (дзеркало `property_folders`).
-- Для папок це правильно — їх створюють і видаляють руками. Для архіву ні:
-- його цінність у тому, що він ПРАВДИВИЙ. Це історія правовідносин, до якої
-- повертаються при спорі з орендарем, і запис, який можна відредагувати,
-- доказом не є.
--
-- Конкретна діра, заміряна на живому Postgres (scripts/verify-rls.sql):
-- РЕДАКТОР команди — принципал, якого власник запрошує й відкликає, тобто
-- менш довірений — міг стерти ВЕСЬ архів власника одним DELETE або
-- переписати імена орендарів і суми. Власник так само міг «підправити»
-- власну історію заднім числом.
--
-- Клієнту запис не потрібен узагалі: `useTenancies` лише читає, а рядки
-- відкриває й закриває тригер `sync_tenancy_on_property_change()`, який є
-- SECURITY DEFINER і належить власнику таблиці — тобто RLS не проходить
-- взагалі. Стенд окремо доводить, що після цієї міграції тригер пише далі.
--
-- ДВА шари, і обидва потрібні:
--   1. політики — лише SELECT;
--   2. відкликані табличні права на запис. Без другого шару наступна
--      міграція, що «за зразком» додасть FOR ALL-політику, мовчки відкрила б
--      запис знову; з ним — додати політику недостатньо, треба ще й явний
--      GRANT, тобто рішення стає видимим у дифі.
--
-- Ідемпотентна: безпечна і на базі, де 067 застосована, і разом із нею в
-- одному накаті (supabase/RELEASE.sql).
-- ═══════════════════════════════════════════════════════════════════════════

DROP POLICY IF EXISTS "tenancies_owner_all"  ON tenancies;
DROP POLICY IF EXISTS "tenancies_editor_all" ON tenancies;

DROP POLICY IF EXISTS "tenancies_owner_select" ON tenancies;
CREATE POLICY "tenancies_owner_select" ON tenancies
  FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

-- Редактор БАЧИТЬ архів: він створює ті самі оренди, і ховати від нього
-- історію було б брехнею про те, хто що зробив. Але лише бачить.
DROP POLICY IF EXISTS "tenancies_editor_select" ON tenancies;
CREATE POLICY "tenancies_editor_select" ON tenancies
  FOR SELECT
  USING (db_id IN (SELECT get_editor_db_ids(current_app_user_id())));

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenancies FROM anon, authenticated;

-- ─────────────────────────────────────────────────────────────────────────
-- 069_access_integrity.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ═══════════════════════════════════════════════════════════════════════════
-- 069 — цілісність доступів: хто що отримує і що справді забирається
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Два дефекти, обидва знайдені ВИКОНАННЯМ на живому Postgres (не читанням),
-- обидва — сервер робить не те, що обіцяє інтерфейс.
--
-- ── 1. Гостьове запрошення ЗНИЖУВАЛО власника до гостя — назавжди ──────────
-- `claim_guest_link` робив `UPDATE users SET role = 'guest' … AND role = 'owner'`
-- для БУДЬ-якого власника. Захист стояв лише від клейму ВЛАСНОГО запрошення,
-- тож власник, що має бази і прийняв чуже запрошення (він же орендар деінде —
-- цілком звичайна ситуація), ставав `guest`. Таббар будує вкладки за роллю, а
-- в гостя їх три: «Обʼєкти», «Сповіщення», «Профіль». Тобто ВЛАСНІ бази
-- зникали з інтерфейсу — дані цілі (RLS не залежить від ролі), але дійти до
-- них нема як. Повернути роль не можна навіть самому:
-- `prevent_privilege_escalation` блокує guest→owner за будь-якого контексту
-- (заміряно: `role_escalation_blocked: guest→owner not allowed`).
--
-- Сусідній `subscribe_to_shared_db` (037/055) цю умову вже має:
-- `AND NOT EXISTS (SELECT 1 FROM databases d2 WHERE d2.owner_id = v_uid)`.
-- Правило знали — його просто не застосували в другій функції тієї ж родини.
--
-- Тіло нижче — точна копія 048, змінено РІВНО один предикат (урок 050:
-- контракт відповіді не чіпаємо, бо його читає перший екран запрошеного).
--
-- ── 2. «Відкликати доступ» не забирав доступу в тих, хто ВЖЕ підписався ────
-- Шит поширення обіцяє: «Усі, з ким ви ділились, втратять доступ». А
-- `manage_share(revoke|rotate)` міняв лише токен і термін. Доступ рієлтора ж
-- тримається не на токені, а на рядку `realtor_subscriptions`
-- (`get_realtor_db_ids` читає саме його), і цей рядок лишався. Заміряно:
-- рієлтор, що підписався до відкликання, після нього бачив і базу, і обʼєкти.
--
-- Гард `share-handoff` цього не бачив за побудовою: він перевіряв, що СТАРИЙ
-- токен не дає НОВОЇ підписки, а не те, що наявна підписка зникає.
--
-- Тепер rotate/revoke бази видаляють її підписки в тій самій транзакції.
-- СВІДОМО НЕ чіпає: `set_expiry` (термін — про ЛІНК, тобто про нові
-- приєднання; хто вже працює з базою, лишається) і команду (`db_members` —
-- окремий механізм із власним відкликанням). Обидва рішення закріплені
-- стендом, щоб зміна була видимою, а не випадковою.
--
-- ── Ремонт ─────────────────────────────────────────────────────────────────
-- Ті, кого вже знизило, лишились би гостями назавжди: виправлення функції
-- нікого не повертає. Ознака однозначна — роль `guest` при ≥1 ВЛАСНІЙ базі:
-- гостьовий інтерфейс створити базу не дає, тож іншого шляху в такий стан
-- немає. Тригер ескалації блокує й це оновлення, тож його вимикаємо на час
-- одного UPDATE — УМОВНО: якщо тригера в базі немає, ALTER інакше повалив би
-- весь RELEASE.sql (урок 024: прод має прогалини всередині 001-047).
--
-- Підписки на бази, відкликані ДО цієї міграції, НЕ чистяться: відкликання й
-- закінчення терміну в базі нерозрізненні (обидва — минулий
-- `share_expires_at`), а друге забирати доступ не повинно. Таких власників
-- варто попросити натиснути «Оновити посилання» ще раз.
--
-- Ідемпотентна.


CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
  v_name TEXT;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status, owner_id
  INTO v_link
  FROM guest_links
  WHERE invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_link.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  -- Owner must never claim their own invite: it would demote them to guest role,
  -- locking them out of all their databases with no client-side recovery path.
  IF v_uid = v_link.owner_id THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Already claimed by this user → idempotent success
  IF v_link.status = 'active' AND v_link.guest_user_id = v_uid THEN
    RETURN jsonb_build_object(
      'property_id', v_link.property_id,
      'db_id',       v_link.db_id
    );
  END IF;

  -- Already claimed by someone else
  IF v_link.status = 'active' AND v_link.guest_user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  SELECT NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
  INTO v_name
  FROM users u WHERE u.id = v_uid;

  UPDATE guest_links
  SET guest_user_id = v_uid,
      status        = 'active',
      claimed_at    = now(),
      guest_name    = v_name
  WHERE id = v_link.id;

  -- Гостем стає лише ДЕФОЛТНИЙ власник — той, хто жодної бази не створював
  -- (онбординг лишає `owner` за замовчуванням). Власника з базами не чіпаємо:
  -- гостьовий таббар не має «Баз», а назад роль не повертає ніщо (069).
  UPDATE users SET role = 'guest'
  WHERE id = v_uid
    AND role = 'owner'
    AND NOT EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = v_uid);

  RETURN jsonb_build_object(
    'property_id', v_link.property_id,
    'db_id',       v_link.db_id
  );
END;
$$;
REVOKE ALL ON FUNCTION claim_guest_link(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_guest_link(TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION manage_share(
  p_kind   TEXT,
  p_id     UUID,
  p_action TEXT,
  p_days   INT DEFAULT NULL
)
RETURNS TABLE (share_token TEXT, share_expires_at TIMESTAMPTZ, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid   UUID;
  v_owner UUID;
  v_tok   TEXT;
  v_exp   TIMESTAMPTZ;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'not_authenticated'::TEXT; RETURN;
  END IF;
  IF p_kind NOT IN ('db','prop','col') OR p_action NOT IN ('rotate','set_expiry','clear_expiry','revoke') THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;
  IF p_action = 'set_expiry' AND (p_days IS NULL OR p_days < 1 OR p_days > 365) THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    SELECT owner_id INTO v_owner FROM databases WHERE id = p_id FOR UPDATE;
  ELSIF p_kind = 'prop' THEN
    SELECT owner_id INTO v_owner FROM properties WHERE id = p_id FOR UPDATE;
  ELSE
    SELECT realtor_id INTO v_owner FROM collections WHERE id = p_id FOR UPDATE;
  END IF;

  IF v_owner IS NULL OR v_owner <> v_uid THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'forbidden'::TEXT; RETURN;
  END IF;

  -- 060: `revoke` тепер у списку дій, що ротують токен, поруч із `rotate`.
  IF p_kind = 'db' THEN
    UPDATE databases SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE databases.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE databases.share_expires_at
                         END
    WHERE id = p_id
    RETURNING databases.share_token, databases.share_expires_at INTO v_tok, v_exp;

    -- 069: доступ рієлтора тримається на підписці, а не на токені, тож без
    -- цього рядка «Усі, з ким ви ділились, втратять доступ» було неправдою.
    -- `set_expiry` підписок свідомо не чіпає — див. шапку.
    IF p_action IN ('rotate','revoke') THEN
      DELETE FROM realtor_subscriptions rs WHERE rs.db_id = p_id;
    END IF;
  ELSIF p_kind = 'prop' THEN
    UPDATE properties SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE properties.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE properties.share_expires_at
                         END
    WHERE id = p_id
    RETURNING properties.share_token, properties.share_expires_at INTO v_tok, v_exp;
  ELSE
    UPDATE collections SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE collections.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE collections.share_expires_at
                         END
    WHERE id = p_id
    RETURNING collections.share_token, collections.share_expires_at INTO v_tok, v_exp;
  END IF;

  RETURN QUERY SELECT v_tok, v_exp, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) TO authenticated, service_role;

-- ── Ремонт: повернути роль тим, кого вже знизило ───────────────────────────
-- Ознака — `guest` при ≥1 власній базі (див. шапку). Тригер ескалації вимкнено
-- рівно на один UPDATE і лише якщо він є: інакше ALTER повалив би файл.
DO $$
DECLARE
  has_trg BOOLEAN;
  n INT;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = 'public.users'::regclass
      AND tgname  = 'trg_prevent_privilege_escalation'
      AND NOT tgisinternal
  ) INTO has_trg;

  IF has_trg THEN
    EXECUTE 'ALTER TABLE public.users DISABLE TRIGGER trg_prevent_privilege_escalation';
  END IF;

  UPDATE public.users u SET role = 'owner'
  WHERE u.role = 'guest'
    AND EXISTS (SELECT 1 FROM public.databases d WHERE d.owner_id = u.id);
  GET DIAGNOSTICS n = ROW_COUNT;

  IF has_trg THEN
    EXECUTE 'ALTER TABLE public.users ENABLE TRIGGER trg_prevent_privilege_escalation';
  END IF;

  IF n > 0 THEN
    RAISE NOTICE '069: повернуто роль власника % користувачам, яких знизило гостьове запрошення', n;
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';


-- ─────────────────────────────────────────────────────────────────────────
-- 070_reminders_skip_paid.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 070 — нагадування про оплату НЕ йде, коли платіж уже підтверджено
-- ============================================================================
-- Знайдено аудитом розділу платежів. `get_due_reminders_today()` питає лише
-- «чи настав день нагадування» і «чи не нагадували цього місяця», але НЕ
-- питає, чи гроші вже прийшли. Орендар, що заплатив на тиждень раніше, а
-- власник це підтвердив, — і за три дні до дати власник однаково отримує в
-- Telegram «оплата через 3 дні». Гість (орендар) — те саме від гостьової
-- функції. Нагадування, що бреше про стан грошей, вчить їх ігнорувати.
--
-- Друга умова того самого класу: дата ДО початку договору. Обʼєкт, зданий
-- 10-го з днем оплати 5-го, у перший місяць не винен нічого (`isOwedUnderLease`
-- на клієнті це вже знає), а нагадування про «оплату 5-го» приходило.
--
-- Тіла перенесені з 058 ДОСЛІВНО (включно з 053-м `rp.owner_id = p.owner_id`,
-- 058-м `tg_id IS NOT NULL` і клампом дня місяця). Змінено одне: дата платежу
-- рахується РАЗ у `LATERAL`, бо тепер вона потрібна в трьох місцях, і
-- додано два предикати. Контракт результату той самий — `CREATE OR REPLACE`
-- без зміни типу (урок 42P13 з 044).
--
-- Посилання на колонки КВАЛІФІКОВАНІ: `due_date`, `property_id`, `owner_id` —
-- це ще й OUT-параметри функції, і неякісний `due_date` був би неоднозначним
-- (урок 055).
-- ============================================================================


CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         d.due
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  CROSS JOIN LATERAL (
    SELECT make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    ) AS due
  ) d
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND u.tg_id IS NOT NULL        -- 058: інакше вічний щоденний ретрай
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    -- 070: до початку договору платежу немає.
    AND (p.lease_start_date IS NULL OR d.due >= p.lease_start_date)
    -- 070: гроші вже прийшли — нагадувати нема про що.
    AND NOT EXISTS (
      SELECT 1 FROM rent_payment_records r
      WHERE r.property_id = rp.property_id
        AND r.due_date = d.due
        AND r.status = 'paid'
    )
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;

CREATE OR REPLACE FUNCTION get_due_guest_reminders()
RETURNS TABLE (
  guest_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT DISTINCT ON (u.id, rp.property_id)
    u.id, u.tg_id, rp.property_id,
    p.name::TEXT,
    rp.due_day::INT,
    d.due
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN guest_links gl ON (gl.property_id = rp.property_id OR gl.db_id = p.db_id)
                      AND gl.status = 'active'
  JOIN users u ON u.id = gl.guest_user_id
  CROSS JOIN LATERAL (
    SELECT make_date(
      EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
      LEAST(
        rp.due_day,
        EXTRACT(DAY FROM (
          DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
          + INTERVAL '1 month' - INTERVAL '1 day'
        ))::INT
      )
    ) AS due
  ) d
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND u.tg_id IS NOT NULL        -- 058: див. вище
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND (p.lease_start_date IS NULL OR d.due >= p.lease_start_date)   -- 070
    AND NOT EXISTS (                                                   -- 070
      SELECT 1 FROM rent_payment_records r
      WHERE r.property_id = rp.property_id
        AND r.due_date = d.due
        AND r.status = 'paid'
    )
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = u.id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    )
  ORDER BY u.id, rp.property_id;
END;
$$;

REVOKE ALL ON FUNCTION get_due_reminders_today()  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_due_guest_reminders()  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;
GRANT EXECUTE ON FUNCTION get_due_guest_reminders() TO service_role;


NOTIFY pgrst, 'reload schema';

-- ─────────────────────────────────────────────────────────────────────────
-- 071_partial_payments.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 071 — ЧАСТКОВА ОПЛАТА: платіж за період складається з НАДХОДЖЕНЬ
-- ============================================================================
-- Доти `rent_payment_records` мав рівно один стан «отримано»: рядок на
-- (обʼєкт, дату платежу) зі статусом `paid` і сумою. Орендар, що заплатив
-- $1 000 із $1 800, давав власнику два погані варіанти: підтвердити як
-- `paid` (і борг $800 зникав з календаря, лічильника й нагадувань) або не
-- підтверджувати (і $1 000, які вже в кишені, не існували для архіву).
--
-- МОДЕЛЬ: рядок `rent_payment_records` лишається ПЕРІОДОМ (нарахуванням), а
-- гроші, що прийшли, — окремі НАДХОДЖЕННЯ в `rent_payment_parts`, кожне зі
-- своєю датою й приміткою. Підсумок періоду (`amount`, `paid_at`, `status`)
-- рахує СЕРВЕР тригером, а не клієнт:
--   * сума надходжень ≥ `amount_due`  → `paid`;
--   * більше нуля, але менше          → `partial`;
--   * надходжень немає                → `pending` (024 зробить `overdue`).
--
-- ЧОМУ ТАК, А НЕ «ОДНА СУМА, ЯКУ ДОПИСУЮТЬ». Дописування втрачає ДАТИ
-- надходжень («коли він доплатив?» — перше питання будь-якої суперечки), а
-- читання-зміна-запис з двох пристроїв (власник і редактор) губить одне з
-- надходжень. Тут сума — агрегат під блокуванням рядка періоду.
--
-- ЧОМУ ВСІ НАЯВНІ СПОЖИВАЧІ НЕ ЛАМАЮТЬСЯ. `amount` лишається «скільки
-- отримано за період», `status = 'paid'` лишається «закрито повністю». Тобто
-- календар, нагадування (070 пропускає лише `paid`), архів оренд — усі
-- читають той самий контракт; частковий період для них просто НЕ закритий.
--
-- `amount_due` — ЗАМОРОЖЕНА очікувана сума. Ставка оренди змінюється, і
-- старий період, порахований за новою ставкою, раптом ставав би «частковим»
-- (або «закритим») заднім числом. Тому сума фіксується в мить ПЕРШОГО
-- надходження і далі не рухається. NULL — очікуване невідоме (обʼєкт без
-- ставки): тоді будь-яке надходження закриває період, як і доти.
-- ============================================================================


-- ── 1. Період: заморожена очікувана сума і стан «частково» ─────────────────
ALTER TABLE rent_payment_records ADD COLUMN IF NOT EXISTS amount_due NUMERIC(12,2);

-- Імʼя CHECK-обмеження автозгенероване (021/023 оголошували його інлайном),
-- тож шукаємо за ВИЗНАЧЕННЯМ, а не за назвою: у базі, накоченій вручну, воно
-- могло назватись інакше (урок 055 — не покладатись на автоімена).
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'public.rent_payment_records'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ~* 'status'
  LOOP
    EXECUTE format('ALTER TABLE public.rent_payment_records DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

ALTER TABLE rent_payment_records ADD CONSTRAINT rent_payment_records_status_check
  CHECK (status IN ('pending', 'paid', 'overdue', 'partial'));

-- ── 2. Надходження ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rent_payment_parts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- CASCADE: «Скасувати платіж» у календарі видаляє ПЕРІОД, і надходження
  -- без періоду не мають сенсу — їх ніде показати.
  record_id   UUID NOT NULL REFERENCES rent_payment_records(id) ON DELETE CASCADE,
  amount      NUMERIC(12,2) NOT NULL CHECK (amount > 0 AND amount <= 10000000000),
  paid_at     TIMESTAMPTZ NOT NULL,
  notes       TEXT CHECK (notes IS NULL OR char_length(notes) <= 200),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rent_payment_parts_record ON rent_payment_parts(record_id, paid_at);

ALTER TABLE rent_payment_parts ENABLE ROW LEVEL SECURITY;

-- Ціль перевіряється на ОБОХ боках (правило 11): надходження можна вписати
-- лише в період обʼєкта, яким ти володієш або який редагуєш. Знати
-- `record_id` чужого платежу недостатньо — підзапит іде під RLS періодів і
-- ще й явно фільтрується по власних обʼєктах.
--
-- Гостя й рієлтора тут свідомо НЕМАЄ: жоден клієнтський екран не показує їм
-- надходжень, а найменші права — ті, яких не видали.
DROP POLICY IF EXISTS "parts_owner_all"  ON rent_payment_parts;
DROP POLICY IF EXISTS "parts_editor_all" ON rent_payment_parts;

CREATE POLICY "parts_owner_all" ON rent_payment_parts
  FOR ALL
  USING (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  ))
  WITH CHECK (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  ));

CREATE POLICY "parts_editor_all" ON rent_payment_parts
  FOR ALL
  USING (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
  ))
  WITH CHECK (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
  ));

-- Анонімові таблиця не потрібна ні для чого; RLS його й так не пустить, але
-- дефолтні права Supabase видають запис УСІМ ролям — знімаємо явно, щоб
-- рішення було видно в дифі (той самий хід, що 068).
REVOKE ALL ON rent_payment_parts FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON rent_payment_parts TO authenticated;

-- ── 3. Підсумок періоду рахує сервер ───────────────────────────────────────
-- SECURITY INVOKER — і це свідомо, на відміну від тригера оренд (067). Сюди
-- потрапляє лише той, кого вже пропустила політика надходжень, а вона
-- вимагає права на обʼєкт; оновлення періоду під ТИМИ САМИМИ правами не
-- розширює нічого. Definer тут був би зайвим периметром.
--
-- Логіка ВБУДОВАНА в тригер, а не винесена в окрему функцію: вкладений виклик
-- перевіряє EXECUTE у ПОТОЧНОГО користувача, тобто окрему функцію довелось би
-- видати `authenticated` — ще одна точка входу, якої ніхто не просив.
CREATE OR REPLACE FUNCTION public.sync_rent_record_from_parts()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_ids  UUID[];
  v_rid  UUID;
  v_due  NUMERIC;
  v_n    INT;
  v_sum  NUMERIC;
  v_last TIMESTAMPTZ;
BEGIN
  -- Перенесене надходження міняє ДВА періоди: той, звідки, і той, куди.
  IF TG_OP = 'INSERT' THEN v_ids := ARRAY[NEW.record_id];
  ELSIF TG_OP = 'DELETE' THEN v_ids := ARRAY[OLD.record_id];
  ELSIF NEW.record_id IS DISTINCT FROM OLD.record_id THEN v_ids := ARRAY[OLD.record_id, NEW.record_id];
  ELSE v_ids := ARRAY[NEW.record_id];
  END IF;

  FOREACH v_rid IN ARRAY v_ids LOOP
    -- БЛОКУВАННЯ ПЕРІОДУ ПЕРЕД АГРЕГАТОМ. Два надходження з двох пристроїв
    -- (власник і редактор) інакше рахували б суму кожен у своєму знімку, і
    -- той, хто записав ОСТАННІМ, затер би чуже надходження з підсумку. Після
    -- блокування наступний SELECT у READ COMMITTED бере свіжий знімок і
    -- бачить уже закомічене.
    SELECT amount_due INTO v_due FROM rent_payment_records WHERE id = v_rid FOR UPDATE;
    -- Періоду немає — його саме видаляють (каскад «Скасувати платіж»), і
    -- оновлювати нічого.
    CONTINUE WHEN NOT FOUND;

    SELECT count(*), COALESCE(sum(amount), 0), max(paid_at)
      INTO v_n, v_sum, v_last
      FROM rent_payment_parts WHERE record_id = v_rid;

    IF v_n = 0 THEN
      UPDATE rent_payment_records
         SET amount = NULL, paid_at = NULL, status = 'pending', updated_at = now()
       WHERE id = v_rid;
    ELSE
      UPDATE rent_payment_records
         SET amount = v_sum, paid_at = v_last,
             status = CASE WHEN v_due IS NULL OR v_sum >= v_due THEN 'paid' ELSE 'partial' END,
             updated_at = now()
       WHERE id = v_rid;
    END IF;
  END LOOP;

  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.sync_rent_record_from_parts() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_sync_rent_record_from_parts ON rent_payment_parts;
CREATE TRIGGER trg_sync_rent_record_from_parts
  AFTER INSERT OR UPDATE OR DELETE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.sync_rent_record_from_parts();

-- ── 4. Одна дія клієнта — один виклик ──────────────────────────────────────
-- «Отримав гроші» = створити період, якщо його ще немає (із ЗАМОРОЖЕНОЮ
-- очікуваною сумою), і вписати надходження. Двома запитами з клієнта це не
-- атомарно: збій другого лишав би порожній період. Тут обидва кроки — одна
-- транзакція.
--
-- SECURITY INVOKER: усі права перевіряє RLS (періоду — політики 041/053,
-- надходження — політики вище). UUID обʼєкта тут НЕ є ключем доступу, тож
-- IDOR-клас (§5 Audit playbook) не виникає; anon не має EXECUTE узагалі.
--
-- Наявний період свою `amount_due` НЕ міняє: заморожена сума — це сенс
-- заморожування. Тому `p_amount_due` діє лише на НОВИЙ період.
CREATE OR REPLACE FUNCTION public.record_rent_payment(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount      NUMERIC,
  p_paid_at     TIMESTAMPTZ,
  p_notes       TEXT DEFAULT NULL,
  p_amount_due  NUMERIC DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_owner UUID;
  v_rid   UUID;
  v_part  UUID;
  v_rec   RECORD;
BEGIN
  IF p_amount IS NULL OR p_amount <= 0 OR p_amount > 10000000000 THEN
    RETURN jsonb_build_object('error', 'invalid_amount');
  END IF;
  -- День наперед — запас на пояс: локальна північ Києва — це ще вчора в UTC.
  IF p_paid_at IS NULL OR p_paid_at > now() + INTERVAL '1 day' THEN
    RETURN jsonb_build_object('error', 'invalid_date');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  INSERT INTO rent_payment_records (property_id, owner_id, due_date, amount_due, status)
  VALUES (p_property_id, v_owner, p_due_date,
          CASE WHEN p_amount_due > 0 THEN round(p_amount_due, 2) END, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Період, підтверджений СТАРИМ клієнтом уже після міграції (кешована
  -- вкладка в Telegram пише `status='paid'` + суму напряму, без надходжень).
  -- Без цього кроку перше ж нове надходження перерахувало б суму з нуля, і
  -- отримані раніше гроші зникли б із підсумку. Той самий перенос, що й
  -- бекфіл нижче, — лише для одного періоду й у тій самій транзакції.
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  SELECT r.id, round(r.amount::NUMERIC, 2),
         COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
         NULLIF(btrim(left(r.notes, 200)), '')
    FROM rent_payment_records r
   WHERE r.id = v_rid AND r.status IN ('paid', 'partial') AND r.amount > 0
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  VALUES (v_rid, round(p_amount, 2), p_paid_at, NULLIF(btrim(p_notes), ''))
  RETURNING id INTO v_part;

  SELECT r.status, r.amount, r.amount_due INTO v_rec
    FROM rent_payment_records r WHERE r.id = v_rid;

  RETURN jsonb_build_object(
    'record_id',  v_rid,
    'part_id',    v_part,
    'status',     v_rec.status,
    'amount',     v_rec.amount,
    'amount_due', v_rec.amount_due,
    'error',      NULL
  );
END;
$$;

-- Правило 12: дефолтний PUBLIC знімається ДО гранту, інакше функція
-- лишається викликабельною з anon-ключа.
REVOKE ALL ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC) TO authenticated;

-- ── 5. Наявні підтвердження стають надходженнями ───────────────────────────
-- Без цього кожен уже підтверджений платіж виглядав би «отриманим без
-- жодного надходження», а перше ж редагування (додати частину) перерахувало
-- б суму з нуля. Очікувана сума такого періоду = отримана: він уже був
-- закритий, і заднім числом робити його частковим не можна.
--
-- Ідемпотентно: лише періоди без жодного надходження.
UPDATE rent_payment_records r
   SET amount_due = round(r.amount::NUMERIC, 2)
 WHERE r.status = 'paid' AND r.amount > 0 AND r.amount_due IS NULL
   AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
SELECT r.id, round(r.amount::NUMERIC, 2),
       COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
       NULLIF(btrim(left(r.notes, 200)), '')
  FROM rent_payment_records r
 WHERE r.status = 'paid' AND r.amount > 0
   AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

NOTIFY pgrst, 'reload schema';


-- ─────────────────────────────────────────────────────────────────────────
-- 072_rent_terms_history.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 072 — УМОВИ ОРЕНДИ В ЧАСІ: борг рахується за ставкою, що ДІЯЛА тоді
-- ============================================================================
-- ЩО ЛІКУЄ. Очікувана сума неоплаченого періоду рахувалась із ПОТОЧНОЇ
-- ставки обʼєкта. Підняв оренду з $1 800 до $2 000 у жовтні — і серпневий
-- борг, якого ще не сплатили, теж ставав $2 000. Тобто зміна ставки
-- переписувала минулі борги заднім числом, і саме в ту суму, про яку
-- сперечаються з орендарем. 071 заморожує суму лише в мить ПЕРШОГО
-- надходження — до нього період був беззахисним.
--
-- ДВІ РЕЧІ, і друга — не «заодно»:
--
--   1. ІСТОРІЯ УМОВ. Тригер записує СТАРІ умови (ставка, тип, площі, база
--      розрахунку) в мить, коли вони змінились, з міткою `valid_until`.
--      Умови на дату D = найраніший рядок, що діяв після D; якщо такого
--      немає — поточні умови обʼєкта. Формула грошей при цьому лишається В
--      ОДНОМУ МІСЦІ (клієнтська `expectedRent`): сервер зберігає ФАКТИ, а не
--      рахує суми, тож дрейфу між двома реалізаціями формули бути не може.
--
--   2. СУМА ЗА КОНКРЕТНИЙ ПЕРІОД (`set_rent_amount_due`). Історія НЕ
--      розрізняє «підняв ставку» і «виправив описку»: обидва — зміна. Без
--      виходу виправлена описка ($18 000 → $1 800) лишила б серпень із
--      очікуваними $18 000, тобто вічним «частковим» боргом — і навіть
--      «Скасувати платіж» не допоміг би, бо повторний запис знову взяв би
--      ставку з історії. Той самий вихід потрібен і без описок: неповний
--      перший місяць (заїхав 18-го), знижка, домовленість — сума періоду
--      відрізняється від ставки законно.
--
-- ЧЕСНА МЕЖА. Історія починається з цієї міграції: як змінювалась ставка
-- ДОТИ, ніде не записано, тож для старих періодів діє поточна ставка — як і
-- було. Вигадувати минуле з архіву оренд не можна: він фіксує ставку на
-- кінець ОРЕНДИ, а не на кожну дату.
-- ============================================================================


-- ── 1. Історія ─────────────────────────────────────────────────────────────
-- CASCADE: історія умов має сенс лише разом із платежами обʼєкта, а ті
-- видаляються з ним (021). Архів правовідносин живе окремо (067) і власну
-- ставку на момент закриття оренди зберігає сам.
CREATE TABLE IF NOT EXISTS property_rent_terms (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id    UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  rent_rate      DOUBLE PRECISION,
  rent_type      TEXT,
  utilities_rate DOUBLE PRECISION,
  area_basis     TEXT,
  area_useful    DOUBLE PRECISION,
  area_total     DOUBLE PRECISION,
  -- Мить, до якої ці умови ДІЯЛИ (тобто мить зміни).
  valid_until    TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE property_rent_terms ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_property_rent_terms_prop
  ON property_rent_terms (property_id, valid_until);

-- ── RLS: бачать ті, хто бачить платежі; писати не може НІХТО з клієнтів ───
-- Урок 068: історія цінна тим, що правдива. Запис, який власник чи редактор
-- може «підправити», доказом при суперечці не є, а редактор — принципал,
-- якого запрошують і відкликають. Рядки пише лише тригер (SECURITY DEFINER).
DROP POLICY IF EXISTS "rent_terms_owner_select"  ON property_rent_terms;
CREATE POLICY "rent_terms_owner_select" ON property_rent_terms
  FOR SELECT
  USING (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

DROP POLICY IF EXISTS "rent_terms_editor_select" ON property_rent_terms;
CREATE POLICY "rent_terms_editor_select" ON property_rent_terms
  FOR SELECT
  USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())));

-- Другий шар (068): без явного GRANT майбутня «політика за зразком» не
-- відкриє запис мовчки.
REVOKE ALL ON property_rent_terms FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON property_rent_terms FROM authenticated;
GRANT SELECT ON property_rent_terms TO authenticated;

-- ── Тригер ───────────────────────────────────────────────────────────────
-- SECURITY DEFINER — той самий випадок, що 067: службовий облік, усі
-- значення з OLD, вводу ззовні немає. Редактор міняє ставку під своїми
-- правами на `properties`, а запис в історію не впирається в його політику
-- (якої для запису й немає).
CREATE OR REPLACE FUNCTION public.record_rent_terms_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO property_rent_terms (
    property_id, rent_rate, rent_type, utilities_rate,
    area_basis, area_useful, area_total, valid_until
  ) VALUES (
    OLD.id, OLD.rent_rate, OLD.rent_type, OLD.utilities_rate,
    OLD.area_basis, OLD.area_useful, OLD.area_total, now()
  );
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.record_rent_terms_change() FROM PUBLIC;

-- `WHEN`, а не лише `UPDATE OF`: форма шле ВСІ поля при кожному збереженні,
-- тож `UPDATE OF` спрацьовує і тоді, коли ставку ніхто не чіпав. Без умови
-- кожне перейменування обʼєкта плодило б рядок «змін», яких не було.
DROP TRIGGER IF EXISTS trg_record_rent_terms ON properties;
CREATE TRIGGER trg_record_rent_terms
  AFTER UPDATE OF rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total
  ON properties
  FOR EACH ROW
  WHEN (
       OLD.rent_rate      IS DISTINCT FROM NEW.rent_rate
    OR OLD.rent_type      IS DISTINCT FROM NEW.rent_type
    OR OLD.utilities_rate IS DISTINCT FROM NEW.utilities_rate
    OR OLD.area_basis     IS DISTINCT FROM NEW.area_basis
    OR OLD.area_useful    IS DISTINCT FROM NEW.area_useful
    OR OLD.area_total     IS DISTINCT FROM NEW.area_total
  )
  EXECUTE FUNCTION public.record_rent_terms_change();

-- ── 2. Сума за конкретний період ───────────────────────────────────────────
-- SECURITY INVOKER, як і `record_rent_payment` (071): права перевіряє RLS
-- періодів і надходжень, тож чужий обʼєкт тут просто невидимий. UUID обʼєкта
-- не є ключем доступу — IDOR-клас (§5) не виникає; anon EXECUTE не має.
--
-- Підсумок рахується тут же, а не тригером: тригер 071 висить на
-- НАДХОДЖЕННЯХ, а тут міняється сам період. Логіка та сама — сума
-- надходжень проти очікуваної — під блокуванням рядка періоду.
CREATE OR REPLACE FUNCTION public.set_rent_amount_due(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount_due  NUMERIC
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_owner  UUID;
  v_rid    UUID;
  v_due    NUMERIC := round(p_amount_due, 2);
  v_n      INT;
  v_sum    NUMERIC;
  v_status TEXT;
BEGIN
  IF p_amount_due IS NULL OR p_amount_due <= 0 OR p_amount_due > 10000000000 THEN
    RETURN jsonb_build_object('error', 'invalid_amount');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Сума ставиться ОКРЕМИМ UPDATE нижче, а не тут, навіть для нового
  -- періоду: так зміна суми — завжди зміна рядка, і журнал змін (073) бачить
  -- її однаково, був період до того чи ні.
  INSERT INTO rent_payment_records (property_id, owner_id, due_date, status)
  VALUES (p_property_id, v_owner, p_due_date, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date
   FOR UPDATE;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Період, підтверджений СТАРИМ клієнтом (сума без надходжень), — той самий
  -- перенос, що в `record_rent_payment`: інакше перерахунок нижче не побачив
  -- би отриманих грошей і назвав би оплачений період неоплаченим.
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  SELECT r.id, round(r.amount::NUMERIC, 2),
         COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
         NULLIF(btrim(left(r.notes, 200)), '')
    FROM rent_payment_records r
   WHERE r.id = v_rid AND r.status IN ('paid', 'partial') AND r.amount > 0
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

  SELECT count(*), COALESCE(sum(amount), 0) INTO v_n, v_sum
    FROM rent_payment_parts WHERE record_id = v_rid;

  v_status := CASE WHEN v_n = 0 THEN 'pending'
                   WHEN v_sum >= v_due THEN 'paid'
                   ELSE 'partial' END;

  UPDATE rent_payment_records
     SET amount_due = v_due, status = v_status, updated_at = now()
   WHERE id = v_rid;

  RETURN jsonb_build_object(
    'record_id',  v_rid,
    'status',     v_status,
    'amount_due', v_due,
    'error',      NULL
  );
END;
$$;

REVOKE ALL ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) TO authenticated;

NOTIFY pgrst, 'reload schema';


-- ─────────────────────────────────────────────────────────────────────────
-- 073_db_activity.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 073 — ХТО ЩО ЗРОБИВ: автор надходження і журнал змін бази
-- ============================================================================
-- ЩО ЛІКУЄ. Команда (041) дала редакторам право писати в базу власника:
-- обʼєкти, ставки, орендарів, гроші. Але жоден рядок не відповідав на
-- питання «хто це зробив». Власник бачив, що ставку змінили, обʼєкт
-- видалили, а надходження $1 000 «записане» — і не мав як дізнатись, ким.
-- Для обліку грошей у команді це перше питання будь-якої розбіжності.
--
-- ДВІ ЧАСТИНИ:
--
--   1. АВТОР НАДХОДЖЕННЯ — колонки на самому `rent_payment_parts`. Ставить
--      ТРИГЕР, а не клієнт: значення з тіла запиту — це те, що клієнт
--      захотів написати, і редактор міг би «записати» гроші від імені
--      власника. Тригер перезаписує будь-що з тіла, а на UPDATE тримає
--      старе — автор не міняється від виправлення суми.
--
--   2. ЖУРНАЛ ЗМІН БАЗИ — `db_activity`. Пишуть ЛИШЕ тригери (SECURITY
--      DEFINER), клієнтам — лише читання (урок 068: журнал, який можна
--      підправити, доказом не є). Подія ПІДСУМКОВА, а не сирий діф: «Здано
--      в оренду: ТОВ Х» замість семи змінених колонок, і ім'я дійової особи
--      заморожене в рядку — переживає вихід людини з команди.
--
-- ЩО СВІДОМО НЕ ПИШЕТЬСЯ:
--   * дії без особи (крон, міграції, service-role) — це не «хтось зробив»;
--   * каскади: видалили обʼєкт — це ОДНА подія, а не ще десять «видалено
--     надходження / документ / розклад» під ним;
--   * шум без змісту: порядок, папки, опис, додавання фото (пакет із 20
--     знімків дав би 20 рядків). Видалення фото — пишеться: воно незворотне.
--
-- ЖУРНАЛ НЕ СМІЄ ЛАМАТИ ДІЮ. Будь-яка помилка запису події ковтається з
-- WARNING: втрачений рядок журналу — прикро, а «не вдалося зберегти
-- платіж» через журнал — неприпустимо. Це журнал змін, а не механізм
-- безпеки; права, як і доти, тримає RLS.
-- ============================================================================


-- ── 1. Автор надходження ───────────────────────────────────────────────────
ALTER TABLE rent_payment_parts
  ADD COLUMN IF NOT EXISTS created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_by_name TEXT;

CREATE OR REPLACE FUNCTION public.stamp_rent_part_author()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    NEW.created_by      := OLD.created_by;
    NEW.created_by_name := OLD.created_by_name;
    RETURN NEW;
  END IF;

  -- Перенесене підтвердження СТАРОГО клієнта (071: сума на періоді без
  -- надходжень стає першим надходженням). Гроші вписав хтось раніше, і
  -- приписати їх тому, чия дія спричинила перенос, було б неправдою.
  -- Звичайний перший платіж періоду так не виглядає: період без надходжень
  -- має порожню суму (її обнуляє тригер 071).
  IF EXISTS (SELECT 1 FROM rent_payment_records r
              WHERE r.id = NEW.record_id AND r.amount > 0
                AND r.status IN ('paid', 'partial'))
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = NEW.record_id) THEN
    NEW.created_by      := NULL;
    NEW.created_by_name := NULL;
    RETURN NEW;
  END IF;

  NEW.created_by      := NULL;
  NEW.created_by_name := NULL;
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO NEW.created_by, NEW.created_by_name
    FROM users u WHERE u.id = current_app_user_id();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.stamp_rent_part_author() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_stamp_rent_part_author ON rent_payment_parts;
CREATE TRIGGER trg_stamp_rent_part_author
  BEFORE INSERT OR UPDATE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.stamp_rent_part_author();

-- ── 2. Журнал ──────────────────────────────────────────────────────────────
-- `db_id` CASCADE: журнал живе в базі. `property_id` SET NULL: подія про
-- видалений обʼєкт лишається — назва заморожена в рядку.
CREATE TABLE IF NOT EXISTS db_activity (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id         UUID NOT NULL REFERENCES databases(id)  ON DELETE CASCADE,
  property_id   UUID          REFERENCES properties(id) ON DELETE SET NULL,
  property_name TEXT,
  actor_id      UUID          REFERENCES users(id)      ON DELETE SET NULL,
  actor_name    TEXT,
  kind          TEXT NOT NULL CHECK (kind IN (
    'property_created', 'property_deleted', 'property_renamed', 'property_moved',
    'property_rented', 'property_vacated', 'property_status', 'tenant_changed',
    'terms_changed',
    'payment_received', 'payment_edited', 'payment_deleted', 'payment_cancelled',
    'due_changed', 'schedule_set', 'schedule_deleted',
    'file_added', 'file_deleted', 'photo_deleted'
  )),
  details       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE db_activity ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_db_activity_db ON db_activity (db_id, created_at DESC, id DESC);

-- Бачать ті, хто веде базу: власник і редактор. Редактор бачить і чужі
-- дії, і власні — журнал, у якому видно лише себе, нічого не пояснює.
-- Рієлтор і гість — ні: це внутрішня кухня власника.
DROP POLICY IF EXISTS "activity_owner_select"  ON db_activity;
CREATE POLICY "activity_owner_select" ON db_activity
  FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

DROP POLICY IF EXISTS "activity_editor_select" ON db_activity;
CREATE POLICY "activity_editor_select" ON db_activity
  FOR SELECT
  USING (db_id IN (SELECT get_editor_db_ids(current_app_user_id())));

REVOKE ALL ON db_activity FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON db_activity FROM authenticated;
GRANT SELECT ON db_activity TO authenticated;

-- Один запис події. Не видається НІКОМУ: його кличуть лише тригери нижче,
-- які є SECURITY DEFINER і виконуються від власника функцій.
CREATE OR REPLACE FUNCTION public.log_db_activity(
  p_db_id         UUID,
  p_property_id   UUID,
  p_property_name TEXT,
  p_kind          TEXT,
  p_details       JSONB
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_uid  UUID;
  v_name TEXT;
BEGIN
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO v_uid, v_name
    FROM users u WHERE u.id = current_app_user_id();
  -- Без особи — не «хтось зробив», а система: крон, міграція, service-role.
  IF v_uid IS NULL OR p_db_id IS NULL THEN RETURN; END IF;
  -- Базу саме видаляють (каскад) — писати нікуди, і вставка впала б на FK.
  IF NOT EXISTS (SELECT 1 FROM databases d WHERE d.id = p_db_id) THEN RETURN; END IF;

  INSERT INTO db_activity (db_id, property_id, property_name, actor_id, actor_name, kind, details)
  VALUES (
    p_db_id,
    CASE WHEN p_property_id IS NOT NULL
          AND EXISTS (SELECT 1 FROM properties p WHERE p.id = p_property_id)
         THEN p_property_id END,
    p_property_name, v_uid, v_name, p_kind, COALESCE(p_details, '{}'::jsonb)
  );
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'db_activity: подію % не записано (%)', p_kind, SQLERRM;
END;
$$;

REVOKE ALL ON FUNCTION public.log_db_activity(UUID, UUID, TEXT, TEXT, JSONB) FROM PUBLIC;

-- ── Обʼєкти ────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_property()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_terms_old JSONB;
  v_terms_new JSONB;
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_created',
      jsonb_build_object('status', NEW.status));
    RETURN NULL;
  END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM log_db_activity(OLD.db_id, NULL, OLD.name, 'property_deleted',
      jsonb_build_object('tenant', OLD.tenant_name));
    RETURN NULL;
  END IF;

  -- Переміщення — подія в ОБОХ базах: у старій обʼєкт зник, у новій зʼявився.
  IF NEW.db_id IS DISTINCT FROM OLD.db_id THEN
    PERFORM log_db_activity(OLD.db_id, NEW.id, NEW.name, 'property_moved',
      jsonb_build_object('direction', 'out', 'db', (SELECT d.name FROM databases d WHERE d.id = NEW.db_id)));
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_moved',
      jsonb_build_object('direction', 'in', 'db', (SELECT d.name FROM databases d WHERE d.id = OLD.db_id)));
  END IF;

  IF NEW.name IS DISTINCT FROM OLD.name THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_renamed',
      jsonb_build_object('from', OLD.name, 'to', NEW.name));
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'occupied' THEN
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_rented',
        jsonb_build_object('tenant', NEW.tenant_name, 'lease_start', NEW.lease_start_date, 'lease_end', NEW.lease_end_date));
    ELSIF OLD.status = 'occupied' THEN
      -- Орендар — з OLD: та сама операція обнуляє його в NEW (той самий
      -- урок, що в тригері оренд 067).
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_vacated',
        jsonb_build_object('tenant', OLD.tenant_name, 'to', NEW.status));
    ELSE
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_status',
        jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
  ELSIF NEW.status = 'occupied' AND NEW.tenant_name IS DISTINCT FROM OLD.tenant_name THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'tenant_changed',
      jsonb_build_object('from', OLD.tenant_name, 'to', NEW.tenant_name));
  END IF;

  v_terms_old := jsonb_build_object('rent_rate', OLD.rent_rate, 'rent_type', OLD.rent_type,
    'utilities_rate', OLD.utilities_rate, 'area_basis', OLD.area_basis,
    'area_useful', OLD.area_useful, 'area_total', OLD.area_total);
  v_terms_new := jsonb_build_object('rent_rate', NEW.rent_rate, 'rent_type', NEW.rent_type,
    'utilities_rate', NEW.utilities_rate, 'area_basis', NEW.area_basis,
    'area_useful', NEW.area_useful, 'area_total', NEW.area_total);
  IF v_terms_old IS DISTINCT FROM v_terms_new THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'terms_changed',
      jsonb_build_object('from', v_terms_old, 'to', v_terms_new));
  END IF;

  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_property() FROM PUBLIC;

-- Список колонок обовʼязковий: перестановка порядку (`sort_order`) і папки
-- міняють десятки рядків за раз, і тригер на кожен з них був би марною
-- роботою — подій там немає.
DROP TRIGGER IF EXISTS trg_activity_property ON properties;
CREATE TRIGGER trg_activity_property
  AFTER INSERT OR DELETE OR UPDATE OF
    db_id, name, status, tenant_name,
    rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total
  ON properties
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property();

-- ── Надходження ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_part()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_rec RECORD;
BEGIN
  SELECT r.due_date, p.id AS property_id, p.db_id, p.name INTO v_rec
    FROM rent_payment_records r JOIN properties p ON p.id = r.property_id
   WHERE r.id = COALESCE(NEW.record_id, OLD.record_id);
  -- Періоду чи обʼєкта вже немає — це каскад, і його подію вже записано
  -- вище («Скасовано платіж», «Видалено обʼєкт»).
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'INSERT' THEN
    -- Без автора — перенесене підтвердження старого клієнта (див. штамп):
    -- це не нова дія, а запис про гроші, які прийшли раніше.
    IF NEW.created_by IS NULL THEN RETURN NULL; END IF;
    PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_received',
      jsonb_build_object('due_date', v_rec.due_date, 'amount', NEW.amount, 'paid_at', NEW.paid_at));
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.amount IS DISTINCT FROM OLD.amount OR NEW.paid_at IS DISTINCT FROM OLD.paid_at THEN
      PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_edited',
        jsonb_build_object('due_date', v_rec.due_date, 'from', OLD.amount, 'to', NEW.amount,
                           'from_paid_at', OLD.paid_at, 'to_paid_at', NEW.paid_at));
    END IF;
  ELSE
    PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_deleted',
      jsonb_build_object('due_date', v_rec.due_date, 'amount', OLD.amount));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_part() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_part ON rent_payment_parts;
CREATE TRIGGER trg_activity_rent_part
  AFTER INSERT OR UPDATE OR DELETE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_part();

-- ── Періоди: скасування платежу і сума за період ──────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_record()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.amount_due IS DISTINCT FROM OLD.amount_due THEN
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'due_changed',
        jsonb_build_object('due_date', NEW.due_date, 'from', OLD.amount_due, 'to', NEW.amount_due));
    END IF;
  ELSIF OLD.status IN ('paid', 'partial') AND OLD.amount > 0 THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'payment_cancelled',
      jsonb_build_object('due_date', OLD.due_date, 'amount', OLD.amount));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_record() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_record ON rent_payment_records;
CREATE TRIGGER trg_activity_rent_record
  AFTER DELETE OR UPDATE OF amount_due ON rent_payment_records
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_record();

-- ── Розклад платежів ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_schedule()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'schedule_deleted', '{}'::jsonb);
  ELSIF TG_OP = 'INSERT'
     OR NEW.due_day IS DISTINCT FROM OLD.due_day
     OR NEW.is_active IS DISTINCT FROM OLD.is_active THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'schedule_set',
      jsonb_build_object('due_day', NEW.due_day, 'active', NEW.is_active,
                         'from', CASE WHEN TG_OP = 'UPDATE' THEN OLD.due_day END));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_schedule() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_schedule ON rent_payments;
CREATE TRIGGER trg_activity_rent_schedule
  AFTER INSERT OR UPDATE OF due_day, is_active OR DELETE ON rent_payments
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_schedule();

-- ── Документи і фото ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_property_media()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_TABLE_NAME = 'property_files' THEN
    IF TG_OP = 'INSERT' THEN
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'file_added',
        jsonb_build_object('name', NEW.file_name));
    ELSE
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'file_deleted',
        jsonb_build_object('name', OLD.file_name));
    END IF;
  ELSE
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'photo_deleted', '{}'::jsonb);
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_property_media() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_property_files ON property_files;
CREATE TRIGGER trg_activity_property_files
  AFTER INSERT OR DELETE ON property_files
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property_media();

DROP TRIGGER IF EXISTS trg_activity_property_photos ON property_photos;
CREATE TRIGGER trg_activity_property_photos
  AFTER DELETE ON property_photos
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property_media();

NOTIFY pgrst, 'reload schema';


-- ─────────────────────────────────────────────────────────────────────────
-- 074_account_erasure.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 074 — ВИДАЛЕННЯ АКАУНТА: імʼя зникає з чужих баз, автор не висне
-- ============================================================================
-- ЩО ЛІКУЄ. Знайдено ВИКОНАННЯМ на живому Postgres, а не читанням: редактор
-- вписав надходження в базу власника і видалив свій акаунт.
-- `delete_my_account()` звітує успіх, але:
--
--   1. ВИСЯЧИЙ КЛЮЧ. `rent_payment_parts.created_by` лишався на НЕІСНУЮЧОМУ
--      користувачі. Каскад `ON DELETE SET NULL` — це UPDATE, а тригер 073 на
--      кожному UPDATE повертає автора з OLD («автора не переписує ніхто»),
--      тож каскад мовчки скасовувався. Postgres цього не помічає: для нього
--      ключ «не змінився», і перевірка обмеження пропускається. Наслідок не
--      косметичний — логічний бекап відновлює обмеження ПІСЛЯ даних і падає
--      саме на ньому (заміряно: «violates foreign key constraint»). Тобто
--      одне видалення акаунта робило базу невідновлюваною з дампу.
--
--   2. ІМʼЯ ЛИШАЛОСЬ. Політика обіцяє «видалити акаунт і всі повʼязані
--      дані», а заморожені копії імені — їх тримають саме для того, щоб
--      бачили інші, — переживали видалення в ЧОТИРЬОХ місцях: журнал змін і
--      автор надходження (073), аналітика переглядів (`viewer_name`, її
--      показують 063 і екран аналітики) і гостьові лінки (048). 051
--      знеособлювала лише КЛЮЧІ.
--
-- ПРАВИЛО: заморожена копія імені живе рівно доки живе посилання на людину.
-- Посилання перерізали — імʼя йде слідом. Тримає це ТРИГЕР, а не
-- `delete_my_account`: так правило діє на БУДЬ-ЯКОМУ шляху видалення
-- користувача, а не лише на кнопці в профілі.
--
-- ЗАПИСИ ЛИШАЮТЬСЯ. Надходження з сумою, подія журналу, перегляд — це облік
-- ВЛАСНИКА бази, і гроші не зникають через те, що їх вписав той, хто пішов.
-- Зникає лише «хто». Вихід із команди (без видалення акаунта) імені НЕ
-- стирає: людина є, і запис про те, що вона робила, правдивий.
-- ============================================================================


-- ── 1. Автор надходження: виняток для каскаду ──────────────────────────────
-- Тіло — з 073 дослівно, крім гілки UPDATE. Розрізнити каскад і підробку
-- можна лише одним способом, який клієнт не здатен підробити: автора вже не
-- існує. Каскад біжить ПІСЛЯ видалення рядка `users`, тож у ньому
-- `NOT EXISTS` істинне; клієнт, що пробує стерти чи підмінити автора живої
-- людини, і далі дістає старе значення.
CREATE OR REPLACE FUNCTION public.stamp_rent_part_author()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.created_by IS NULL AND OLD.created_by IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = OLD.created_by) THEN
      NEW.created_by_name := NULL;
      RETURN NEW;
    END IF;
    NEW.created_by      := OLD.created_by;
    NEW.created_by_name := OLD.created_by_name;
    RETURN NEW;
  END IF;

  -- Перенесене підтвердження СТАРОГО клієнта (071: сума на періоді без
  -- надходжень стає першим надходженням). Гроші вписав хтось раніше, і
  -- приписати їх тому, чия дія спричинила перенос, було б неправдою.
  -- Звичайний перший платіж періоду так не виглядає: період без надходжень
  -- має порожню суму (її обнуляє тригер 071).
  IF EXISTS (SELECT 1 FROM rent_payment_records r
              WHERE r.id = NEW.record_id AND r.amount > 0
                AND r.status IN ('paid', 'partial'))
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = NEW.record_id) THEN
    NEW.created_by      := NULL;
    NEW.created_by_name := NULL;
    RETURN NEW;
  END IF;

  NEW.created_by      := NULL;
  NEW.created_by_name := NULL;
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO NEW.created_by, NEW.created_by_name
    FROM users u WHERE u.id = current_app_user_id();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.stamp_rent_part_author() FROM PUBLIC;

-- ── 2. Решта копій імені ────────────────────────────────────────────────────
-- Один тригер на три таблиці: аргументи — колонка посилання і колонка імені.
-- Спрацьовує лише на ПЕРЕХОДІ «було посилання → немає», тож службові рядки,
-- що від початку без посилання (публічні «Веб-перегляд»), не зачіпає.
-- Посилання тут обнуляє лише видалення акаунта: явний UPDATE у 051
-- (перегляди — їхній ключ `NO ACTION`, і гостьові лінки) і каскад
-- `SET NULL` (журнал). Інших записів, що рвуть ці посилання, у схемі немає.
CREATE OR REPLACE FUNCTION public.erase_frozen_name()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  IF to_jsonb(NEW) ->> TG_ARGV[0] IS NULL AND to_jsonb(OLD) ->> TG_ARGV[0] IS NOT NULL THEN
    NEW := jsonb_populate_record(NEW, jsonb_build_object(TG_ARGV[1], NULL));
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.erase_frozen_name() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_erase_viewer_name ON property_views;
CREATE TRIGGER trg_erase_viewer_name
  BEFORE UPDATE OF viewer_id ON property_views
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('viewer_id', 'viewer_name');

DROP TRIGGER IF EXISTS trg_erase_guest_name ON guest_links;
CREATE TRIGGER trg_erase_guest_name
  BEFORE UPDATE OF guest_user_id ON guest_links
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('guest_user_id', 'guest_name');

DROP TRIGGER IF EXISTS trg_erase_actor_name ON db_activity;
CREATE TRIGGER trg_erase_actor_name
  BEFORE UPDATE OF actor_id ON db_activity
  FOR EACH ROW EXECUTE FUNCTION public.erase_frozen_name('actor_id', 'actor_name');

-- ── 3. Ремонт того, що вже встигло статись ──────────────────────────────────
-- Порядок важливий: тригери вище МУСЯТЬ стояти раніше, інакше перший UPDATE
-- скасував би сам себе тим самим тригером 073, який тут лагодиться.
UPDATE rent_payment_parts pp SET created_by = NULL
 WHERE pp.created_by IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = pp.created_by);

-- Подію журналу без дійової особи записати неможливо (073 пише лише з
-- особою), тож порожнє посилання тут означає рівно видалений акаунт.
UPDATE db_activity SET actor_name = NULL
 WHERE actor_id IS NULL AND actor_name IS NOT NULL;

-- Гостьовий лінк дістає імʼя лише разом із посиланням на того, хто його
-- прийняв (048), тож імʼя без посилання — залишок видаленого акаунта.
UPDATE guest_links SET guest_name = NULL
 WHERE guest_user_id IS NULL AND guest_name IS NOT NULL;

-- Перегляди — обережно: публічні відкриття пишуться БЕЗ посилання, але зі
-- СЛУЖБОВИМ підписом (059), і екран аналітики його показує. Стирати можна
-- лише те, що не є цим підписом.
UPDATE property_views SET viewer_name = NULL
 WHERE viewer_id IS NULL AND viewer_name IS NOT NULL
   AND viewer_name NOT IN ('Веб-перегляд', 'Веб-перегляд бази', 'Веб-перегляд підбірки');

NOTIFY pgrst, 'reload schema';


-- ─────────────────────────────────────────────────────────────────────────
-- 075_function_acl_supabase_defaults.sql
-- ─────────────────────────────────────────────────────────────────────────
-- ============================================================================
-- 075 — ПРАВА НА ФУНКЦІЇ: те, що Supabase роздає САМ
-- ============================================================================
-- ЩО ЛІКУЄ. Знайдено на ЖИВІЙ базі (перше пряме підключення до проду), а не
-- на стенді — і саме тому стенд цього не бачив:
--
--   Supabase тримає `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA
--   public GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role`.
--   Тобто кожна функція, яку міграція створює через CREATE FUNCTION, одразу
--   дістає ПРЯМИЙ грант `anon` і `authenticated`. Наші міграції знімали лише
--   PUBLIC (правило 12), а прямий грант від цього не зникає. `CREATE OR
--   REPLACE` наявної функції права зберігає, тож уражені саме ті, що
--   зʼявились уперше після накату 062.
--
-- Заміряно в проді до цієї міграції:
--   * get_due_lease_reminders() — SECURITY DEFINER без параметрів, віддає
--     tg_id власника, назву обʼєкта й ІМʼЯ ОРЕНДАРЯ по ВСІХ власниках —
--     викликалась з публічного anon-ключа без помилки. Той самий клас, що
--     052/062 закрили для get_due_reminders_today; 065 його повторила.
--   * log_db_activity(...) — SECURITY DEFINER, пише подію в журнал БУДЬ-ЯКОЇ
--     бази за переданим db_id. Будь-хто, хто увійшов, міг підкинути
--     «надходження» чи «здано в оренду» в журнал чужої бази — тобто журнал,
--     який 073 обіцяє «не можна підправити», підправлявся одним RPC.
--   * клієнтські RPC для тих, хто увійшов (claim_*, lookup_shared_*,
--     manage_share, subscribe_to_shared_db, record_rent_payment,
--     set_rent_amount_due), викликались і анонімно. Кожна сама питає, хто
--     кличе, тож даних це не віддавало, — але периметр був ширший, ніж
--     задумано, і лінтер Supabase (0028/0029) це бачить.
--
-- ЧОТИРИ ШАРИ, кожен ідемпотентний:
--   1. службові функції — лише service_role;
--   2. anon — лише свідомо публічні: превʼю /v за токеном і RLS-хелпери, які
--      кличуть самі політики з роллю {public} (той самий allowlist, що в
--      scripts/verify-behaviour.sql і в рядку 70 verify_release.sql);
--   3. тригерні функції — нікому, крім власника: їх викликає сам Postgres,
--      і права EXECUTE в того, хто змінює рядок, він при цьому не питає;
--   4. ДЖЕРЕЛО: прибрати прямий грант anon/authenticated із default
--      privileges, щоб нова функція більше не відкривалась сама. Після
--      цього правило 12 («REVOKE ... FROM PUBLIC закриває») стає правдою і
--      на Supabase. PUBLIC Postgres видає на нові функції й далі, тож
--      клієнтський RPC без явного GRANT працює, як працював.
--
-- Функції розширень і event trigger-и не чіпаємо: вони не наші.
-- ============================================================================


-- ── 1. Службові: лише service_role ─────────────────────────────────────────
-- По ІМЕНІ, по всіх перевантаженнях (урок 062: у проді буває інша форма
-- функції, ніж у репозиторії). Відсутня функція пропускається: 024 у проді
-- немає, і `mark_overdue_payments` там не існує взагалі.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
       AND p.proname IN ('get_due_lease_reminders', 'get_due_reminders_today',
                         'get_due_guest_reminders', 'mark_overdue_payments',
                         'log_db_activity')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', r.sig);
  END LOOP;
END $$;

-- ── 2. anon: лише свідомо публічні ─────────────────────────────────────────
-- Решта звичайних функцій лишається тим, хто увійшов. Якщо функція досі
-- відкрита через PUBLIC, знімаємо його і видаємо authenticated явно — інакше
-- разом з anon закрили б і клієнтський RPC для всіх.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig,
           has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authed
      FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
       AND p.prokind = 'f'
       AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
       AND NOT EXISTS (SELECT 1 FROM pg_depend d
                        WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
       AND has_function_privilege('anon', p.oid, 'EXECUTE')
       AND p.proname NOT IN (
         -- Публічна /v і гостьовий превʼю: ключ — нездогадний токен, кожна
         -- функція сама перевіряє його й термін дії.
         'get_public_db_preview', 'get_public_property_preview',
         'get_public_collection_preview', 'get_guest_property_preview',
         'record_public_view',
         -- RLS-хелпери, які кличуть самі політики з роллю {public}: без
         -- EXECUTE анонімний запит падав би помилкою замість порожнечі.
         -- Відповідають лише «про мене» (057), тож чужого графа не віддають.
         'current_app_user_id', 'get_app_user_id_from_auth_uid',
         'get_owner_db_ids', 'get_owner_property_ids',
         'get_editor_db_ids', 'get_editor_db_ids_from_auth_uid', 'get_editor_property_ids',
         'get_realtor_db_ids', 'get_realtor_property_ids', 'get_realtor_collection_ids',
         'is_guest_of_property'
       )
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon', r.sig);
    -- service_role — завжди: функція, відкрита ЛИШЕ через PUBLIC, інакше
    -- втратила б і його, а від сервера її кличуть edge-функції.
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', r.sig);
    IF r.authed THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', r.sig);
    END IF;
  END LOOP;
END $$;

-- ── 3. Тригерні функції: нікому, крім власника ─────────────────────────────
-- Викликати їх напряму неможливо, тож це не діра, — але лінтер рахує їх
-- серед відкритих SECURITY DEFINER, і в шумі губиться справжня.
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
       AND p.prorettype = 'trigger'::regtype
       AND NOT EXISTS (SELECT 1 FROM pg_depend d
                        WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);
  END LOOP;
END $$;

-- ── 4. Джерело: нова функція більше не відкривається сама ──────────────────
-- І на рівні схеми, і ГЛОБАЛЬНО: схемні default privileges ДОДАЮТЬСЯ до
-- глобальних, а не перекривають їх, тож глобальний грант зняти схемним
-- REVOKE неможливо. На Supabase глобального запису для postgres немає (no-op),
-- але міграція не сміє на це покладатись.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;
-- Чого цей шар НЕ покриває: default privileges ролі supabase_admin (вона теж
-- видає anon/authenticated на public). Змінити їх postgres не може — він не
-- член цієї ролі. Функції, які створює платформа, ловить рядок 70
-- verify_release.sql: він дивиться на РЕЗУЛЬТАТ, а не на джерело.

NOTIFY pgrst, 'reload schema';


COMMIT;

-- ─────────────────────────────────────────────────────────────────────────
-- ПЕРЕВІРКА ГОТОВНОСТІ — supabase/verify_release.sql дослівно
-- ─────────────────────────────────────────────────────────────────────────
-- ЧОМУ ТУТ, А НЕ ОКРЕМИМ ФАЙЛОМ. Другий файл — другий крок, і його легко не
-- зробити: оператор бачить «Success» і вважає, що все на місці. А «Success»
-- каже лише, що текст виконався, — не що база тепер така, як треба.
--
-- ЧОМУ ПІСЛЯ COMMIT, А НЕ ВСЕРЕДИНІ. Перевірка дивиться й на те, що мали дати
-- міграції 001–047. MISSING там — привід дозастосувати конкретну міграцію,
-- а не причина відкочувати 048+.
--
-- ЩО ПОКАЖЕ РЕДАКТОР. Supabase SQL Editor показує результат ОСТАННЬОГО
-- запиту, що повернув рядки, — тобто саме цю таблицю. Якщо накат упав, сюди
-- виконання не доходить: увесь текст іде одним запитом, і Postgres
-- зупиняє його на першій помилці. Тоді замість таблиці видно помилку.
--
-- Тому сама перевірка не сміє ПАДАТИ (див. правило в шапці verify_release):
-- помилка ПІСЛЯ COMMIT читалась би як «не застосувалось», хоч усе застосовано.

-- ============================================================================
-- verify_release.sql — одна перевірка готовності БД до публікації.
-- Запусти в Supabase Dashboard → SQL Editor. Кожен рядок результату має бути
-- OK; будь-який MISSING = відповідна міграція не застосована (файл вказано).
--
-- Той самий запит ВКЛЕЄНО в кінець supabase/RELEASE.sql (після COMMIT), тож
-- один запуск того файлу і накочує міграції, і показує цю таблицю. Окремо
-- цей файл потрібен, щоб перевірити стан, нічого не застосовуючи.
--
-- ПРАВИЛО ДЛЯ НОВИХ РЯДКІВ: перевірка не сміє ПАДАТИ на базі ДО накату, де
-- таблиць із нових міграцій ще немає, — лише показувати MISSING. Тому про
-- нову таблицю питаємо КАТАЛОГ (`pg_class`, `to_regclass`), а не саму
-- таблицю: запит до неї там — ERROR, і замість відповіді «чого бракує»
-- людина побачила б помилку. З тієї ж причини `to_regclass(...)`, а не
-- `'...'::regclass`. Гард — scripts/verify-migrations.sh (база 001..047).
-- ============================================================================

WITH checks(ord, item, migration, ok) AS (VALUES
  -- 026: security audit fixes
  -- 049 ВИДАЛИЛА get_shared_collection як IDOR (SECURITY DEFINER по UUID,
  -- виданий anon, без звірки токена — ротація лінка її не стосувалась).
  -- Тому перевіряємо ВІДСУТНІСТЬ, а не наявність терміну дії: доти цей рядок
  -- вічно світив «MISSING → виконай 026» і посилав оператора не туди.
  (1,  'get_shared_collection ВІДСУТНЯ (IDOR, прибрано 049)', '049_drop_idor_get_shared_collection.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public' AND p.proname='get_shared_collection')),
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
  -- УВАГА: тут стояло «виконай 038», і це була НЕБЕЗПЕЧНА порада. 038 несе
  -- копію get_app_user_id_from_auth_uid() ДО 031 — без доменного якоря і
  -- tg_id>0 — тож на базі, де 045 застосована, а 038 ні (реальний стан
  -- проду), запуск 038 відкотив би фікс і знову відкрив захоплення акаунта.
  -- 062 робить лише те, чого бракує, і функцій ідентичності не чіпає.
  (6,  'photos: пермісивні політики запису ВИДАЛЕНІ', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='storage'
                  AND tablename='objects'
                  AND policyname IN ('photos_insert_auth','photos_delete_auth'))),
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

  -- 045: КРИТИЧНО — регресія ідентифікації (038/041 стерли фікс 031). Маркер
  -- `tg_id > 0` унікальний для виправленої версії — вразлива копія (038/041) її
  -- не має, тож самої substring-перевірки досить (без неоднозначності LIKE-екранування бекслеша в regex-літералі).
  (21, 'get_app_user_id_from_auth_uid має tg_id>0 (031/045 hardening)', '045_fix_auth_uid_identity_regression.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_app_user_id_from_auth_uid'
              AND prosrc LIKE '%tg_id > 0%')),
  (22, 'get_editor_db_ids_from_auth_uid має tg_id>0 (045 hardening)', '045_fix_auth_uid_identity_regression.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_editor_db_ids_from_auth_uid'
              AND prosrc LIKE '%tg_id > 0%')),

  (23, 'нагадування ВЗАГАЛІ викликаються (тип результату полагоджено)', '052_reminders_fix_and_lockdown.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_reminders_today'
              AND prosrc LIKE '%p.name::TEXT%')),
  (24, 'anon НЕ має службових функцій (дефолтний PUBLIC знято)', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public'
                    AND p.proname IN ('get_due_reminders_today','get_due_guest_reminders','mark_overdue_payments')
                    AND has_function_privilege('anon', p.oid, 'EXECUTE'))),

  (25, 'props_owner_all перевіряє, що БАЗА твоя (не лише owner_id)', '053_owner_policies_target_ownership.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='properties'
              AND policyname='props_owner_all' AND with_check LIKE '%get_owner_db_ids%')),
  (26, 'платежі перевіряють, що ОБʼЄКТ твій', '053_owner_policies_target_ownership.sql',
      (SELECT count(*)=2 FROM pg_policies
       WHERE tablename IN ('rent_payments','rent_payment_records')
         AND with_check LIKE '%get_owner_property_ids%')),
  (27, 'нагадування не розсилають чужих даних (rp.owner_id = p.owner_id)', '053_owner_policies_target_ownership.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_reminders_today'
              AND prosrc LIKE '%rp.owner_id = p.owner_id%')),

  -- Підрядок — свідома МЕЖА цього файлу, не недогляд: у Dashboard не можна
  -- виконати успішну гілку, не створивши справжньої підписки. Доказ виконанням
  -- дає CI (`verify-rls.sql`, блок «відкликання», позитивний контроль).
  (28, 'subscribe_to_shared_db не падає на успішній гілці (ON CONFLICT)', '055_fix_subscribe_ambiguous_db_id.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='subscribe_to_shared_db'
              AND prosrc LIKE '%variable_conflict use_column%')),

  (29, 'підбірка не приймає чужий обʼєкт (056)', '056_collection_target_access.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='collection_properties'
              AND policyname='col_props_realtor_all' AND with_check LIKE '%get_realtor_property_ids%')),
  (30, 'публічна підбірка не світить чужий обʼєкт (056)', '056_collection_target_access.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_collection_preview'
              AND prosrc LIKE '%realtor_subscriptions rs%')),

  (31, 'revoke ЗНИЩУЄ токен, а не лише протермінює (060)', '060_revoke_destroys_token.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='manage_share'
              AND prosrc LIKE '%IN (''rotate'',''revoke'')%')),
  (32, 'телефон на /v лише за згодою (061)', '061_public_phone_opt_in.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_name='users' AND column_name='public_phone')
      AND EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_db_preview'
                  AND prosrc LIKE '%public_phone%')),

  -- Пермісивна політика поруч зі строгою робить строгу безглуздою: правила
  -- обʼєднуються через OR. Рядок 8 цього НЕ бачив — він перевіряє лише, що
  -- строга існує, а не що пермісивної немає. Знайдено на живій базі.
  (33, 'property_files: пермісивні realtor-політики ВИДАЛЕНІ', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='property_files'
                  AND policyname IN ('pfiles_insert_realtor','pfiles_update_realtor'))),

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
              AND prosrc LIKE '%email%')),

  -- Решта КЛІЄНТСЬКИХ RPC. Їх не було тут, і це прогалина саме того класу, що
  -- вже коштувала накату: файл спирався на `mark_overdue_payments`, якої в
  -- проді не існувало, бо 024 ніколи не застосовували. Тобто прогалини всередині
  -- 001–047 ДОВЕДЕНІ, а не гіпотетичні — отже присутність будь-якої функції з
  -- того діапазону треба ПИТАТИ, а не припускати.
  --
  -- `lookup_shared_collection` — найгірший випадок: визначена ЛИШЕ в 020/023,
  -- у RELEASE.sql її немає, тож накат 048–062 її не створює. Якщо в проді її
  -- немає, deep link `col_<token>` (вхід за посиланням на підбірку) падає, і
  -- жоден файл репозиторію про це не скаже.
  (34, 'RPC lookup_shared_collection', '020/023_public_share_tokens.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='lookup_shared_collection')),
  (35, 'RPC lookup_shared_property', '020/023, оновлює 059',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='lookup_shared_property')),
  (36, 'RPC claim_guest_link', '027_guest_role.sql, оновлює 048',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='claim_guest_link')),
  (37, 'RPC get_guest_property_preview', '027_guest_role.sql, оновлює 050',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_guest_property_preview')),
  (38, 'RPC delete_my_account', '051_delete_account_storage.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='delete_my_account')),

  -- 063: сліди переглядів. ДВІ окремі перевірки, бо політика має дві гілки і
  -- кожна лікує свій випадок: без першої редактор команди не пише слід на
  -- картці, без другої перегляд БАЗИ не пише НІХТО (рядок бази має
  -- `property_id = NULL`, а `NULL IN (...)` дає NULL, не FALSE — предикат не
  -- виконувався в принципі й при цьому мовчав).
  (39, 'views_insert_auth: гілка РЕДАКТОРА команди', '063_view_insert_editors_and_dbs.sql',
      EXISTS (SELECT 1 FROM pg_policies
               WHERE tablename='property_views' AND policyname='views_insert_auth'
                 AND with_check LIKE '%get_editor_property_ids%')),
  (40, 'views_insert_auth: гілка рядка БАЗИ (property_id IS NULL)', '063_view_insert_editors_and_dbs.sql',
      EXISTS (SELECT 1 FROM pg_policies
               WHERE tablename='property_views' AND policyname='views_insert_auth'
                 AND with_check LIKE '%get_editor_db_ids%')),
  -- Урок 062: «строга політика існує» НЕ означає, що вона діє — пермісивна
  -- поруч робить її безглуздою, бо правила обʼєднуються через OR. Тому
  -- окремо перевіряємо, що INSERT-політика на цій таблиці РІВНО ОДНА.
  (41, 'property_views: INSERT-політика рівно одна', '063_view_insert_editors_and_dbs.sql',
      (SELECT count(*) FROM pg_policies
        WHERE tablename='property_views' AND cmd='INSERT') = 1),

  -- 064: орендодавець. Колонки — на ОБИДВОХ таблицях: без бази немає дефолта,
  -- без обʼєкта немає перевизначення, і кожна половина окремо безглузда.
  -- Третій рядок — про ПРЕВʼЮ: колонки можуть бути на місці, а публічна /v
  -- усе одно нічого не показує, бо функція їх не віддає.
  (42, 'databases.landlord_name', '064_landlord_name.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='databases' AND column_name='landlord_name')),
  (43, 'properties.landlord_name', '064_landlord_name.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='properties' AND column_name='landlord_name')),
  (44, 'усі три публічні превʼю віддають property_landlord_name', '064_landlord_name.sql',
      (SELECT count(*) FROM pg_proc
        WHERE proname IN ('get_public_property_preview','get_public_db_preview','get_public_collection_preview')
          AND pg_get_function_result(oid) LIKE '%property_landlord_name%') = 3),

  -- 065: нагадування про кінець договору. Перевіряємо ІСНУВАННЯ функції — те,
  -- що вона невидима для `anon`, тримає окремий гард (scripts/verify-behaviour),
  -- бо в тексті GRANT цього не видно (правило 12).
  (45, 'RPC get_due_lease_reminders', '065_lease_reminders.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_lease_reminders')),

  -- 066-1: якір особи. Перевіряємо саме ТІЛО: `CREATE OR REPLACE` міг бути
  -- перекритий пізнішою копією без якоря — рівно так 038 колись стерла фікс
  -- 031, і по тексту міграції цього не видно.
  (46, 'current_app_user_id: домен заякорено і tg_id > 0', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT prosrc LIKE '%telegram\\.propspace\\.app$%' AND prosrc LIKE '%tg_id_val <= 0%'
         FROM pg_proc WHERE proname='current_app_user_id' LIMIT 1)),

  -- 066-2: бакет фото не перелічується. Перевіряємо ВІДСУТНІСТЬ пермісивного
  -- варіанта, а не наявність строгого: політики обʼєднуються через OR, тож
  -- пермісивна поруч зі строгою робить строгу безглуздою (урок 062).
  (47, 'storage_photos_select звужено до authenticated', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT COUNT(*) = 1 FROM pg_policies
        WHERE schemaname='storage' AND tablename='objects'
          AND policyname='storage_photos_select'
          AND 'authenticated' = ANY(roles) AND NOT ('public' = ANY(roles))
          AND qual LIKE '%get_owner_property_ids%')),

  -- 066-3: гостьовий лінк перевіряє ціль.
  (48, 'db_guest_select звіряє owner_id цілі з видавцем', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT COUNT(*) = 1 FROM pg_policies
        WHERE tablename='databases' AND policyname='db_guest_select'
          AND qual LIKE '%owner_id%')),

  -- 067-1: сама таблиця архіву з RLS. Без неї екран працює, просто вимкнений.
  (49, 'tenancies: таблиця існує і RLS увімкнена', '067_tenancies.sql',
      (SELECT COALESCE((SELECT relrowsecurity FROM pg_class WHERE relname='tenancies'), false))),

  -- 067-2: ТРИГЕР, а не лише функція. Функція без тригера — це мертвий код:
  -- жоден зі ТРЬОХ клієнтських шляхів звільнення її не покличе, і архів
  -- лишиться назавжди порожнім, не подавши жодного сигналу.
  (50, 'trg_sync_tenancy висить на properties', '067_tenancies.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='properties' AND t.tgname='trg_sync_tenancy' AND NOT t.tgisinternal)),

  -- 067-3: рівно ОДНА відкрита оренда на обʼєкт. Без цього індексу повторне
  -- відкриття плодило б дублі, і «отримано» рахувалось би двічі.
  (51, 'частковий UNIQUE: одна відкрита оренда на обʼєкт', '067_tenancies.sql',
      (SELECT COUNT(*) = 1 FROM pg_indexes
        WHERE tablename='tenancies' AND indexname='idx_tenancies_one_open')),

  -- 068: архів — ЛИШЕ читання для клієнтів, двома шарами. Перевіряється
  -- ВІДСУТНІСТЬ політик запису, а не наявність SELECT-політики: строга
  -- політика поруч із пермісивною нічого не значить (урок рядка 33).
  (52, 'tenancies: клієнт не має права запису (політики + табличні права)', '068_tenancies_read_only.sql',
      (SELECT NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tenancies' AND cmd <> 'SELECT')
          AND EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tenancies' AND cmd = 'SELECT')
          AND COALESCE((SELECT NOT has_table_privilege('authenticated', c.oid, 'DELETE')
                               AND NOT has_table_privilege('authenticated', c.oid, 'UPDATE')
                               AND NOT has_table_privilege('authenticated', c.oid, 'INSERT')
                          FROM pg_class c WHERE c.relname='tenancies' AND c.relkind='r'), false))),

  -- 069-1: гостьове запрошення не знижує власника, що МАЄ бази. Без цього
  -- власник, який прийняв чуже запрошення, втрачає таббар «Бази» назавжди.
  (53, 'claim_guest_link не знижує власника з базами', '069_access_integrity.sql',
      (SELECT COUNT(*) >= 1 FROM pg_proc
        WHERE proname='claim_guest_link'
          AND prosrc LIKE '%NOT EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = v_uid)%')),

  -- 069-2: «Відкликати доступ» / «Оновити посилання» забирають доступ у вже
  -- підписаних рієлторів. Без цього шит обіцяв те, чого сервер не робив.
  (54, 'manage_share: rotate/revoke знімають підписки рієлторів', '069_access_integrity.sql',
      (SELECT COUNT(*) >= 1 FROM pg_proc
        WHERE proname='manage_share'
          AND prosrc LIKE '%DELETE FROM realtor_subscriptions%')),

  -- 069-3: ремонт відпрацював — знижених власників не лишилось. Перевіряє
  -- ДАНІ, а не код: функцію можна виправити, а людей так і не повернути.
  (55, 'немає гостей, що володіють базами (ремонт 069)', '069_access_integrity.sql',
      (SELECT NOT EXISTS (SELECT 1 FROM users u
                           WHERE u.role='guest'
                             AND EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = u.id)))),

  -- 070: нагадування НЕ йде про вже підтверджений платіж. Обидві функції —
  -- власницька й гостьова: орендар-гість отримував те саме хибне «оплата
  -- через 3 дні», хоч сам уже заплатив.
  (56, 'нагадування пропускають підтверджені платежі (власник і гість)', '070_reminders_skip_paid.sql',
      (SELECT COUNT(*) = 2 FROM pg_proc
        WHERE proname IN ('get_due_reminders_today','get_due_guest_reminders')
          AND prosrc LIKE '%FROM rent_payment_records r%'
          AND prosrc LIKE '%r.status = ''paid''%')),

  -- 071-1: надходження — окрема таблиця з RLS, і обидві політики питають про
  -- ЦІЛЬ (обʼєкт власника чи бази команди), а не лише «чи це мій рядок».
  (57, 'rent_payment_parts: RLS увімкнена, власник і редактор', '071_partial_payments.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='rent_payment_parts' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='rent_payment_parts'
                  AND policyname IN ('parts_owner_all','parts_editor_all')
                  AND with_check LIKE '%property_ids%'))),

  -- 071-2: ТРИГЕР, а не лише функція — інакше надходження пишуться, а
  -- підсумок періоду (сума, статус) лишається старим, і календар бреше.
  (58, 'trg_sync_rent_record_from_parts висить на rent_payment_parts', '071_partial_payments.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='rent_payment_parts' AND t.tgname='trg_sync_rent_record_from_parts' AND NOT t.tgisinternal)),

  -- 071-3: статус «частково» легальний. Без нового CHECK тригер падав би на
  -- КОЖНОМУ неповному надходженні, тобто фіча працювала б лише для повних.
  (59, 'rent_payment_records.status приймає partial', '071_partial_payments.sql',
      (SELECT COUNT(*) >= 1 FROM pg_constraint
        WHERE conrelid = to_regclass('public.rent_payment_records') AND contype='c'
          AND pg_get_constraintdef(oid) LIKE '%partial%')),

  -- 071-4: RPC є, автентифікованому доступна, анонімові — ні (правило 12:
  -- без явного REVOKE дефолтний PUBLIC лишився б).
  (60, 'record_rent_payment: authenticated так, anon ні', '071_partial_payments.sql',
      (SELECT COALESCE((SELECT has_function_privilege('authenticated', p.oid, 'EXECUTE')
                               AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
                          FROM pg_proc p WHERE p.proname='record_rent_payment' LIMIT 1), false))),

  -- 072-1: історія умов — лише ЧИТАННЯ для клієнтів (урок 068). Друга
  -- половина важливіша за першу: без неї «політика за зразком» відкрила б
  -- запис мовчки, і «ставка, що діяла тоді» стала б тим, що захотіли.
  (61, 'property_rent_terms: RLS, лише SELECT, запис клієнтам закритий', '072_rent_terms_history.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='property_rent_terms' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='property_rent_terms' AND cmd='SELECT'
                  AND policyname IN ('rent_terms_owner_select','rent_terms_editor_select'))
          AND (SELECT COUNT(*) = 0 FROM pg_policies
                WHERE tablename='property_rent_terms' AND cmd <> 'SELECT')
          AND CASE WHEN to_regclass('public.property_rent_terms') IS NULL THEN false
                   ELSE NOT has_table_privilege('authenticated', 'public.property_rent_terms', 'INSERT') END)),

  -- 072-2: ТРИГЕР, а не лише функція — без нього історія лишається порожньою
  -- назавжди, і борг рахується з поточної ставки БЕЗ жодного сигналу.
  (62, 'trg_record_rent_terms висить на properties', '072_rent_terms_history.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='properties' AND t.tgname='trg_record_rent_terms' AND NOT t.tgisinternal)),

  -- 072-3: сума за період — authenticated так, anon ні (правило 12).
  (63, 'set_rent_amount_due: authenticated так, anon ні', '072_rent_terms_history.sql',
      (SELECT COALESCE((SELECT has_function_privilege('authenticated', p.oid, 'EXECUTE')
                               AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
                          FROM pg_proc p WHERE p.proname='set_rent_amount_due' LIMIT 1), false))),

  -- 073-1: журнал змін — лише ЧИТАННЯ для клієнтів (урок 068): журнал, який
  -- редактор може підправити, не відповідає на «хто це зробив».
  (64, 'db_activity: RLS, лише SELECT, запис клієнтам закритий', '073_db_activity.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='db_activity' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='db_activity' AND cmd='SELECT'
                  AND policyname IN ('activity_owner_select','activity_editor_select'))
          AND (SELECT COUNT(*) = 0 FROM pg_policies
                WHERE tablename='db_activity' AND cmd <> 'SELECT')
          AND CASE WHEN to_regclass('public.db_activity') IS NULL THEN false
                   ELSE NOT has_table_privilege('authenticated', 'public.db_activity', 'INSERT') END)),

  -- 073-2: ТРИГЕРИ на всіх пʼяти таблицях. Таблиця без тригерів — це журнал,
  -- що мовчить завжди, тобто «змін не було», яке читається як правда.
  (65, 'журнал: тригери на properties, надходженнях, періодах, розкладі, документах, фото', '073_db_activity.sql',
      (SELECT COUNT(*) = 6 FROM pg_trigger t
        WHERE NOT t.tgisinternal AND t.tgname IN (
          'trg_activity_property', 'trg_activity_rent_part', 'trg_activity_rent_record',
          'trg_activity_rent_schedule', 'trg_activity_property_files', 'trg_activity_property_photos'))),

  -- 073-3: автора надходження ставить сервер — інакше редактор міг би
  -- «записати» гроші від імені власника.
  (66, 'rent_payment_parts: автор ставиться тригером', '073_db_activity.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='rent_payment_parts' AND t.tgname='trg_stamp_rent_part_author' AND NOT t.tgisinternal)),

  -- 074-1: автор надходження звільняється, коли акаунт видалено. Без винятку
  -- тригер 073 скасовував каскад `SET NULL`, і ключ лишався на неіснуючому
  -- користувачі — логічний бекап на такому обмеженні не відновлюється.
  (67, 'автор надходження не висне після видалення акаунта', '074_account_erasure.sql',
      (SELECT COALESCE(bool_or(p.prosrc LIKE '%NOT EXISTS (SELECT 1 FROM users u WHERE u.id = OLD.created_by)%'), false)
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'stamp_rent_part_author')),

  -- 074-2: імʼя йде слідом за посиланням — у журналі, переглядах і гостьових
  -- лінках. Без тригерів «видалити акаунт і всі повʼязані дані» з Політики
  -- лишається неправдою щодо чужих баз.
  (68, 'видалений акаунт: імʼя стирається з журналу, переглядів і гостьових лінків', '074_account_erasure.sql',
      (SELECT COUNT(*) = 3 FROM pg_trigger t
        WHERE NOT t.tgisinternal
          AND t.tgname IN ('trg_erase_viewer_name', 'trg_erase_guest_name', 'trg_erase_actor_name'))),

  -- 051: стирання файлів при видаленні акаунта тримається на ЗОВНІШНІЙ умові —
  -- власник функції обходить RLS (у Supabase це `postgres`), бо delete-політики
  -- storage видані лише `authenticated`. Доти це показувала тільки хвостова
  -- вибірка самої 051, а редактор SQL показує ЛИШЕ ОСТАННЮ таблицю — тож у
  -- RELEASE.sql із вбудованою перевіркою її вже не видно. Тому вона тут.
  -- Порада правильна: 051 дропає функцію і створює заново, тобто повторний
  -- запуск у SQL Editor робить її власником саме `postgres`.
  -- Що anon її НЕ кличе, тримає рядок 70 (075): `delete_my_account` поза
  -- allowlist-ом. Тут лише те, що дає сама 051, — інакше ❌ радив би
  -- перезапустити не ту міграцію.
  (69, 'delete_my_account: власник обходить RLS, authenticated кличе', '051_delete_account_storage.sql',
      (SELECT COALESCE(bool_and(
                  has_function_privilege('authenticated', p.oid, 'EXECUTE')
              AND COALESCE((SELECT r.rolbypassrls FROM pg_roles r
                             WHERE r.rolname = pg_get_userbyid(p.proowner)), false)), false)
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'delete_my_account')),

  -- 075-1: anon виконує лише свідомо публічні функції. Supabase видає EXECUTE
  -- на КОЖНУ нову функцію `anon` і `authenticated` прямим грантом, тож
  -- `REVOKE ... FROM PUBLIC` у міграції його не знімає — так у проді й
  -- лишились відкритими get_due_lease_reminders і log_db_activity. Список —
  -- той самий, що в 075 і в scripts/verify-behaviour.sql (звіряє юніт-тест).
  (70, 'anon кличе лише свідомо публічні функції', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public' AND p.prokind = 'f'
                     AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
                     AND NOT EXISTS (SELECT 1 FROM pg_depend d
                                      WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
                     AND has_function_privilege('anon', p.oid, 'EXECUTE')
                     AND p.proname NOT IN (
                       'get_public_db_preview', 'get_public_property_preview',
                       'get_public_collection_preview', 'get_guest_property_preview',
                       'record_public_view',
                       'current_app_user_id', 'get_app_user_id_from_auth_uid',
                       'get_owner_db_ids', 'get_owner_property_ids',
                       'get_editor_db_ids', 'get_editor_db_ids_from_auth_uid', 'get_editor_property_ids',
                       'get_realtor_db_ids', 'get_realtor_property_ids', 'get_realtor_collection_ids',
                       'is_guest_of_property'))),

  -- 075-2: службові функції — лише service_role. Перевірка вище дивиться на
  -- anon, а цим не можна й тим, хто увійшов: одна віддає дані ВСІХ власників,
  -- друга пише в журнал БУДЬ-ЯКОЇ бази.
  (71, 'службові функції не кличе ні anon, ні authenticated', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public'
                     AND p.proname IN ('get_due_lease_reminders', 'get_due_reminders_today',
                                       'get_due_guest_reminders', 'mark_overdue_payments', 'log_db_activity')
                     AND (has_function_privilege('anon', p.oid, 'EXECUTE')
                          OR has_function_privilege('authenticated', p.oid, 'EXECUTE')))),

  -- 075-3: ДЖЕРЕЛО класу — default privileges. Поки в них anon/authenticated,
  -- наступна службова функція знову відкриється сама.
  -- Схемний І глобальний запис: схемні default privileges додаються до
  -- глобальних, тож глобальний грант пережив би схемний REVOKE.
  (72, 'нова функція не відкривається anon/authenticated сама', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
                   WHERE (d.defaclnamespace = 0 OR n.nspname = 'public') AND d.defaclobjtype = 'f'
                     AND pg_get_userbyid(d.defaclrole) = 'postgres'
                     AND array_to_string(d.defaclacl, ',') ~ '(^|,)(anon|authenticated)=')),

  -- 075-4: друга межа периметра. Закривши функцію для anon, легко зачепити
  -- хелпер, який кличе САМА політика з роллю {public}: анонімний запит до
  -- таблиці тоді падає помилкою замість порожнечі, тобто /v ламається.
  -- Питаємо фінальні політики, а не текст міграцій.
  (73, 'політики {public} кличуть лише функції, доступні anon', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies pol
                   CROSS JOIN LATERAL regexp_matches(coalesce(pol.qual, '') || ' ' || coalesce(pol.with_check, ''),
                                                     '([a-z_][a-z0-9_]*)\(', 'g') AS m
                   JOIN pg_proc f ON f.proname = m[1]
                   JOIN pg_namespace ns ON ns.oid = f.pronamespace AND ns.nspname = 'public'
                  WHERE ('public' = ANY (pol.roles) OR 'anon' = ANY (pol.roles))
                    AND NOT has_function_privilege('anon', f.oid, 'EXECUTE'))),

  -- 075 закрила log_db_activity для клієнтів, тож журнал живе лише тим, що
  -- тригери — SECURITY DEFINER, а їхній власник сам має EXECUTE. Тригер,
  -- перестворений іншою роллю чи як INVOKER, валив би саму ДІЮ (його виклик
  -- журналу не загорнутий у перехоплення), а не лише подію журналу.
  (74, 'тригери журналу можуть писати в журнал', '073_db_activity.sql',
      (SELECT COALESCE(bool_and(c.prosecdef AND has_function_privilege(c.proowner, l.oid, 'EXECUTE')), false)
         FROM pg_proc l JOIN pg_namespace ln ON ln.oid = l.pronamespace AND ln.nspname = 'public'
         JOIN pg_proc c ON c.prosrc LIKE '%log_db_activity(%' AND c.oid <> l.oid
         JOIN pg_namespace cn ON cn.oid = c.pronamespace AND cn.nspname = 'public'
        WHERE l.proname = 'log_db_activity'))
)
SELECT
  CASE WHEN ok THEN '✅ OK     ' ELSE '❌ MISSING' END AS status,
  item,
  CASE WHEN ok THEN '' ELSE '→ виконай ' || migration END AS action
FROM checks ORDER BY ord;
