-- ============================================================================
-- PropSpace — ОДИН файл для накату в Supabase Dashboard → SQL Editor
--
-- ЗГЕНЕРОВАНО: scripts/build-release-sql.sh. РУКАМИ НЕ ПРАВИТИ.
-- Джерело правди — supabase/migrations/; CI звіряє, що цей файл їм
-- відповідає (робота `migrations`, крок «RELEASE.sql не розійшовся»).
--
-- Містить міграції 14 шт., від 48 і далі:
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
--
-- ЯК НАКОЧУВАТИ: вставити цілком і виконати ОДИН раз.
--   * усе загорнуте в BEGIN/COMMIT — при будь-якій помилці НІЧОГО не
--     застосується, тобто напівстану не буде;
--   * файл ІДЕМПОТЕНТНИЙ (перевірено повторним накатом у CI), тож
--     повторний запуск безпечний;
--   * після нього запусти supabase/verify_release.sql — усі рядки
--     мають бути ✅ OK.
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

COMMIT;
