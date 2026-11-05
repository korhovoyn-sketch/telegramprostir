-- ============================================================================
-- 076: ОСОБУ ДАЄ СЕРВЕР, А НЕ EMAIL, ЯКИЙ ОБИРАЄ САМ КОРИСТУВАЧ
-- ============================================================================
-- Обидва резолвери особи (`current_app_user_id()` для всіх політик таблиць і
-- `get_app_user_id_from_auth_uid()` для сховища) виводили tg_id з EMAIL
-- облікового запису: `{tg_id}@telegram.propspace.app`. Якір домену (031/045/
-- 066) захищав від ЧУЖОГО домену, але не від того, що такий самий email
-- може отримати не наша edge-функція, а будь-хто:
--
--   * реєстрація в Supabase Auth з ПУБЛІЧНИМ ключем (`signUp`) — якщо в Auth
--     увімкнено реєстрацію email/пароль без підтвердження;
--   * зміна email власного акаунта (`updateUser`), зокрема АНОНІМНОГО — а
--     анонімний вхід у проді вже вмикався (31 такий акаунт, березень 2026).
--
-- Атака (відтворено на стенді): зловмисник займає email `920001@…` для
-- Telegram-id, який ще не входив; коли жертва вперше входить, edge-функція
-- створює її профіль із tg_id 920001, і токен ЗЛОВМИСНИКА відтепер резолвиться
-- у профіль жертви — він бачить і змінює все, що вона введе. Залежність від
-- налаштувань Auth, яких цей репозиторій не контролює, — і є дефект.
--
-- Рішення: особу засвідчує `auth.users.raw_app_meta_data.tg_id`. Його може
-- записати ЛИШЕ службовий ключ (адмін-API), тобто наша edge-функція; сам
-- користувач змінює `user_metadata`, але не `app_metadata`. Читається з БД,
-- а не з токена: так перевірка діє й для вже виданих токенів, щойно рядок
-- засвідчено, і не залежить від того, чи потрапило поле в JWT.
--
-- Вимагається ЗБІГ двох джерел: tg_id з app_metadata == локальна частина
-- email. Акаунт, що змінив собі email на чужий, має app_metadata від ІНШОГО
-- tg_id і не резолвиться ні в кого.
--
-- ПОРЯДОК ДЕПЛОЮ: edge-функція `telegram-auth` (ставить app_metadata новим і
-- наявним користувачам) → ця міграція. У зворотному порядку новий користувач,
-- створений у проміжку старою функцією, лишився б без засвідчення до свого
-- наступного входу. Наявних закриває бекфіл нижче.
-- ============================================================================

BEGIN;

-- ── Бекфіл засвідчення ──────────────────────────────────────────────────────
-- Позначаються лише ті, хто вже є легальним користувачем: email у форматі
-- входу, ПІДТВЕРДЖЕНИЙ (edge-функція створює з `email_confirm: true`), не
-- анонімний і з профілем. Бекфіл довіряє поточному стану бази — на проді
-- 31.10.2026 таких акаунтів рівно три, і всі троє створені edge-функцією
-- (підтверджені, з профілем, жодного з чужим провайдером).
UPDATE auth.users au
   SET raw_app_meta_data = COALESCE(au.raw_app_meta_data, '{}'::jsonb)
                           || jsonb_build_object('tg_id', SPLIT_PART(au.email, '@', 1))
 WHERE au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
   AND au.email_confirmed_at IS NOT NULL
   AND NOT COALESCE(au.is_anonymous, false)
   AND NOT COALESCE(au.raw_app_meta_data ? 'tg_id', false)
   AND EXISTS (SELECT 1 FROM public.users u
                WHERE u.tg_id = SPLIT_PART(au.email, '@', 1)::BIGINT);

-- ── Резолвер для політик таблиць ────────────────────────────────────────────
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
  IF jwt_email IS NULL OR jwt_email !~ '^\d{1,20}@telegram\.propspace\.app$' THEN
    RETURN NULL;
  END IF;
  tg_id_val := SPLIT_PART(jwt_email, '@', 1)::BIGINT;
  IF tg_id_val <= 0 THEN
    RETURN NULL;
  END IF;
  -- 076: email з токена — лише ПІДКАЗКА, яку обирає сам користувач. Особу
  -- засвідчує app_metadata того ж облікового запису, і лише коли збігаються
  -- обидва.
  IF NOT EXISTS (
    SELECT 1 FROM auth.users au
     WHERE au.email = jwt_email
       AND au.raw_app_meta_data->>'tg_id' = tg_id_val::TEXT
  ) THEN
    RETURN NULL;
  END IF;
  RETURN (SELECT id FROM users WHERE tg_id = tg_id_val LIMIT 1);
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$$;

-- ── Резолвер для сховища (контекст, де надійний лише `sub`) ─────────────────
CREATE OR REPLACE FUNCTION get_app_user_id_from_auth_uid()
RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id
  FROM public.users u
  JOIN auth.users au ON au.id = auth.uid()
  WHERE u.tg_id = (SPLIT_PART(au.email, '@', 1)::BIGINT)
    -- Якір домену й формату (031/045) лишається.
    AND au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
    AND u.tg_id > 0
    -- 076: засвідчення сервером — app_metadata збігається з email.
    AND au.raw_app_meta_data->>'tg_id' = SPLIT_PART(au.email, '@', 1)
  LIMIT 1;
$$;

-- ── Службовий пошук запису входу за email ──────────────────────────────────
-- Потрібен edge-функції, щоб прибрати ЧУЖИЙ запис, який зайняв email
-- користувача наперед: адмін-API Auth шукає лише за id, а схема `auth` через
-- REST не публікується. Тільки службовий ключ — у клієнтських руках це був би
-- оракул «чи зареєстрований такий Telegram-id».
CREATE OR REPLACE FUNCTION auth_user_id_by_email(p_email TEXT)
RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM auth.users WHERE email = p_email LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_user_id_by_email(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION auth_user_id_by_email(TEXT) TO service_role;

COMMIT;
