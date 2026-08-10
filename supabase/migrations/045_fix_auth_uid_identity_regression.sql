-- ============================================================================
-- 045_fix_auth_uid_identity_regression.sql — CRITICAL: re-apply 031's identity
-- hardening that 038 and 041 silently reverted. Idempotent.
-- Run IMMEDIATELY in Supabase Dashboard → SQL Editor, ahead of any other
-- pending migration.
--
-- ЩО СТАЛОСЯ: 031_critical_security_hotfixes.sql (CRITICAL-2) навмисно
-- переозначив get_app_user_id_from_auth_uid() з двома захистами:
--   1. `au.email ~ '^\d{1,20}@telegram\.propspace\.app$'` — email мусить бути
--      РІВНО {tg_id}@telegram.propspace.app, не просто містити tg_id ДО '@';
--   2. `u.tg_id > 0` — відкидає нульовий/непарсний tg_id.
-- 038_storage_write_hardening.sql, написана ПІЗНІШЕ (номер вищий — виконується
-- останньою), містить власну "самодостатню" копію тієї ж функції "про всяк
-- випадок, якщо 030 не застосована" — але скопіювала ДОВОЛІ-031 версію без цих
-- двох перевірок, CREATE OR REPLACE якої мовчки стирає фікс 031. 041_team_members
-- скопіювала вже РЕГРЕСОВАНИЙ патерн у нову get_editor_db_ids_from_auth_uid(),
-- поширивши діру далі.
--
-- ЕКСПЛУАТАЦІЯ: без домен-якоря будь-хто, хто самостійно реєструється в Supabase
-- Auth (звичайний email/password, публічний anon key) з email виду
-- "<чийсь_tg_id>@будь-що.example", отримує SPLIT_PART(email,'@',1) = tg_id
-- жертви. Домен не збігається з telegram.propspace.app, тож UNIQUE(email) не
-- конфліктує зі справжнім акаунтом жертви — реєстрація проходить. Далі
-- get_app_user_id_from_auth_uid() резолвиться в users.id ЖЕРТВИ, і зловмисник
-- отримує права на запис/видалення фото жертви (storage_photos_insert/delete,
-- 038) та — якщо tg_id збігається з активним редактором чиєїсь бази — повний
-- editor-запис фото (storage_photos_editor_insert/delete, 041). tg_id не є
-- секретом (видимий у публічних лінках/юзернеймах), тож ціль обирається
-- тривіально.
-- ============================================================================

CREATE OR REPLACE FUNCTION get_app_user_id_from_auth_uid()
RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id
  FROM public.users u
  JOIN auth.users au ON au.id = auth.uid()
  WHERE u.tg_id = (SPLIT_PART(au.email, '@', 1)::BIGINT)
    -- Строга валідація: email мусить збігатися РІВНО з очікуваним форматом.
    AND au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
    -- tg_id мусить бути валідним (ненульовим) Telegram ID.
    AND u.tg_id > 0
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION get_editor_db_ids_from_auth_uid()
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT m.db_id
  FROM db_members m
  JOIN public.users u ON u.id = m.user_id
  JOIN auth.users au ON au.id = auth.uid()
  WHERE u.tg_id = (SPLIT_PART(au.email, '@', 1)::BIGINT)
    AND au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
    AND u.tg_id > 0
    AND m.status = 'active' AND m.role = 'editor';
$$;

-- Верифікація (has_nonzero_guard має бути TRUE на обидва рядки — цей маркер
-- унікальний для виправленої версії, вразлива копія (038/041) його не мала).
SELECT
  proname,
  prosrc LIKE '%tg_id > 0%' AS has_nonzero_guard
FROM pg_proc
WHERE proname IN ('get_app_user_id_from_auth_uid', 'get_editor_db_ids_from_auth_uid');
