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
