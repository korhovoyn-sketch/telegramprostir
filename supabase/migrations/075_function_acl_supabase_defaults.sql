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

BEGIN;

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
