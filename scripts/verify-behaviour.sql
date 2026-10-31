-- ПАСТКА, НА ЯКУ Я ТУТ НАСТУПИВ: `v->>'ключ' <> 'значення'` при ВІДСУТНЬОМУ
-- ключі дає NULL, а `IF NULL THEN` не спрацьовує. Тобто перевірка мовчазно
-- пропускала саме той випадок, заради якого писалась, — зниклий ключ. Скрізь
-- нижче тільки `IS DISTINCT FROM`.
--
-- Поведінкові перевірки на СПРАВЖНІЙ базі. Не «чи компілюється», а «чи робить
-- те, що обіцяє». Кожна падає з `RAISE EXCEPTION`, тож скрипт зупиняє CI.
\set ON_ERROR_STOP on

DO $$
DECLARE
  r RECORD; n INT;
BEGIN
  -- ── Фікстура: власник, база, обʼєкт, два фото (одне БЕЗ файлу), документ ──
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES
    ('11111111-1111-1111-1111-111111111111','777001@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,role) VALUES
    ('22222222-2222-2222-2222-222222222222',777001,'Тест','owner');
  INSERT INTO databases (id,owner_id,name,type) VALUES
    ('33333333-3333-3333-3333-333333333333','22222222-2222-2222-2222-222222222222','БЦ','business_center');
  INSERT INTO properties (id,db_id,owner_id,name) VALUES
    ('44444444-4444-4444-4444-444444444444','33333333-3333-3333-3333-333333333333','22222222-2222-2222-2222-222222222222','Офіс 1');
  INSERT INTO property_photos (property_id,storage_path,sort_order) VALUES
    ('44444444-4444-4444-4444-444444444444','44444444-4444-4444-4444-444444444444/a.jpg',0),
    -- Рядок БЕЗ файлу: у сховищі його вже немає. Попередня редакція 051
    -- саме на цьому робила акаунт НЕВИДАЛЬНИМ назавжди.
    ('44444444-4444-4444-4444-444444444444','44444444-4444-4444-4444-444444444444/zniklo.jpg',1);
  INSERT INTO storage.objects (bucket_id,name) VALUES
    ('photos','44444444-4444-4444-4444-444444444444/a.jpg'),
    ('property-files','44444444-4444-4444-4444-444444444444/dogovir.pdf'),
    -- ЧУЖИЙ файл: не має постраждати.
    ('photos','99999999-9999-9999-9999-999999999999/foreign.jpg');

  PERFORM set_config('request.jwt.claims','{"email":"777001@telegram.propspace.app"}',false);

  -- ── 051: видалення акаунта стирає файли І сам акаунт ────────────────────
  SELECT * INTO r FROM delete_my_account();
  IF NOT r.deleted THEN
    RAISE EXCEPTION '051: видалення відмовило (%). Розбіжність БД↔сховище НЕ мусить блокувати стирання', r.error;
  END IF;

  SELECT count(*) INTO n FROM storage.objects
   WHERE name LIKE '44444444-4444-4444-4444-444444444444/%';
  IF n IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION '051: у сховищі лишилось % власних обʼєктів — публічні URL живі', n;
  END IF;

  SELECT count(*) INTO n FROM storage.objects WHERE name LIKE '99999999%';
  IF n IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION '051: ЧУЖИЙ файл постраждав (лишилось %) — фільтр по власнику не працює', n;
  END IF;

  SELECT count(*) INTO n FROM users;              IF n IS DISTINCT FROM 0 THEN RAISE EXCEPTION '051: профіль не видалено'; END IF;
  SELECT count(*) INTO n FROM auth.users;         IF n IS DISTINCT FROM 0 THEN RAISE EXCEPTION '051: auth-акаунт лишився — наступний вхід підніме порожній профіль'; END IF;
  SELECT count(*) INTO n FROM properties;         IF n IS DISTINCT FROM 0 THEN RAISE EXCEPTION '051: каскад не спрацював'; END IF;

  -- 051: гілка «не бачу storage» мусить ВІДМОВИТИ, а не звітувати успіх.
  -- Це рівно те, чого попередня редакція не вміла: `count` і `DELETE`
  -- фільтруються однаково, тож при повній невидимості обидва дають 0 і
  -- різниця нульова. Перевіряємо на КОПІЇ функції з власником БЕЗ bypassrls —
  -- саму функцію чіпати не можна, вона потрібна решті перевірок.
  CREATE ROLE zz_noby NOLOGIN;
  GRANT USAGE ON SCHEMA public, storage TO zz_noby;
  GRANT SELECT, DELETE ON storage.objects TO zz_noby;
  EXECUTE format(
    'CREATE FUNCTION zz_probe_blind() RETURNS TABLE(deleted BOOLEAN, error TEXT) '
    'LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS %L',
    $probe$
    BEGIN
      IF NOT COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), FALSE)
         AND COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid = 'storage.objects'::regclass), FALSE)
      THEN
        RETURN QUERY SELECT FALSE, 'storage_not_verifiable'::TEXT; RETURN;
      END IF;
      RETURN QUERY SELECT TRUE, NULL::TEXT;
    END $probe$);
  ALTER FUNCTION zz_probe_blind() OWNER TO zz_noby;

  IF (SELECT error FROM zz_probe_blind()) IS DISTINCT FROM 'storage_not_verifiable' THEN
    RAISE EXCEPTION '051: власник БЕЗ bypassrls дістав успіх — доказ стирання безсилий проти повної невидимості';
  END IF;
  DROP FUNCTION zz_probe_blind();
  REVOKE ALL ON storage.objects FROM zz_noby;
  REVOKE USAGE ON SCHEMA public, storage FROM zz_noby;
  DROP ROLE zz_noby;

  RAISE NOTICE '  ✓ 051: файли, профіль і auth-акаунт знесені; чужий файл цілий; сліпий власник ВІДМОВЛЯЄ';
END $$;

DO $$
DECLARE
  v JSONB; n INT;
BEGIN
  -- ── 050: форма JSON гостьового превʼю ──────────────────────────────────
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES ('aaaaaaaa-0000-0000-0000-000000000001','777003@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('bbbbbbbb-0000-0000-0000-000000000001',777003,'Микола','owner');
  INSERT INTO databases (id,owner_id,name,type,color) VALUES
    ('cccccccc-0000-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000001','БЦ Рубін','business_center','blue');
  INSERT INTO properties (id,db_id,owner_id,name,status,floor) VALUES
    ('dddddddd-0000-0000-0000-000000000001','cccccccc-0000-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000001','Офіс 101','free','3');
  INSERT INTO guest_links (id,owner_id,property_id,invite_token,status) VALUES
    ('eeeeeeee-0000-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000001','dddddddd-0000-0000-0000-000000000001','tok_prop_001','pending');
  INSERT INTO guest_links (id,owner_id,db_id,invite_token,status) VALUES
    ('eeeeeeee-0000-0000-0000-000000000002','bbbbbbbb-0000-0000-0000-000000000001','cccccccc-0000-0000-0000-000000000001','tok_db_001','pending');

  -- Гілка ОБʼЄКТА
  v := get_guest_property_preview('tok_prop_001');
  IF v IS NULL THEN RAISE EXCEPTION '050: превʼю обʼєкта порожнє'; END IF;
  IF v->>'type' IS DISTINCT FROM 'property' THEN RAISE EXCEPTION '050: ключ `type` = % (екран гілкується саме по ньому)', v->>'type'; END IF;
  IF v->>'owner_first' IS NULL THEN RAISE EXCEPTION '050: немає `owner_first` — речення «… надає вам доступ до:» лишиться обірваним'; END IF;
  IF v->'property'->>'name' IS NULL THEN RAISE EXCEPTION '050: немає `property.name` — тайл безіменний'; END IF;
  IF v->'property'->>'db_color' IS NULL THEN RAISE EXCEPTION '050: немає вкладеного `db_color`'; END IF;

  -- Гілка БАЗИ
  v := get_guest_property_preview('tok_db_001');
  IF v->>'type' IS DISTINCT FROM 'database' THEN RAISE EXCEPTION '050: гілка бази віддає type=%', v->>'type'; END IF;
  IF v->'database'->>'name' IS NULL THEN RAISE EXCEPTION '050: немає `database.name`'; END IF;
  IF jsonb_array_length(COALESCE(v->'properties','[]'::jsonb)) IS DISTINCT FROM 1 THEN RAISE EXCEPTION '050: список обʼєктів бази порожній'; END IF;

  -- Відкликаний лінк не пускає
  UPDATE guest_links SET status='revoked' WHERE invite_token='tok_prop_001';
  IF get_guest_property_preview('tok_prop_001') IS NOT NULL THEN
    RAISE EXCEPTION '050: ВІДКЛИКАНИЙ лінк усе ще віддає вміст';
  END IF;

  RAISE NOTICE '  ✓ 050: обидві гілки віддають форму, яку читає екран; revoked не пускає';
END $$;

DO $$
DECLARE v JSONB; nm TEXT;
BEGIN
  -- ── 048: клейм записує імʼя гостя ──────────────────────────────────────
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES ('aaaaaaaa-0000-0000-0000-000000000002','777004@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,last_name,role) VALUES
    ('bbbbbbbb-0000-0000-0000-000000000002',777004,'Олена','Ковальчук','owner');
  PERFORM set_config('request.jwt.claims','{"email":"777004@telegram.propspace.app"}',false);

  v := claim_guest_link('tok_db_001');
  IF v->>'error' IS NOT NULL THEN RAISE EXCEPTION '048: клейм відмовив: %', v->>'error'; END IF;

  SELECT guest_name INTO nm FROM guest_links WHERE invite_token='tok_db_001';
  IF nm IS DISTINCT FROM 'Олена Ковальчук' THEN
    RAISE EXCEPTION '048: імʼя гостя не записано (отримано %) — список гостей лишиться безіменним', COALESCE(nm,'NULL');
  END IF;

  -- Ідемпотентність: повторний клейм тим самим користувачем не падає
  v := claim_guest_link('tok_db_001');
  IF v->>'error' IS NOT NULL THEN RAISE EXCEPTION '048: повторний клейм впав: %', v->>'error'; END IF;

  RAISE NOTICE '  ✓ 048: імʼя записано, повторний клейм ідемпотентний';
END $$;

DO $$
DECLARE n INT; leaked TEXT;
BEGIN
  -- ── 052: нагадування ВЗАГАЛІ повертають рядки ───────────────────────────
  -- Обидві функції були оголошені з `property_name TEXT`, а `properties.name`
  -- звужено до VARCHAR(200) міграцією 014 — тобто КОЖЕН виклик падав, і
  -- таблиця `notifications`, яку наповнює лише ця пара, не могла отримати
  -- жодного рядка. Джерельний гард такого не бачить у принципі: обидва типи
  -- в тексті виглядають правильно, розходяться вони лише у виконанні.
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES ('aaaaaaaa-0000-0000-0000-000000000052','777052@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('bbbbbbbb-0000-0000-0000-000000000052',777052,'Нагадувач','owner');
  INSERT INTO databases (id,owner_id,name,type) VALUES
    ('cccccccc-0000-0000-0000-000000000052','bbbbbbbb-0000-0000-0000-000000000052','База нагадувань','business_center');
  INSERT INTO properties (id,db_id,owner_id,name,status,tenant_name) VALUES
    ('dddddddd-0000-0000-0000-000000000052','cccccccc-0000-0000-0000-000000000052',
     'bbbbbbbb-0000-0000-0000-000000000052','Офіс 52','occupied','ТОВ Орендар');
  -- due_day у межах CHECK (1..28), notify_days_before у межах (0..14):
  -- беремо день, що настане через 3 дні, і лише якщо він ≤ 28.
  INSERT INTO rent_payments (property_id,owner_id,due_day,notify_days_before,is_active)
  SELECT 'dddddddd-0000-0000-0000-000000000052','bbbbbbbb-0000-0000-0000-000000000052',
         d, 3, true
  FROM (SELECT EXTRACT(DAY FROM current_date + INTERVAL '3 day')::INT AS d) s
  WHERE s.d BETWEEN 1 AND 28;

  IF EXISTS (SELECT 1 FROM rent_payments WHERE property_id='dddddddd-0000-0000-0000-000000000052') THEN
    SELECT count(*) INTO n FROM get_due_reminders_today()
      WHERE property_id='dddddddd-0000-0000-0000-000000000052';
    IF n <> 1 THEN
      RAISE EXCEPTION '052: get_due_reminders_today() не віддала рядок (%) — сповіщень про платежі не буде', n;
    END IF;
  END IF;
  -- Гостьова функція мусить бути ВИКЛИКАБЕЛЬНОЮ навіть коли гостей нема:
  -- саме тип результату, а не наявність даних, і був зламаний.
  PERFORM count(*) FROM get_due_guest_reminders();

  -- ── 052: жодна НОВА функція не стає доступною anon випадково ───────────
  -- `GRANT ... TO service_role` НЕ знімає дефолтний грант PUBLIC, який
  -- Postgres вішає на кожну функцію при створенні — його треба знімати
  -- явним REVOKE. Тому перевіряємо не список «тих трьох, що ловили», а
  -- ВСІ SECURITY DEFINER функції проти allowlist-а свідомо публічних.
  -- Нова функція без REVOKE впаде тут, навіть якщо про неї ніхто не згадав.
  SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO leaked
  FROM pg_proc p
  JOIN pg_namespace ns ON ns.oid = p.pronamespace AND ns.nspname = 'public'
  WHERE p.prosecdef
    AND p.prorettype <> 'trigger'::regtype
    AND has_function_privilege('anon', p.oid, 'EXECUTE')
    AND p.proname NOT IN (
      -- Публічна /v: ключ доступу — нездогадний share-токен, і кожна з них
      -- сама перевіряє його та термін дії. Це і є проєктний периметр.
      'get_public_db_preview','get_public_property_preview',
      'get_public_collection_preview','get_guest_property_preview',
      'record_public_view',
      -- Хелпери, які викликають САМІ RLS-політики. Політики мають роль
      -- {public}, тобто виконуються і від anon, тож EXECUTE їм потрібен.
      --
      -- ТУТ РАНІШЕ СТОЯЛА НЕПРАВДА: «щоб отримати чужий граф, треба вже знати
      -- users.id жертви, якого жодна публічна поверхня не віддає». Віддає:
      -- `GuestHomeScreen` читає `guest_links.owner_id`, а `lookup_shared_db`
      -- повертає `owner_id` кожному, хто має шер-лінк. Перевірено виконанням —
      -- гість, запрошений на ОДИН обʼєкт, перелічував усю базу власника.
      --
      -- Тепер безпеку тримає не цей allowlist, а сама функція: 057 додала їм
      -- перевірку «питають про мене?» (обидві особи — email- і sub-клейм).
      -- Гард на це — `verify-rls.sql`, блок 14.
      'current_app_user_id','get_app_user_id_from_auth_uid',
      'get_owner_db_ids','get_owner_property_ids',
      'get_editor_db_ids','get_editor_db_ids_from_auth_uid','get_editor_property_ids',
      'get_realtor_db_ids','get_realtor_property_ids','get_realtor_collection_ids',
      -- Те саме для гостьової гілки: пʼять політик {public} (обʼєкти, фото,
      -- файли, розклад, платежі) кличуть його і для anon, а відповідає він
      -- лише «чи Я гість цього обʼєкта».
      'is_guest_of_property'
    );
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION '052/075: anon має EXECUTE на SECURITY DEFINER функціях поза allowlist-ом: %', leaked;
  END IF;

  -- ── 075: службові функції не кличе НІХТО, крім service_role ───────────
  -- Перевірка вище дивиться лише на anon, а цим функціям не можна й
  -- authenticated: get_due_lease_reminders віддає дані ВСІХ власників, а
  -- log_db_activity пише в журнал БУДЬ-ЯКОЇ бази. Обидві були відкриті в
  -- проді, бо Supabase видає EXECUTE прямим грантом (емуляція — pg-shim).
  SELECT string_agg(p.proname || '(' ||
           CASE WHEN has_function_privilege('anon', p.oid, 'EXECUTE') THEN 'anon ' ELSE '' END ||
           CASE WHEN has_function_privilege('authenticated', p.oid, 'EXECUTE') THEN 'authenticated' ELSE '' END || ')',
         ', ' ORDER BY p.proname) INTO leaked
  FROM pg_proc p
  JOIN pg_namespace ns ON ns.oid = p.pronamespace AND ns.nspname = 'public'
  WHERE p.proname IN ('get_due_lease_reminders', 'get_due_reminders_today',
                      'get_due_guest_reminders', 'mark_overdue_payments', 'log_db_activity')
    AND (has_function_privilege('anon', p.oid, 'EXECUTE')
         OR has_function_privilege('authenticated', p.oid, 'EXECUTE'));
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION '075: службові функції викликає клієнт: %', leaked;
  END IF;
  -- Антивакуум: інакше «нікому не відкрито» означало б і «функцій немає».
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
       WHERE ns.nspname = 'public' AND p.proname IN ('get_due_lease_reminders', 'log_db_activity')) <> 2 THEN
    RAISE EXCEPTION '075: службових функцій не знайдено — перевірка вище нічого не міряла';
  END IF;
  IF NOT has_function_privilege('service_role', 'public.get_due_lease_reminders()'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '075: service_role втратив get_due_lease_reminders — крон не розішле нагадувань';
  END IF;

  -- ── 075: політики {public} кличуть лише те, що anon може виконати ──────
  -- Друга межа того самого периметра. Закривши функцію для anon, легко
  -- зачепити хелпер, який кличе САМА політика з роллю {public}: тоді
  -- анонімний запит до таблиці падає помилкою замість порожнечі — у проді
  -- це вже не «немає даних», а зламана сторінка. Питаємо ФІНАЛЬНІ політики,
  -- а не текст міграцій: старі політики давно перестворені.
  SELECT string_agg(DISTINCT f.proname, ', ') INTO leaked
  FROM pg_policies pol
  CROSS JOIN LATERAL regexp_matches(coalesce(pol.qual, '') || ' ' || coalesce(pol.with_check, ''),
                                    '([a-z_][a-z0-9_]*)\(', 'g') AS m
  JOIN pg_proc f ON f.proname = m[1]
  JOIN pg_namespace ns ON ns.oid = f.pronamespace AND ns.nspname = 'public'
  WHERE ('public' = ANY (pol.roles) OR 'anon' = ANY (pol.roles))
    AND NOT has_function_privilege('anon', f.oid, 'EXECUTE');
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION '075: політики з роллю {public} кличуть функції, закриті для anon: %', leaked;
  END IF;
  -- Антивакуум: такі політики мусять існувати, інакше перевірка порожня.
  IF NOT EXISTS (SELECT 1 FROM pg_policies pol
                  WHERE 'public' = ANY (pol.roles)
                    AND coalesce(pol.qual, '') LIKE '%is_guest_of_property(%') THEN
    RAISE EXCEPTION '075: не знайдено жодної політики {public} із хелпером — перевірка вище нічого не міряла';
  END IF;

  -- ── 075: нова функція більше не відкривається сама ─────────────────────
  -- Джерело класу — default privileges. Поки в них стоять anon/authenticated,
  -- кожна наступна службова функція знову буде відкрита, хоч би як старанно
  -- міграція знімала PUBLIC.
  -- І схемний, і глобальний запис: схемні додаються до глобальних.
  IF EXISTS (SELECT 1 FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
              WHERE (d.defaclnamespace = 0 OR n.nspname = 'public') AND d.defaclobjtype = 'f'
                AND pg_get_userbyid(d.defaclrole) = 'postgres'
                AND array_to_string(d.defaclacl, ',') ~ '(^|,)(anon|authenticated)=') THEN
    RAISE EXCEPTION '075: default privileges досі видають anon/authenticated EXECUTE на нові функції';
  END IF;

  -- ── 058: власник БЕЗ tg_id не потрапляє в розсилку ──────────────────────
  -- Інакше edge-функція кличе Telegram з `chat_id: null`, дістає 400 і НЕ
  -- пише маркер дедуплікації (він пишеться лише на `res.ok`) — тобто той
  -- самий рядок віддається ЩОДНЯ до кінця місяця. Дефект досяжний рівно з
  -- моменту, коли 052 вмикає нагадування.
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES ('aaaaaaaa-0000-0000-0000-000000000058','777058@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('bbbbbbbb-0000-0000-0000-000000000058',NULL,'БезTG','owner');
  INSERT INTO databases (id,owner_id,name,type) VALUES
    ('cccccccc-0000-0000-0000-000000000058','bbbbbbbb-0000-0000-0000-000000000058','База безTG','business_center');
  INSERT INTO properties (id,db_id,owner_id,name,status,tenant_name) VALUES
    ('dddddddd-0000-0000-0000-000000000058','cccccccc-0000-0000-0000-000000000058',
     'bbbbbbbb-0000-0000-0000-000000000058','Офіс 58','occupied','Орендар');
  INSERT INTO rent_payments (property_id,owner_id,due_day,notify_days_before,is_active)
  SELECT 'dddddddd-0000-0000-0000-000000000058','bbbbbbbb-0000-0000-0000-000000000058', d, 3, true
  FROM (SELECT EXTRACT(DAY FROM current_date + INTERVAL '3 day')::INT AS d) q
  WHERE q.d BETWEEN 1 AND 28;

  IF EXISTS (SELECT 1 FROM rent_payments rp WHERE rp.property_id='dddddddd-0000-0000-0000-000000000058') THEN
    SELECT count(*) INTO n FROM get_due_reminders_today()
     WHERE property_id='dddddddd-0000-0000-0000-000000000058';
    IF n <> 0 THEN
      RAISE EXCEPTION '058: власник без tg_id у розсилці (% рядків) — щоденний ретрай до кінця місяця', n;
    END IF;

    -- АНТИВАКУУМ, і чесно про його місце: занадто широкий предикат ловить
    -- РАНІШЕ перевірка 052 у цьому ж блоці (вона вимагає рівно 1 рядок для
    -- того самого обʼєкта) — заміряно, `AND FALSE` падає саме там. Ця
    -- перевірка лишається як друга лінія: якщо 052-й позитив колись
    -- приберуть чи переставлять, вимога «фільтр не ховає законного власника»
    -- має стояти поруч із самим фільтром, а не залежати від сусіда.
    SELECT count(*) INTO n FROM get_due_reminders_today()
     WHERE property_id='dddddddd-0000-0000-0000-000000000052';
    IF n <> 1 THEN
      RAISE EXCEPTION '058: фільтр tg_id прибрав і ЗАКОННОГО власника (% рядків)', n;
    END IF;
  END IF;

  RAISE NOTICE '  ✓ 052/058: нагадування повертають рядки; без tg_id — ні; anon не має службових функцій';
END $$;

-- ── 070: нагадування НЕ йде про вже підтверджений платіж ────────────────────
-- Функція питала лише «чи настав день» і «чи не нагадували цього місяця», тож
-- орендар, що заплатив раніше, однаково породжував «оплата через 3 дні». Плюс
-- дата ДО початку договору — платежу тоді немає взагалі.
-- Два позитиви, без яких «0 рядків» не доводить нічого: непідтверджений запис
-- (`pending`) нагадування НЕ гасить, а без дати договору воно повертається.
DO $$
DECLARE n INT; due DATE;
  v_pid CONSTANT UUID := 'dddddddd-0000-0000-0000-000000000052';
  v_owner CONSTANT UUID := 'bbbbbbbb-0000-0000-0000-000000000052';
BEGIN
  IF NOT EXISTS (SELECT 1 FROM rent_payments WHERE property_id = v_pid) THEN
    RAISE NOTICE '  · 070: день платежу сьогодні поза 1..28 — перевірку пропущено';
    RETURN;
  END IF;
  SELECT r.due_date INTO due FROM get_due_reminders_today() r WHERE r.property_id = v_pid;
  IF due IS NULL THEN
    RAISE EXCEPTION '070: законне нагадування зникло — фільтр ховає все';
  END IF;

  INSERT INTO rent_payment_records (property_id, owner_id, due_date, paid_at, amount, status)
  VALUES (v_pid, v_owner, due, now(), 1000, 'paid');
  SELECT count(*) INTO n FROM get_due_reminders_today() r WHERE r.property_id = v_pid;
  IF n <> 0 THEN
    RAISE EXCEPTION '070: нагадування про ВЖЕ підтверджений платіж (% рядків)', n;
  END IF;

  UPDATE rent_payment_records SET status = 'pending' WHERE property_id = v_pid AND due_date = due;
  SELECT count(*) INTO n FROM get_due_reminders_today() r WHERE r.property_id = v_pid;
  IF n <> 1 THEN
    RAISE EXCEPTION '070: НЕпідтверджений запис погасив нагадування (% рядків)', n;
  END IF;
  DELETE FROM rent_payment_records WHERE property_id = v_pid AND due_date = due;

  UPDATE properties SET lease_start_date = due + 1 WHERE id = v_pid;
  SELECT count(*) INTO n FROM get_due_reminders_today() r WHERE r.property_id = v_pid;
  IF n <> 0 THEN
    RAISE EXCEPTION '070: нагадування про дату ДО початку договору (% рядків)', n;
  END IF;
  UPDATE properties SET lease_start_date = NULL WHERE id = v_pid;
  SELECT count(*) INTO n FROM get_due_reminders_today() r WHERE r.property_id = v_pid;
  IF n <> 1 THEN
    RAISE EXCEPTION '070: без дати договору нагадування не повернулось (% рядків)', n;
  END IF;

  -- Гостьова функція — той самий предикат; тут доводимо, що вона ВИКОНУЄТЬСЯ
  -- після переписування (тип результату, LATERAL), бо гостьових фікстур у
  -- цьому блоці немає.
  PERFORM count(*) FROM get_due_guest_reminders();

  RAISE NOTICE '  ✓ 070: сплачене й до-договірне не нагадується; pending і без договору — так';
END $$;

-- ── 065: нагадування про КІНЕЦЬ ДОГОВОРУ ────────────────────────────────────
-- Три властивості, і кожна ламається окремо:
--   • ПОРІГ — рядок віддається рівно на {30,7,1,0} днях, а не щодня все вікно
--     (щоденна розсилка 30 днів поспіль — це шум, після якого нагадування
--     вимикають);
--   • ДЕДУП — після успішної відправки той самий поріг більше не повертається;
--   • ПРОДОВЖЕННЯ — зміна `lease_end_date` відкриває НОВУ серію, бо ключ дедупу
--     містить саму дату. Без цього продовжений договір не нагадав би про себе
--     ніколи: старий рядок `notifications` лишається назавжди.
--
-- Позитивний контроль тут не додатковий, а несучий: перевірка «на 14-й день
-- нічого не приходить» проходить і на функції, яка не віддає НІЧОГО взагалі —
-- рівно те, чим 052 була зламана роками (тип результату не збігався, і жоден
-- рядок не міг зʼявитись).
DO $$
DECLARE n INT;
BEGIN
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES ('aaaaaaaa-0000-0000-0000-000000000065','777065@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('bbbbbbbb-0000-0000-0000-000000000065',777065,'Лізинг','owner');
  INSERT INTO databases (id,owner_id,name,type) VALUES
    ('cccccccc-0000-0000-0000-000000000065','bbbbbbbb-0000-0000-0000-000000000065','База 065','business_center');

  -- Рівно на порозі 7 днів.
  INSERT INTO properties (id,db_id,owner_id,name,status,tenant_name,lease_end_date) VALUES
    ('dddddddd-0000-0000-0000-000000000065','cccccccc-0000-0000-0000-000000000065',
     'bbbbbbbb-0000-0000-0000-000000000065','Офіс 065','occupied','Орендар 065', current_date + 7);
  -- Всередині вікна, але НЕ на порозі.
  INSERT INTO properties (id,db_id,owner_id,name,status,lease_end_date) VALUES
    ('dddddddd-0000-0000-0000-000000000066','cccccccc-0000-0000-0000-000000000065',
     'bbbbbbbb-0000-0000-0000-000000000065','Офіс 066','occupied', current_date + 14);
  -- Вільний обʼєкт із датою — договору немає, нагадувати нема про що.
  INSERT INTO properties (id,db_id,owner_id,name,status,lease_end_date) VALUES
    ('dddddddd-0000-0000-0000-000000000067','cccccccc-0000-0000-0000-000000000065',
     'bbbbbbbb-0000-0000-0000-000000000065','Офіс 067','free', current_date + 7);

  SELECT count(*) INTO n FROM get_due_lease_reminders()
   WHERE property_id='dddddddd-0000-0000-0000-000000000065';
  IF n <> 1 THEN
    RAISE EXCEPTION '065: поріг 7 днів не спрацював (% рядків) — нагадувань про договори не буде', n;
  END IF;

  SELECT count(*) INTO n FROM get_due_lease_reminders()
   WHERE property_id IN ('dddddddd-0000-0000-0000-000000000066','dddddddd-0000-0000-0000-000000000067');
  IF n <> 0 THEN
    RAISE EXCEPTION '065: розсилка пішла поза порогом або на вільний обʼєкт (% рядків)', n;
  END IF;

  -- Маркер дедупу — саме той рядок, який пише edge-функція на `res.ok`.
  INSERT INTO notifications (user_id,type,title,body,is_read,data) VALUES (
    'bbbbbbbb-0000-0000-0000-000000000065','lease_reminder','Договір','Закінчується',false,
    jsonb_build_object(
      'property_id','dddddddd-0000-0000-0000-000000000065',
      'lease_end_date',(current_date + 7)::TEXT,
      'days_left',7));

  SELECT count(*) INTO n FROM get_due_lease_reminders()
   WHERE property_id='dddddddd-0000-0000-0000-000000000065';
  IF n <> 0 THEN
    RAISE EXCEPTION '065: дедуп не тримає — той самий поріг піде ЩОДНЯ (% рядків)', n;
  END IF;

  -- ПРОДОВЖЕННЯ ДОГОВОРУ. Перша редакція цієї перевірки була ВАКУУМНОЮ, і це
  -- спіймала власна фальсифікація: вона просто змінювала дату на +30, тобто
  -- разом із датою мінявся й `days_left` (7 → 30), і рядок повертався навіть
  -- без дати в ключі дедупу. Причина глибша за недогляд: у МЕЖАХ ОДНОГО ДНЯ
  -- дата й `days_left` — та сама інформація (`days_left = дата - сьогодні`),
  -- тож на одноденному стенді дату перевірити НЕМОЖЛИВО, змінюючи дату.
  --
  -- Дата несе сенс МІЖ днями: договір закінчився, обʼєкт здали знову, і новий
  -- договір теж підходить до порога 7 днів — але вже іншою датою. Відтворюємо
  -- саме це: маркер дедупу з тим самим `days_left`, але від ІНШОГО договору.
  DELETE FROM notifications WHERE user_id='bbbbbbbb-0000-0000-0000-000000000065';
  INSERT INTO notifications (user_id,type,title,body,is_read,data) VALUES (
    'bbbbbbbb-0000-0000-0000-000000000065','lease_reminder','Договір','Закінчується',false,
    jsonb_build_object(
      'property_id','dddddddd-0000-0000-0000-000000000065',
      'lease_end_date',(current_date + 100)::TEXT,   -- ПОПЕРЕДНІЙ договір
      'days_left',7));                               -- той самий поріг

  SELECT count(*) INTO n FROM get_due_lease_reminders()
   WHERE property_id='dddddddd-0000-0000-0000-000000000065';
  IF n <> 1 THEN
    RAISE EXCEPTION '065: НОВИЙ договір задушено маркером СТАРОГО (% рядків) — про продовжений договір не нагадає ніхто', n;
  END IF;

  RAISE NOTICE '  ✓ 065: пороги тримаються, дедуп працює, продовження відкриває нову серію';
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- 067: АРХІВ ОРЕНД — тригер мусить спрацювати на ВСІХ шляхах обнулення
-- ════════════════════════════════════════════════════════════════════════════
-- Головне тут — не «рядок створився», а ПОВНОТА: орендаря обнуляють три різні
-- екрани, і запис в обробнику однієї кнопки покрив би один шлях із трьох.
-- Тому кожен шлях відтворюється тим самим UPDATE, який робить саме він.
DO $$
DECLARE
  o  UUID := 'bbbbbbbb-0000-0000-0000-000000000067';
  d  UUID := 'cccccccc-0000-0000-0000-000000000067';
  p1 UUID := 'dddddddd-0000-0000-0000-000000000671';
  p2 UUID := 'dddddddd-0000-0000-0000-000000000672';
  p3 UUID := 'dddddddd-0000-0000-0000-000000000673';
  n  INT;
  t  RECORD;
BEGIN
  INSERT INTO users (id, tg_id, first_name, role, currency)
    VALUES (o, 670001, 'Оксана', 'owner', 'UAH') ON CONFLICT DO NOTHING;
  INSERT INTO databases (id, owner_id, name, type)
    VALUES (d, o, 'Архівна база', 'business_center') ON CONFLICT DO NOTHING;

  -- ── Здача: рядок мусить ВІДКРИТИСЬ, а не чекати на звільнення ─────────────
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name,
                          rent_rate, rent_type, area_useful, lease_start_date)
    VALUES (p1, d, o, 'Офіс 1', 'occupied', 'Орендар Перший',
            100, 'per_m2', 50, current_date - 30);

  SELECT count(*) INTO n FROM tenancies WHERE property_id = p1 AND ended_at IS NULL;
  IF n <> 1 THEN
    RAISE EXCEPTION '067: здача НЕ відкрила оренду (% рядків) — архів побачив би лише минуле, а не поточні відносини', n;
  END IF;

  -- Заморожені факти мусять доїхати, інакше архівна картка порожня.
  SELECT * INTO t FROM tenancies WHERE property_id = p1 AND ended_at IS NULL;
  IF t.tenant_name <> 'Орендар Перший' OR t.rent_rate <> 100 OR t.currency <> 'UAH' THEN
    RAISE EXCEPTION '067: факти не заморозились (орендар=%, ставка=%, валюта=%)',
      t.tenant_name, t.rent_rate, t.currency;
  END IF;

  -- ── ШЛЯХ 1: «Звільнити обʼєкт» (PropertyDetailScreen) ─────────────────────
  -- Той самий UPDATE, що й у коді: статус І обнулення орендаря ОДНІЄЮ
  -- операцією. Саме тому тригер бере факти з OLD, а не з NEW.
  UPDATE properties SET status='free', tenant_name=NULL,
         lease_start_date=NULL, lease_end_date=NULL WHERE id = p1;

  SELECT * INTO t FROM tenancies WHERE property_id = p1 ORDER BY started_at DESC LIMIT 1;
  IF t.ended_at IS NULL THEN
    RAISE EXCEPTION '067/шлях-1: оренда не закрилась — звільнення лишилось безслідним';
  END IF;
  IF t.tenant_name IS DISTINCT FROM 'Орендар Перший' THEN
    RAISE EXCEPTION '067/шлях-1: орендар загубився при закритті (=%) — узято з NEW замість OLD', t.tenant_name;
  END IF;

  -- ── СКАСУВАННЯ: повертає ТУ САМУ оренду, а не плодить другу ───────────────
  UPDATE properties SET status='occupied', tenant_name='Орендар Перший',
         lease_start_date = current_date - 30 WHERE id = p1;

  SELECT count(*) INTO n FROM tenancies WHERE property_id = p1;
  IF n <> 1 THEN
    RAISE EXCEPTION '067: «Скасувати» створило ДРУГУ оренду (% всього) — в архіві зʼявилась би трисекундна фантомна оренда', n;
  END IF;
  SELECT count(*) INTO n FROM tenancies WHERE property_id = p1 AND ended_at IS NULL;
  IF n <> 1 THEN
    RAISE EXCEPTION '067: «Скасувати» не повернуло оренду у відкритий стан';
  END IF;

  -- АНТИВАКУУМ: вікно скасування не сміє зливати РІЗНІ оренди. Інший орендар
  -- одразу після звільнення — це НОВІ відносини, і вони мусять бути окремим
  -- рядком, інакше «повернення» з'їдало б реальну історію.
  UPDATE properties SET status='free', tenant_name=NULL WHERE id = p1;
  UPDATE properties SET status='occupied', tenant_name='Орендар Другий' WHERE id = p1;
  SELECT count(*) INTO n FROM tenancies WHERE property_id = p1;
  IF n <> 2 THEN
    RAISE EXCEPTION '067: ІНШИЙ орендар не створив нову оренду (% всього) — вікно скасування зливає різні відносини', n;
  END IF;

  -- ── ШЛЯХ 2: пакетне «Вільно» (useProperties.batchUpdateStatus) ────────────
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name, rent_rate, rent_type)
    VALUES (p2, d, o, 'Офіс 2', 'occupied', 'Орендар Пакетний', 200, 'fixed');
  UPDATE properties SET status='free', tenant_name=NULL,
         lease_start_date=NULL, lease_end_date=NULL WHERE id IN (p2);
  SELECT count(*) INTO n FROM tenancies
    WHERE property_id = p2 AND ended_at IS NOT NULL AND tenant_name = 'Орендар Пакетний';
  IF n <> 1 THEN
    RAISE EXCEPTION '067/шлях-2: пакетне звільнення не заархівувало оренду (% рядків)', n;
  END IF;

  -- ── ШЛЯХ 3: форма обʼєкта зі статусом ≠ «Зайнято» ─────────────────────────
  -- Тут UPDATE несе ВЕСЬ payload форми, а не лише статус — саме цим він і
  -- відрізняється від двох попередніх.
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name, rent_rate, rent_type)
    VALUES (p3, d, o, 'Офіс 3', 'occupied', 'Орендар Формений', 300, 'fixed');
  UPDATE properties SET status='for_sale', tenant_name=NULL, lease_start_date=NULL,
         lease_end_date=NULL, name='Офіс 3', rent_rate=300, area_useful=70 WHERE id = p3;
  SELECT count(*) INTO n FROM tenancies
    WHERE property_id = p3 AND ended_at IS NOT NULL AND tenant_name = 'Орендар Формений';
  IF n <> 1 THEN
    RAISE EXCEPTION '067/шлях-3: збереження форми не заархівувало оренду (% рядків)', n;
  END IF;

  -- ── Перейменування орендаря НЕ ділить оренду надвоє ───────────────────────
  -- Виправлення одруківки не сміє фабрикувати неіснуючі правовідносини.
  UPDATE properties SET tenant_name='Орендар Другий (ФОП)' WHERE id = p1;
  SELECT count(*) INTO n FROM tenancies WHERE property_id = p1;
  IF n <> 2 THEN
    RAISE EXCEPTION '067: перейменування орендаря розділило оренду (% всього)', n;
  END IF;
  SELECT tenant_name INTO t FROM tenancies WHERE property_id = p1 AND ended_at IS NULL;
  IF t.tenant_name <> 'Орендар Другий (ФОП)' THEN
    RAISE EXCEPTION '067: відкрита оренда не синхронізувалась (=%)', t.tenant_name;
  END IF;

  -- ── Видалення ОБʼЄКТА не стирає історію, видалення БАЗИ стирає ────────────
  DELETE FROM properties WHERE id = p2;
  SELECT count(*) INTO n FROM tenancies WHERE property_name = 'Офіс 2' AND property_id IS NULL;
  IF n <> 1 THEN
    RAISE EXCEPTION '067: видалення обʼєкта стерло фінансову історію (% рядків лишилось)', n;
  END IF;

  RAISE NOTICE '  ✓ 067: усі три шляхи архівують, скасування повертає оренду, історія переживає обʼєкт';
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- 071: ЧАСТКОВА ОПЛАТА — підсумок періоду рахує СЕРВЕР із надходжень
-- ════════════════════════════════════════════════════════════════════════════
-- Тут — арифметика й життєвий цикл (від postgres, тобто без RLS); хто що
-- може — у verify-rls.sql. Кожен перехід стану перевіряється разом із сумою:
-- «статус правильний, сума ні» — це рівно той клас, що в обліку найдорожчий.
DO $$
DECLARE
  o  UUID := 'bbbbbbbb-0000-0000-0000-000000000071';
  d  UUID := 'cccccccc-0000-0000-0000-000000000071';
  p  UUID := 'dddddddd-0000-0000-0000-000000000711';
  pl UUID := 'dddddddd-0000-0000-0000-000000000712';
  v  JSONB;
  r  RECORD;
  part2 UUID;
  n  INT;
BEGIN
  INSERT INTO users (id, tg_id, first_name, role) VALUES (o, 710001, 'Платник', 'owner');
  INSERT INTO databases (id, owner_id, name, type) VALUES (d, o, 'База 071', 'business_center');
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name) VALUES
    (p,  d, o, 'Офіс 71',  'occupied', 'ТОВ Частковий'),
    (pl, d, o, 'Офіс 72',  'occupied', 'ФОП Легасі');

  -- ── Перше надходження менше за очікуване → «частково» ─────────────────────
  v := record_rent_payment(p, DATE '2026-09-05', 1000, now() - INTERVAL '2 day', 'Готівка', 1800);
  IF v->>'error' IS NOT NULL THEN RAISE EXCEPTION '071: RPC відмовив: %', v->>'error'; END IF;
  IF v->>'status' IS DISTINCT FROM 'partial' OR (v->>'amount')::NUMERIC <> 1000
     OR (v->>'amount_due')::NUMERIC <> 1800 THEN
    RAISE EXCEPTION '071: перше надходження дало %', v;
  END IF;

  -- ── Доплата закриває період; ЗАМОРОЖЕНА сума не рухається ─────────────────
  -- Ставка за цей час «зросла» до 2500: передаємо нову очікувану, і вона НЕ
  -- сміє застосуватись до вже відкритого періоду — інакше вересень став би
  -- частковим заднім числом.
  v := record_rent_payment(p, DATE '2026-09-05', 800, now(), NULL, 2500);
  IF v->>'status' IS DISTINCT FROM 'paid' OR (v->>'amount')::NUMERIC <> 1800
     OR (v->>'amount_due')::NUMERIC <> 1800 THEN
    RAISE EXCEPTION '071: доплата дала % (очікувано paid, 1800, due 1800)', v;
  END IF;
  part2 := (v->>'part_id')::UUID;
  SELECT * INTO r FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  IF r.paid_at IS NULL OR r.paid_at < now() - INTERVAL '1 minute' THEN
    RAISE EXCEPTION '071: дата періоду — не дата ОСТАННЬОГО надходження (%)', r.paid_at;
  END IF;

  -- ── Видалення надходження повертає борг ───────────────────────────────────
  DELETE FROM rent_payment_parts WHERE id = part2;
  SELECT * INTO r FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  IF r.status <> 'partial' OR r.amount <> 1000 THEN
    RAISE EXCEPTION '071: після видалення доплати період % / % (очікувано partial / 1000)', r.status, r.amount;
  END IF;

  -- ── Виправлення суми надходження перераховує період ───────────────────────
  UPDATE rent_payment_parts SET amount = 2000
   WHERE record_id = r.id;
  SELECT * INTO r FROM rent_payment_records WHERE id = r.id;
  IF r.status <> 'paid' OR r.amount <> 2000 THEN
    RAISE EXCEPTION '071: виправлена сума не перерахувала період (% / %)', r.status, r.amount;
  END IF;

  -- ── Без жодного надходження період знову НЕоплачений, а не «$0 отримано» ──
  DELETE FROM rent_payment_parts WHERE record_id = r.id;
  SELECT * INTO r FROM rent_payment_records WHERE id = r.id;
  IF r.status = 'paid' OR r.status = 'partial' OR r.amount IS NOT NULL OR r.paid_at IS NOT NULL THEN
    RAISE EXCEPTION '071: період без надходжень лишився % / % / %', r.status, r.amount, r.paid_at;
  END IF;

  -- ── Каскад: «Скасувати платіж» видаляє період разом із надходженнями ──────
  v := record_rent_payment(p, DATE '2026-09-05', 500, now(), NULL, NULL);
  DELETE FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  SELECT count(*) INTO n FROM rent_payment_parts pp
    LEFT JOIN rent_payment_records rr ON rr.id = pp.record_id WHERE rr.id IS NULL;
  IF n <> 0 THEN RAISE EXCEPTION '071: каскад лишив % осиротілих надходжень', n; END IF;

  -- ── Без очікуваної суми (обʼєкт без ставки) будь-яке надходження закриває ──
  v := record_rent_payment(p, DATE '2026-10-05', 300, now(), NULL, NULL);
  IF v->>'status' IS DISTINCT FROM 'paid' THEN
    RAISE EXCEPTION '071: без очікуваної суми період не закрився (%)', v;
  END IF;

  -- ── Ввід, якого не буває ──────────────────────────────────────────────────
  v := record_rent_payment(p, DATE '2026-11-05', 0, now(), NULL, 1800);
  IF v->>'error' IS DISTINCT FROM 'invalid_amount' THEN RAISE EXCEPTION '071: нульова сума пройшла (%)', v; END IF;
  v := record_rent_payment(p, DATE '2026-11-05', 100, now() + INTERVAL '10 day', NULL, 1800);
  IF v->>'error' IS DISTINCT FROM 'invalid_date' THEN RAISE EXCEPTION '071: дата з майбутнього пройшла (%)', v; END IF;
  -- Відмова не сміє лишати порожній період.
  SELECT count(*) INTO n FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-11-05';
  IF n <> 0 THEN RAISE EXCEPTION '071: відхилений ввід лишив період'; END IF;

  -- ── Період, підтверджений СТАРИМ клієнтом, не губить своїх грошей ─────────
  -- Кешована вкладка пише `paid` + суму напряму, без надходжень. Нове
  -- надходження мусить ДОДАТИСЬ до цієї суми, а не замінити її.
  INSERT INTO rent_payment_records (property_id, owner_id, due_date, paid_at, amount, status, notes)
  VALUES (pl, o, DATE '2026-08-05', now() - INTERVAL '30 day', 1800, 'paid', 'Переказ');
  v := record_rent_payment(pl, DATE '2026-08-05', 200, now(), 'Переплата', NULL);
  IF (v->>'amount')::NUMERIC <> 2000 THEN
    RAISE EXCEPTION '071: нове надходження затерло суму старого клієнта (%)', v;
  END IF;
  SELECT count(*) INTO n FROM rent_payment_parts pp JOIN rent_payment_records rr ON rr.id = pp.record_id
   WHERE rr.property_id = pl AND rr.due_date = DATE '2026-08-05';
  IF n <> 2 THEN RAISE EXCEPTION '071: старе підтвердження не стало надходженням (% частин)', n; END IF;

  -- ── Статус «частково» — легальне значення, а не обхід CHECK ───────────────
  BEGIN
    UPDATE rent_payment_records SET status = 'bogus' WHERE property_id = pl;
    RAISE EXCEPTION '071: CHECK статусу пропускає довільні значення';
  EXCEPTION WHEN check_violation THEN NULL;
  END;

  RAISE NOTICE '  ✓ 071: частково → оплачено → назад; сума заморожена; каскад; старий клієнт не губить грошей';
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- 072: УМОВИ ОРЕНДИ В ЧАСІ — історія ставок і сума за конкретний період
-- ════════════════════════════════════════════════════════════════════════════
-- Тригер мусить писати СТАРІ умови рівно тоді, коли вони змінились, — і
-- мовчати, коли форма просто перезберегла ті самі значення (вона шле всі
-- поля щоразу). Обидва боки тут, бо гард лише на «пише» пройшов би і на
-- тригері, що пише ЗАВЖДИ, тобто вигадує зміни, яких не було.
DO $$
DECLARE
  o  UUID := 'bbbbbbbb-0000-0000-0000-000000000072';
  d  UUID := 'cccccccc-0000-0000-0000-000000000072';
  p  UUID := 'dddddddd-0000-0000-0000-000000000721';
  pl UUID := 'dddddddd-0000-0000-0000-000000000722';
  v  JSONB;
  r  RECORD;
  n  INT;
BEGIN
  INSERT INTO users (id, tg_id, first_name, role) VALUES (o, 720001, 'Ставка', 'owner');
  INSERT INTO databases (id, owner_id, name, type) VALUES (d, o, 'База 072', 'business_center');
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name, rent_type, rent_rate, area_total, area_basis) VALUES
    (p,  d, o, 'Офіс 72', 'occupied', 'ТОВ Ставка', 'fixed', 1800, 50, 'total'),
    (pl, d, o, 'Офіс 73', 'occupied', 'ФОП Легасі', 'fixed', 1800, 50, 'total');

  -- ── Перейменування і перезбереження тих самих умов — НЕ зміна умов ──────
  UPDATE properties SET name = 'Офіс 72а' WHERE id = p;
  UPDATE properties SET rent_rate = 1800, rent_type = 'fixed', area_total = 50, area_basis = 'total' WHERE id = p;
  SELECT count(*) INTO n FROM property_rent_terms WHERE property_id = p;
  IF n <> 0 THEN RAISE EXCEPTION '072: перезбереження тих самих умов записало % «змін»', n; END IF;

  -- ── Підняв ставку → в історії СТАРІ умови з міткою зміни ─────────────────
  UPDATE properties SET rent_rate = 2000 WHERE id = p;
  SELECT * INTO r FROM property_rent_terms WHERE property_id = p;
  IF NOT FOUND THEN RAISE EXCEPTION '072: зміна ставки не записалась в історію'; END IF;
  IF r.rent_rate <> 1800 OR r.rent_type <> 'fixed' OR r.area_total <> 50 THEN
    RAISE EXCEPTION '072: в історію лягли НЕ старі умови (% / % / %)', r.rent_rate, r.rent_type, r.area_total;
  END IF;
  IF r.valid_until < now() - INTERVAL '1 minute' THEN
    RAISE EXCEPTION '072: мітка зміни не «зараз» (%)', r.valid_until;
  END IF;

  -- Площа теж міняє суму для $/м² — і теж записується.
  UPDATE properties SET area_total = 60 WHERE id = p;
  SELECT count(*) INTO n FROM property_rent_terms WHERE property_id = p;
  IF n <> 2 THEN RAISE EXCEPTION '072: зміна площі не записалась (% рядків)', n; END IF;

  -- ── Сума за період: неоплачений період отримує свою суму ─────────────────
  v := set_rent_amount_due(p, DATE '2026-08-05', 900);
  IF v->>'error' IS NOT NULL OR v->>'status' IS DISTINCT FROM 'pending' OR (v->>'amount_due')::NUMERIC <> 900 THEN
    RAISE EXCEPTION '072: сума неоплаченого періоду дала %', v;
  END IF;

  -- ── Із надходженнями: зміна суми ПЕРЕРАХОВУЄ стан ────────────────────────
  v := record_rent_payment(p, DATE '2026-09-05', 1000, now(), NULL, 1800);
  IF v->>'status' IS DISTINCT FROM 'partial' THEN RAISE EXCEPTION '072: фікстура: %', v; END IF;
  -- Неповний місяць: домовились на $1 000 — період закритий.
  v := set_rent_amount_due(p, DATE '2026-09-05', 1000);
  IF v->>'status' IS DISTINCT FROM 'paid' THEN
    RAISE EXCEPTION '072: сума, рівна отриманому, не закрила період (%)', v;
  END IF;
  SELECT * INTO r FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  IF r.status <> 'paid' OR r.amount <> 1000 OR r.amount_due <> 1000 THEN
    RAISE EXCEPTION '072: період після зміни суми % / % / %', r.status, r.amount, r.amount_due;
  END IF;
  -- І назад: більша сума знову робить період частковим, гроші не губляться.
  v := set_rent_amount_due(p, DATE '2026-09-05', 1500);
  SELECT * INTO r FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  IF r.status <> 'partial' OR r.amount <> 1000 THEN
    RAISE EXCEPTION '072: збільшена сума дала % / % (очікувано partial / 1000)', r.status, r.amount;
  END IF;
  -- Наступне надходження рахується від НОВОЇ суми, а не від старої ставки.
  v := record_rent_payment(p, DATE '2026-09-05', 500, now(), NULL, 2000);
  IF v->>'status' IS DISTINCT FROM 'paid' OR (v->>'amount_due')::NUMERIC <> 1500 THEN
    RAISE EXCEPTION '072: доплата після зміни суми дала %', v;
  END IF;

  -- ── Період старого клієнта (сума без надходжень) не губить грошей ────────
  INSERT INTO rent_payment_records (property_id, owner_id, due_date, paid_at, amount, status)
  VALUES (pl, o, DATE '2026-08-05', now() - INTERVAL '20 day', 1800, 'paid');
  v := set_rent_amount_due(pl, DATE '2026-08-05', 2000);
  IF v->>'status' IS DISTINCT FROM 'partial' THEN
    RAISE EXCEPTION '072: старе підтвердження не врахувалось у перерахунку (%)', v;
  END IF;
  SELECT amount INTO r FROM rent_payment_records WHERE property_id = pl AND due_date = DATE '2026-08-05';
  IF r.amount <> 1800 THEN RAISE EXCEPTION '072: отримані $1 800 старого клієнта стали %', r.amount; END IF;

  -- ── Ввід, якого не буває ──────────────────────────────────────────────────
  v := set_rent_amount_due(p, DATE '2026-10-05', 0);
  IF v->>'error' IS DISTINCT FROM 'invalid_amount' THEN RAISE EXCEPTION '072: нульова сума пройшла (%)', v; END IF;
  v := set_rent_amount_due('dddddddd-0000-0000-0000-00000000ffff', DATE '2026-10-05', 100);
  IF v->>'error' IS DISTINCT FROM 'not_found' THEN RAISE EXCEPTION '072: неіснуючий обʼєкт: %', v; END IF;
  SELECT count(*) INTO n FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-10-05';
  IF n <> 0 THEN RAISE EXCEPTION '072: відхилений ввід лишив період'; END IF;

  -- ── Історія йде разом з обʼєктом ─────────────────────────────────────────
  DELETE FROM properties WHERE id = p;
  SELECT count(*) INTO n FROM property_rent_terms WHERE property_id = p;
  IF n <> 0 THEN RAISE EXCEPTION '072: історія умов пережила обʼєкт (% рядків)', n; END IF;

  RAISE NOTICE '  ✓ 072: історія пише лише справжні зміни; сума періоду перераховує стан і не губить грошей';
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- 073: ХТО ЩО ЗРОБИВ — автор надходження і журнал змін бази
-- ════════════════════════════════════════════════════════════════════════════
-- Від postgres, але З особою в JWT: тригери питають `current_app_user_id()`,
-- а RLS тут не предмет (вона — у verify-rls.sql). Кожна подія перевіряється
-- разом із тим, ЧИЄЮ вона записана, а «тиша» — разом із позитивом поруч:
-- журнал, що мовчить завжди, пройшов би всі «не записав зайвого».
CREATE OR REPLACE FUNCTION pg_temp.as_user(p_tg BIGINT) RETURNS VOID
LANGUAGE plpgsql AS $$ BEGIN
  -- З 076 особу засвідчує обліковий запис, створений edge-функцією, а не
  -- сам email у токені. Користувачі цього блоку сіються без нього, тож
  -- «вхід» створює його тим самим шляхом, що й справжній перший вхід.
  IF p_tg IS NOT NULL AND NOT EXISTS (SELECT 1 FROM auth.users WHERE email = p_tg || '@telegram.propspace.app') THEN
    PERFORM auth.shim_create_user(NULL, p_tg || '@telegram.propspace.app');
  END IF;
  PERFORM set_config('request.jwt.claims',
    CASE WHEN p_tg IS NULL THEN '' ELSE json_build_object('email', p_tg || '@telegram.propspace.app')::TEXT END,
    false);
END $$;

DO $$
DECLARE
  o  UUID := 'bbbbbbbb-0000-0000-0000-000000000073';
  e  UUID := 'bbbbbbbb-0000-0000-0000-000000000731';
  d  UUID := 'cccccccc-0000-0000-0000-000000000073';
  p  UUID := 'dddddddd-0000-0000-0000-000000000731';
  pl UUID := 'dddddddd-0000-0000-0000-000000000732';
  v  JSONB;
  r  RECORD;
  n  INT;
  n0 INT;
  part UUID;
  f  UUID;
BEGIN
  INSERT INTO users (id, tg_id, first_name, last_name, role) VALUES
    (o, 730001, 'Власник', 'Журналу', 'owner'),
    (e, 730002, 'Редактор', NULL, 'realtor');
  INSERT INTO databases (id, owner_id, name, type) VALUES (d, o, 'База 073', 'business_center');
  INSERT INTO db_members (db_id, user_id, role, status) VALUES (d, e, 'editor', 'active');

  -- ── Створення — подія з автором ───────────────────────────────────────────
  PERFORM pg_temp.as_user(730001);
  INSERT INTO properties (id, db_id, owner_id, name, status, rent_type, rent_rate) VALUES
    (p, d, o, 'Офіс 73', 'free', 'fixed', 1800);
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'property_created';
  IF NOT FOUND OR r.actor_id <> o OR r.actor_name <> 'Власник Журналу' OR r.property_name <> 'Офіс 73' THEN
    RAISE EXCEPTION '073: створення обʼєкта не записалось або без автора (%)', r;
  END IF;

  -- ── Шум без змісту — не подія ─────────────────────────────────────────────
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d;
  UPDATE properties SET sort_order = 500, description = 'ремонт' WHERE id = p;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d;
  IF n <> n0 THEN RAISE EXCEPTION '073: порядок/опис записали % подій', n - n0; END IF;

  -- ── Здано, змінено орендаря, змінено ставку ───────────────────────────────
  UPDATE properties SET status = 'occupied', tenant_name = 'ТОВ Перший' WHERE id = p;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'property_rented';
  IF r.details->>'tenant' IS DISTINCT FROM 'ТОВ Перший' THEN RAISE EXCEPTION '073: здача без орендаря (%)', r.details; END IF;
  UPDATE properties SET tenant_name = 'ТОВ Другий' WHERE id = p;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'tenant_changed';
  IF r.details->>'from' IS DISTINCT FROM 'ТОВ Перший' OR r.details->>'to' IS DISTINCT FROM 'ТОВ Другий' THEN
    RAISE EXCEPTION '073: зміна орендаря %', r.details;
  END IF;
  UPDATE properties SET rent_rate = 2000 WHERE id = p;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'terms_changed';
  IF (r.details->'from'->>'rent_rate')::NUMERIC <> 1800 OR (r.details->'to'->>'rent_rate')::NUMERIC <> 2000 THEN
    RAISE EXCEPTION '073: зміна ставки %', r.details;
  END IF;

  -- ── Гроші вписує РЕДАКТОР: автор — він, і підробити не може ───────────────
  PERFORM pg_temp.as_user(730002);
  v := record_rent_payment(p, DATE '2026-09-05', 1000, now(), NULL, 2000);
  SELECT * INTO r FROM rent_payment_parts WHERE id = (v->>'part_id')::UUID;
  IF r.created_by IS DISTINCT FROM e OR r.created_by_name IS DISTINCT FROM 'Редактор' THEN
    RAISE EXCEPTION '073: автор надходження % / % (очікувано редактор)', r.created_by, r.created_by_name;
  END IF;
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, created_by, created_by_name)
  VALUES ((v->>'record_id')::UUID, 100, now(), o, 'Власник Журналу') RETURNING id INTO part;
  SELECT * INTO r FROM rent_payment_parts WHERE id = part;
  IF r.created_by IS DISTINCT FROM e THEN
    RAISE EXCEPTION '073: редактор ЗАПИСАВ гроші від імені власника (автор %)', r.created_by_name;
  END IF;
  -- Виправлення суми — подія, але автор лишається тим, хто вписав.
  PERFORM pg_temp.as_user(730001);
  UPDATE rent_payment_parts SET amount = 150, created_by = o WHERE id = part;
  SELECT * INTO r FROM rent_payment_parts WHERE id = part;
  IF r.created_by IS DISTINCT FROM e THEN RAISE EXCEPTION '073: виправлення переписало автора надходження'; END IF;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'payment_edited';
  IF NOT FOUND OR r.actor_id <> o OR (r.details->>'to')::NUMERIC <> 150 THEN
    RAISE EXCEPTION '073: виправлення надходження не записалось (%)', r;
  END IF;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND kind = 'payment_received' AND actor_id = e;
  IF n <> 2 THEN RAISE EXCEPTION '073: надходження редактора записались % раз (очікувано 2)', n; END IF;

  -- ── Сума за період (072) — подія навіть для НОВОГО періоду ────────────────
  v := set_rent_amount_due(p, DATE '2026-10-05', 900);
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'due_changed';
  IF NOT FOUND OR (r.details->>'to')::NUMERIC <> 900 THEN RAISE EXCEPTION '073: сума за період не записалась (%)', r; END IF;

  -- ── Скасування платежу — ОДНА подія, без каскаду «видалено надходження» ──
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d;
  DELETE FROM rent_payment_records WHERE property_id = p AND due_date = DATE '2026-09-05';
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d;
  IF n - n0 <> 1 THEN RAISE EXCEPTION '073: скасування платежу дало % подій (очікувано 1)', n - n0; END IF;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'payment_cancelled';
  IF (r.details->>'amount')::NUMERIC <> 1150 THEN RAISE EXCEPTION '073: скасовано не ту суму (%)', r.details; END IF;

  -- ── Розклад: створення — подія, перезбереження тих самих значень — ні ────
  INSERT INTO rent_payments (property_id, owner_id, due_day) VALUES (p, o, 5);
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d AND kind = 'schedule_set';
  UPDATE rent_payments SET due_day = 5, is_active = true WHERE property_id = p;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND kind = 'schedule_set';
  IF n0 <> 1 OR n <> 1 THEN RAISE EXCEPTION '073: розклад: % подій після створення, % після перезбереження', n0, n; END IF;

  -- ── Документи ─────────────────────────────────────────────────────────────
  INSERT INTO property_files (property_id, owner_id, storage_path, file_name, mime_type)
  VALUES (p, o, p || '/1_a.pdf', 'Договір.pdf', 'application/pdf') RETURNING id INTO f;
  DELETE FROM property_files WHERE id = f;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND kind IN ('file_added', 'file_deleted')
    AND details->>'name' = 'Договір.pdf';
  IF n <> 2 THEN RAISE EXCEPTION '073: документ: % подій (очікувано додано + видалено)', n; END IF;

  -- ── Звільнення: орендар — з OLD, бо NEW його вже обнулив ─────────────────
  UPDATE properties SET status = 'free', tenant_name = NULL WHERE id = p;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'property_vacated';
  IF r.details->>'tenant' IS DISTINCT FROM 'ТОВ Другий' THEN RAISE EXCEPTION '073: звільнення без орендаря (%)', r.details; END IF;

  -- ── Без особи (крон, міграція) — не «хтось зробив» ───────────────────────
  PERFORM pg_temp.as_user(NULL);
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d;
  UPDATE properties SET name = 'Офіс 73 (крон)' WHERE id = p;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d;
  IF n <> n0 THEN RAISE EXCEPTION '073: дія без особи записалась у журнал'; END IF;

  -- ── Перенесене підтвердження старого клієнта: без автора і без події ─────
  PERFORM pg_temp.as_user(730001);
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name, rent_type, rent_rate)
  VALUES (pl, d, o, 'Офіс 74', 'occupied', 'ФОП Легасі', 'fixed', 1800);
  INSERT INTO rent_payment_records (property_id, owner_id, due_date, paid_at, amount, status)
  VALUES (pl, o, DATE '2026-08-05', now() - INTERVAL '20 day', 1800, 'paid');
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d AND kind = 'payment_received';
  v := record_rent_payment(pl, DATE '2026-08-05', 200, now(), NULL, NULL);
  SELECT count(*) INTO n FROM rent_payment_parts pp JOIN rent_payment_records rr ON rr.id = pp.record_id
   WHERE rr.property_id = pl AND pp.created_by IS NULL;
  IF n <> 1 THEN RAISE EXCEPTION '073: перенесене підтвердження приписано тому, хто доплатив (% без автора)', n; END IF;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND kind = 'payment_received';
  IF n - n0 <> 1 THEN RAISE EXCEPTION '073: перенос старого підтвердження записав % подій «отримано»', n - n0; END IF;

  -- ── Журнал НЕ СМІЄ ламати дію: збій запису події — лише WARNING ──────────
  ALTER TABLE db_activity ADD CONSTRAINT zz_probe_fail CHECK (false) NOT VALID;
  UPDATE properties SET name = 'Офіс 74а' WHERE id = pl;
  SELECT name INTO r FROM properties WHERE id = pl;
  IF r.name <> 'Офіс 74а' THEN RAISE EXCEPTION '073: збій журналу зламав саму дію'; END IF;
  ALTER TABLE db_activity DROP CONSTRAINT zz_probe_fail;

  -- ── Видалення обʼєкта — ОДНА подія, а не десять каскадних ───────────────
  v := record_rent_payment(pl, DATE '2026-09-05', 300, now(), NULL, NULL);
  SELECT count(*) INTO n0 FROM db_activity WHERE db_id = d;
  DELETE FROM properties WHERE id = pl;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d;
  IF n - n0 <> 1 THEN RAISE EXCEPTION '073: видалення обʼєкта дало % подій (очікувано 1)', n - n0; END IF;
  SELECT * INTO r FROM db_activity WHERE db_id = d AND kind = 'property_deleted';
  IF r.property_name IS DISTINCT FROM 'Офіс 74а' OR r.property_id IS NOT NULL THEN
    RAISE EXCEPTION '073: подія видалення без назви або з висячим id (%)', r;
  END IF;

  -- ── Видалення БАЗИ не падає на журналі ───────────────────────────────────
  DELETE FROM databases WHERE id = d;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d;
  IF n <> 0 THEN RAISE EXCEPTION '073: журнал пережив базу (% рядків)', n; END IF;

  PERFORM pg_temp.as_user(NULL);
  RAISE NOTICE '  ✓ 073: подія — з автором; шум, каскад і система не пишуться; підробити автора не можна; журнал не ламає дію';
END $$;

-- ════════════════════════════════════════════════════════════════════════════
-- 074: ВИДАЛЕННЯ АКАУНТА — імʼя зникає з чужих баз, автор не висне
-- ════════════════════════════════════════════════════════════════════════════
-- Сценарій той, на якому це знайшлось: РЕДАКТОР вписав гроші в базу
-- власника, правив обʼєкт, переглядав його, мав гостьовий доступ — і видалив
-- акаунт. Перевіряється і стирання (імені ніде немає), і те, що облік
-- власника ЛИШИВСЯ: стирання, що прибрало б надходження разом з автором,
-- пройшло б «імені немає» так само.
--
-- ДВА блоки, тобто ДВІ транзакції, — і це не стиль. Для рядка, вставленого
-- ТІЄЮ САМОЮ транзакцією, Postgres перевірку ключа не пропускає, тож в
-- одному блоці дефект проявлявся б ПОМИЛКОЮ видалення. У проді надходження
-- вписують задовго до видалення акаунта, і там той самий дефект ТИХИЙ:
-- видалення «успішне», ключ висить. Стенд мусить бачити саме цей варіант.
DO $$
DECLARE
  o  UUID := 'bbbbbbbb-0000-0000-0000-000000000074';
  e  UUID := 'bbbbbbbb-0000-0000-0000-000000000741';
  d  UUID := 'cccccccc-0000-0000-0000-000000000074';
  p  UUID := 'dddddddd-0000-0000-0000-000000000741';
  v  JSONB;
  r  RECORD;
  n  INT;
BEGIN
  INSERT INTO auth.users (id,email,email_confirmed_at,raw_app_meta_data)
    SELECT v.id::uuid, v.email, now(), jsonb_build_object('tg_id', split_part(v.email,'@',1))
      FROM (VALUES
    ('aaaaaaaa-0000-0000-0000-000000000741', '740002@telegram.propspace.app')) v(id,email);
  INSERT INTO users (id, tg_id, first_name, last_name, role) VALUES
    (o, 740001, 'Власник', 'Сімдесятчотири', 'owner'),
    (e, 740002, 'Олена', 'Стерта', 'realtor');
  INSERT INTO databases (id, owner_id, name, type) VALUES (d, o, 'База 074', 'business_center');
  INSERT INTO db_members (db_id, user_id, role, status, member_name) VALUES (d, e, 'editor', 'active', 'Олена Стерта');

  PERFORM pg_temp.as_user(740001);
  INSERT INTO properties (id, db_id, owner_id, name, status, tenant_name, rent_type, rent_rate)
  VALUES (p, d, o, 'Офіс 740', 'occupied', 'ТОВ Орендар', 'fixed', 1000);

  -- Сліди редактора в чужій базі: гроші, правка (подія журналу), перегляд,
  -- гостьовий доступ від того ж власника.
  PERFORM pg_temp.as_user(740002);
  v := record_rent_payment(p, DATE '2026-09-05', 400, now(), NULL, NULL);
  UPDATE properties SET name = 'Офіс 740А' WHERE id = p;
  INSERT INTO property_views (property_id, viewer_id, viewer_name, action) VALUES (p, e, 'Олена Стерта', 'view');
  INSERT INTO guest_links (owner_id, property_id, invite_token, status, guest_user_id, guest_name)
  VALUES (o, p, 'tok_074_guest', 'active', e, 'Олена Стерта');
  -- Службовий підпис публічного відкриття — НЕ імʼя людини, і він мусить вижити.
  INSERT INTO property_views (property_id, viewer_id, viewer_name, action) VALUES (p, NULL, 'Веб-перегляд', 'view');

  -- ── Поки людина є, автора не стирає й не підміняє НІХТО (захист 073) ─────
  -- Без цього позитиву виняток для каскаду міг би відкрити стирання будь-кому.
  UPDATE rent_payment_parts pp SET created_by = NULL, created_by_name = 'Хтось'
    FROM rent_payment_records rr WHERE rr.id = pp.record_id AND rr.property_id = p;
  SELECT pp.created_by, pp.created_by_name INTO r
    FROM rent_payment_parts pp JOIN rent_payment_records rr ON rr.id = pp.record_id WHERE rr.property_id = p;
  IF r.created_by IS DISTINCT FROM e OR r.created_by_name IS DISTINCT FROM 'Олена Стерта' THEN
    RAISE EXCEPTION '074: виняток для каскаду відкрив стирання автора живої людини (%)', r;
  END IF;
  PERFORM pg_temp.as_user(NULL);
END $$;

DO $$
DECLARE
  d  UUID := 'cccccccc-0000-0000-0000-000000000074';
  p  UUID := 'dddddddd-0000-0000-0000-000000000741';
  r  RECORD;
  n  INT;
BEGIN
  -- ── Видалення акаунта — окремою транзакцією, як у проді ───────────────────
  PERFORM pg_temp.as_user(740002);
  SELECT * INTO r FROM delete_my_account();
  IF NOT r.deleted THEN RAISE EXCEPTION '074: видалення акаунта редактора відмовило (%)', r.error; END IF;

  -- Ключ не висить: інакше логічний бекап не відновить обмеження.
  SELECT count(*) INTO n FROM rent_payment_parts pp
   WHERE pp.created_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = pp.created_by);
  IF n <> 0 THEN
    RAISE EXCEPTION '074: % надходжень посилаються на видаленого користувача — дамп не відновить обмеження', n;
  END IF;

  -- Імені немає НІДЕ.
  SELECT (SELECT count(*) FROM rent_payment_parts WHERE created_by_name = 'Олена Стерта')
       + (SELECT count(*) FROM db_activity        WHERE actor_name      = 'Олена Стерта')
       + (SELECT count(*) FROM property_views     WHERE viewer_name     = 'Олена Стерта')
       + (SELECT count(*) FROM guest_links        WHERE guest_name      = 'Олена Стерта')
    INTO n;
  IF n <> 0 THEN RAISE EXCEPTION '074: імʼя видаленого акаунта лишилось у % рядках чужих баз', n; END IF;

  -- Облік власника — на місці: гроші, події, перегляди.
  SELECT count(*) INTO n FROM rent_payment_parts pp JOIN rent_payment_records rr ON rr.id = pp.record_id
   WHERE rr.property_id = p AND pp.amount = 400;
  IF n <> 1 THEN RAISE EXCEPTION '074: стирання забрало надходження власника разом з автором'; END IF;
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND actor_id IS NULL;
  IF n < 2 THEN RAISE EXCEPTION '074: події редактора зникли з журналу (лишилось %)', n; END IF;
  -- Стирання, що чистило б УСІ імена, пройшло б перевірку «імені немає» вище.
  SELECT count(*) INTO n FROM db_activity WHERE db_id = d AND actor_name = 'Власник Сімдесятчотири';
  IF n < 1 THEN RAISE EXCEPTION '074: стирання зачепило імʼя ВЛАСНИКА'; END IF;
  SELECT count(*) INTO n FROM property_views WHERE property_id = p AND viewer_name = 'Веб-перегляд';
  IF n <> 1 THEN RAISE EXCEPTION '074: стерто службовий підпис публічного перегляду'; END IF;

  PERFORM pg_temp.as_user(NULL);
  RAISE NOTICE '  ✓ 074: видалений акаунт не лишає ні імені, ні висячого ключа; гроші й події власника на місці';
END $$;
