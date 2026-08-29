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
  INSERT INTO auth.users (id,email) VALUES
    ('11111111-1111-1111-1111-111111111111','777001@telegram.propspace.app');
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
  INSERT INTO auth.users (id,email) VALUES ('aaaaaaaa-0000-0000-0000-000000000001','777003@telegram.propspace.app');
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
  INSERT INTO auth.users (id,email) VALUES ('aaaaaaaa-0000-0000-0000-000000000002','777004@telegram.propspace.app');
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
  INSERT INTO auth.users (id,email) VALUES ('aaaaaaaa-0000-0000-0000-000000000052','777052@telegram.propspace.app');
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
      'get_realtor_db_ids','get_realtor_property_ids','get_realtor_collection_ids'
    );
  IF leaked IS NOT NULL THEN
    RAISE EXCEPTION '052: anon має EXECUTE на SECURITY DEFINER функціях поза allowlist-ом: %', leaked;
  END IF;

  -- ── 058: власник БЕЗ tg_id не потрапляє в розсилку ──────────────────────
  -- Інакше edge-функція кличе Telegram з `chat_id: null`, дістає 400 і НЕ
  -- пише маркер дедуплікації (він пишеться лише на `res.ok`) — тобто той
  -- самий рядок віддається ЩОДНЯ до кінця місяця. Дефект досяжний рівно з
  -- моменту, коли 052 вмикає нагадування.
  INSERT INTO auth.users (id,email) VALUES ('aaaaaaaa-0000-0000-0000-000000000058','777058@telegram.propspace.app');
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
  INSERT INTO auth.users (id,email) VALUES ('aaaaaaaa-0000-0000-0000-000000000065','777065@telegram.propspace.app');
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
