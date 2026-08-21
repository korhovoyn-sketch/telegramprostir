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

  RAISE NOTICE '  ✓ 051: файли, профіль і auth-акаунт знесені; чужий файл цілий';
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
