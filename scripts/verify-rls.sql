-- ============================================================================
-- RLS ПО-СПРАВЖНЬОМУ: перевірка, якої в цьому проєкті не було НІКОЛИ
-- ============================================================================
-- Уся модель безпеки застосунку — це RLS. При цьому всі 324 e2e ганяються
-- проти герметичного мока (`page.route`), де політик не існує в принципі:
-- вони доводять, що ЕКРАН правильно малює те, що йому дали, і нічого не
-- кажуть про те, чи сервер це дав би. Юніт-гарди читають SQL як ТЕКСТ.
--
-- Тобто досі жодна політика жодного разу не була ВИКОНАНА — а саме на них
-- тримаються всі знайдені за останні раунди діри (046 guest_links, 045
-- регресія ідентичності, 041 права редактора).
--
-- Механіка: `current_app_user_id()` резолвить особу з email-клейма JWT, тож
-- «увійти» = виставити `request.jwt.claims` + `SET ROLE authenticated`.
-- Кожен блок перемикається назад на postgres, щоб посіяти наступні дані.
-- ============================================================================

\set ON_ERROR_STOP on

-- ── Дійові особи ────────────────────────────────────────────────────────────
INSERT INTO auth.users (id,email) VALUES
  ('e0000000-0000-0000-0000-00000000000a','900001@telegram.propspace.app'),  -- Аліса, власниця
  ('e0000000-0000-0000-0000-00000000000b','900002@telegram.propspace.app'),  -- Богдан, чужий власник
  ('e0000000-0000-0000-0000-00000000000c','900003@telegram.propspace.app');  -- Клим, рієлтор/гість
INSERT INTO users (id,tg_id,first_name,role) VALUES
  ('a0000000-0000-0000-0000-00000000000a',900001,'Аліса','owner'),
  ('a0000000-0000-0000-0000-00000000000b',900002,'Богдан','owner'),
  ('a0000000-0000-0000-0000-00000000000c',900003,'Клим','realtor');

INSERT INTO databases (id,owner_id,name,type,share_token) VALUES
  ('d0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a','База Аліси','business_center','tok_alice_db'),
  ('d0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000b','База Богдана','business_center','tok_bohdan_db');
INSERT INTO properties (id,db_id,owner_id,name,status,tenant_name,share_token) VALUES
  ('f0000000-0000-0000-0000-00000000000a','d0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a','Офіс Аліси','occupied','Орендар А','tok_alice_prop'),
  ('f0000000-0000-0000-0000-00000000000b','d0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000b','Офіс Богдана','occupied','Орендар Б','tok_bohdan_prop');

CREATE OR REPLACE FUNCTION pg_temp.login(p_email TEXT) RETURNS VOID
LANGUAGE plpgsql AS $$ BEGIN
  PERFORM set_config('request.jwt.claims', json_build_object('email',p_email)::TEXT, false);
  PERFORM set_config('request.jwt.claim.sub', '', false);
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- ── 1. Власник не бачить чужого ─────────────────────────────────────────
  PERFORM pg_temp.login('900001@telegram.propspace.app');
  SET LOCAL ROLE authenticated;

  SELECT count(*) INTO n FROM databases;
  IF n <> 1 THEN RAISE EXCEPTION 'RLS: Аліса бачить % баз замість своєї однієї', n; END IF;
  SELECT count(*) INTO n FROM properties;
  IF n <> 1 THEN RAISE EXCEPTION 'RLS: Аліса бачить % обʼєктів замість свого одного', n; END IF;

  -- ── 2. 053: запис у ЧУЖУ базу з ВЛАСНИМ owner_id не проходить ──────────
  -- До 053 `WITH CHECK` питав лише «owner_id — це я?», не питаючи, чи база
  -- моя. Підкинутий рядок бачили публічна /v жертви й усі її рієлтори, а
  -- сама жертва — ні, тобто не могла його прибрати.
  BEGIN
    INSERT INTO properties (db_id,owner_id,name,status)
    VALUES ('d0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000a','Підкидень','free');
    RAISE EXCEPTION '053: Аліса ВСТАВИЛА обʼєкт у базу Богдана — він зʼявиться на її публічній /v';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- ── 2b. 053: те саме на платежах ───────────────────────────────────────
  -- Підкинутий на чужий обʼєкт розклад змушував крон надсилати
  -- АТАКУВАЛЬНИКУ назву обʼєкта жертви та імʼя її орендаря.
  BEGIN
    INSERT INTO rent_payments (property_id,owner_id,due_day,notify_days_before,is_active)
    VALUES ('f0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000a',5,3,true);
    RAISE EXCEPTION '053: Аліса створила розклад на обʼєкт Богдана — крон надсилатиме їй його дані';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO rent_payment_records (property_id,owner_id,due_date,status)
    VALUES ('f0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000a',current_date,'pending');
    RAISE EXCEPTION '053: Аліса створила платіжний запис на обʼєкт Богдана';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- ── 3. Мовчазна відмова: UPDATE/DELETE чужого рядка дає НУЛЬ рядків ────
  -- Це і є та поведінка, заради якої в клієнті існує `assertAffected`:
  -- помилки немає, набір порожній. Гард доводить, що вона саме така.
  UPDATE properties SET name = 'Захоплено' WHERE id = 'f0000000-0000-0000-0000-00000000000b';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'RLS: Аліса змінила обʼєкт Богдана (% рядків)', n; END IF;

  DELETE FROM databases WHERE id = 'd0000000-0000-0000-0000-00000000000b';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'RLS: Аліса видалила базу Богдана'; END IF;

  -- ── 3b. АНТИВАКУУМ: те, що МОЖНА, мусить працювати ────────────────────
  -- Без цієї половини блок доводив би лише «відмовили», а «відмовили ВСІМ»
  -- і «відмовили правильно» нерозрізненні — рівно та пастка, на якій
  -- спалився storage-гард (054). Помилка в 053 (напр. одруківка в назві
  -- хелпера) зламала б створення обʼєктів для всіх, і денайні перевірки
  -- лишились би зеленими.
  INSERT INTO properties (db_id,owner_id,name,status)
  VALUES ('d0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a','Свій новий','free');
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION '053: власник НЕ МОЖЕ створити обʼєкт у ВЛАСНІЙ базі'; END IF;

  INSERT INTO rent_payments (property_id,owner_id,due_day,notify_days_before,is_active)
  VALUES ('f0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a',5,3,true);
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION '053: власник НЕ МОЖЕ створити розклад на ВЛАСНОМУ обʼєкті'; END IF;

  UPDATE properties SET name = 'Перейменовано' WHERE id = 'f0000000-0000-0000-0000-00000000000a';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION '053: власник НЕ МОЖЕ перейменувати ВЛАСНИЙ обʼєкт'; END IF;

  RESET ROLE;
  RAISE NOTICE '  ✓ RLS: власник не чіпає чуже — і при цьому вільно працює зі своїм';
END $$;

DO $$
DECLARE n INT; v JSONB;
BEGIN
  -- ── 4. 046: гостьовий лінк на ЧУЖУ ціль не створюється ─────────────────
  -- До 046 рядок із чужим `db_id` вставлявся легально, а після клейму
  -- третьою особою віддавав усю базу жертви.
  PERFORM pg_temp.login('900003@telegram.propspace.app');
  SET LOCAL ROLE authenticated;
  BEGIN
    INSERT INTO guest_links (owner_id, db_id, label)
    VALUES ('a0000000-0000-0000-0000-00000000000c','d0000000-0000-0000-0000-00000000000a','Чужа база');
    RAISE EXCEPTION '046: Клим створив гостьовий лінк на базу Аліси';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RESET ROLE;

  -- АНТИВАКУУМ: політика не мусить відмовляти ВСІМ. Аліса створює лінк на
  -- ВЛАСНУ базу — без цієї половини «Клим не зміг» однаково пояснюється і
  -- правильною перевіркою цілі, і повністю зламаною політикою.
  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims','900001@telegram.propspace.app',true);
  PERFORM set_config('request.jwt.claims','{"email":"900001@telegram.propspace.app"}',true);
  INSERT INTO guest_links (owner_id, db_id, label)
  VALUES ('a0000000-0000-0000-0000-00000000000a','d0000000-0000-0000-0000-00000000000a','Свій лінк');
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION '046: власник НЕ МОЖЕ створити лінк на ВЛАСНУ базу'; END IF;
  RESET ROLE;

  -- ── 5. Гість бачить РІВНО ціль свого лінка, а не всю базу ──────────────
  INSERT INTO guest_links (id,owner_id,property_id,invite_token,label,status)
  VALUES ('c0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a',
          'f0000000-0000-0000-0000-00000000000a','tok_guest_rls','Орендар','pending');
  INSERT INTO properties (id,db_id,owner_id,name,status)
  VALUES ('f0000000-0000-0000-0000-00000000000c','d0000000-0000-0000-0000-00000000000a',
          'a0000000-0000-0000-0000-00000000000a','Сусідній офіс Аліси','free');

  PERFORM pg_temp.login('900003@telegram.propspace.app');
  SET LOCAL ROLE authenticated;
  v := claim_guest_link('tok_guest_rls');
  IF v->>'error' IS NOT NULL THEN RAISE EXCEPTION 'RLS: клейм гостя відмовив: %', v->>'error'; END IF;

  SELECT count(*) INTO n FROM properties WHERE db_id = 'd0000000-0000-0000-0000-00000000000a';
  IF n <> 1 THEN
    RAISE EXCEPTION 'RLS: гість бачить % обʼєктів бази замість ОДНОГО, на який його запросили', n;
  END IF;
  -- І нічого не пише
  UPDATE properties SET name='Гість тут був' WHERE id='f0000000-0000-0000-0000-00000000000a';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'RLS: гість ЗМІНИВ обʼєкт власника'; END IF;
  RESET ROLE;

  RAISE NOTICE '  ✓ RLS: гість — рівно своя ціль, лише читання; чужий лінк не створити (046)';
END $$;

DO $$
DECLARE n INT; v JSONB; tok TEXT;
BEGIN
  -- ── 6. 041: редактор команди пише, але не привласнює ───────────────────
  INSERT INTO db_members (db_id, label, status)
  VALUES ('d0000000-0000-0000-0000-00000000000a','Менеджер','pending')
  RETURNING invite_token INTO tok;

  PERFORM pg_temp.login('900002@telegram.propspace.app');
  SET LOCAL ROLE authenticated;
  v := claim_team_invite(tok);
  IF v->>'error' IS NOT NULL THEN RAISE EXCEPTION '041: клейм інвайта відмовив: %', v->>'error'; END IF;

  -- Пише в чужу базу — але ЛИШЕ з owner_id власника бази.
  INSERT INTO properties (db_id, owner_id, name, status)
  VALUES ('d0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000a','Обʼєкт редактора','free');

  BEGIN
    INSERT INTO properties (db_id, owner_id, name, status)
    VALUES ('d0000000-0000-0000-0000-00000000000a','a0000000-0000-0000-0000-00000000000b','Привласнений','free');
    RAISE EXCEPTION '041: редактор привласнив обʼєкт собі (owner_id = він сам)';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RESET ROLE;

  RAISE NOTICE '  ✓ RLS: редактор пише в чужу базу, але owner_id лишається власника (041)';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- ── 7. anon не дістає ДАНИХ із таблиць ──────────────────────────────────
  -- Публічна /v ходить ВИКЛЮЧНО через SECURITY DEFINER превʼю з токеном.
  --
  -- Відмовити anon можна ДВОМА способами, і обидва прийнятні: порожній
  -- результат (політика не матчить) або `permission denied` (політика кличе
  -- функцію, якої anon не має — так сьогодні поводиться `properties`, бо
  -- `props_guest_select` викликає `is_guest_of_property`, а 027 забрала її в
  -- PUBLIC). Гард тому перевіряє РЕЗУЛЬТАТ — «даних не отримав», — а не
  -- конкретний механізм відмови: інакше він фіксував би сьогоднішню
  -- випадковість замість вимоги.
  -- Клейми скидаються в КОЖНОМУ блоці: підтранзакція, що впала на
  -- `permission denied`, відкочує і `set_config(..., true)`, тож наступний
  -- блок біг би з роллю anon, але з ЧУЖОЮ особою в JWT — комбінація, якої в
  -- проді не буває, і гард репортував би неіснуючий витік. Наступано тут же.
  -- АНТИВАКУУМ: рядки мусять реально ІСНУВАТИ. Інакше «anon нічого не бачить»
  -- означало б «дивитись не було на що» — і гард лишався б зеленим на порожній
  -- базі, тобто не перевіряв би нічого.
  SELECT count(*) INTO n FROM databases;
  IF n < 2 THEN RAISE EXCEPTION 'anon-гард вакуумний: у базі % рядків databases', n; END IF;
  SELECT count(*) INTO n FROM properties;
  IF n < 2 THEN RAISE EXCEPTION 'anon-гард вакуумний: у базі % рядків properties', n; END IF;

  BEGIN
    SET LOCAL ROLE anon;
    PERFORM set_config('request.jwt.claims', '', true);
    SELECT count(*) INTO n FROM properties;
    IF n <> 0 THEN RAISE EXCEPTION 'anon читає % обʼєктів напряму з таблиці', n; END IF;
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    SET LOCAL ROLE anon;
    PERFORM set_config('request.jwt.claims', '', true);
    SELECT count(*) INTO n FROM databases;
    IF n <> 0 THEN RAISE EXCEPTION 'anon читає % баз напряму з таблиці', n; END IF;
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    SET LOCAL ROLE anon;
    PERFORM set_config('request.jwt.claims', '', true);
    SELECT count(*) INTO n FROM users;
    IF n <> 0 THEN RAISE EXCEPTION 'anon читає % профілів напряму з таблиці', n; END IF;
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RESET ROLE;

  RAISE NOTICE '  ✓ RLS: anon не читає таблиці напряму — лише токенні превʼю';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- ── 8. 053: сам крон не розсилає чужих даних НАВІТЬ за підкинутого рядка ─
  -- Глибинний захист: політика вже не пропустить нового підкидня, а ремонт у
  -- 053 прибрав старих — але канал закритий і з боку споживача. Саджаємо
  -- рядок від postgres (тобто обходячи RLS, як зробила б будь-яка майбутня
  -- діра в записі) і перевіряємо, що функція його ІГНОРУЄ.
  INSERT INTO rent_payments (property_id, owner_id, due_day, notify_days_before, is_active)
  SELECT 'f0000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-00000000000a',
         d, 3, true
  FROM (SELECT EXTRACT(DAY FROM current_date + INTERVAL '3 day')::INT AS d) s
  WHERE s.d BETWEEN 1 AND 28;

  SELECT count(*) INTO n FROM get_due_reminders_today()
  WHERE owner_id = 'a0000000-0000-0000-0000-00000000000a'
    AND property_id = 'f0000000-0000-0000-0000-00000000000b';
  IF n <> 0 THEN
    RAISE EXCEPTION '053: крон надішле Алісі дані обʼєкта Богдана (% рядків)', n;
  END IF;

  -- АНТИВАКУУМ: ЗАКОННЕ нагадування (розклад і обʼєкт однієї особи) мусить
  -- повертатись. Інакше «підкидня немає» однаково пояснюється і предикатом
  -- `rp.owner_id = p.owner_id`, і функцією, зламаною настільки, що вона не
  -- віддає нічого взагалі — а саме таким і був її стан до 052.
  -- Береться ВЛАСНИЙ обʼєкт Аліси з її ж розкладом (створений у 3b): і рядок,
  -- і обʼєкт однієї особи, тобто нагадування законне. На обʼєкті Богдана це
  -- зробити НЕ МОЖНА — `rent_payments.property_id` UNIQUE, і слот уже зайняв
  -- підкидень. Це, до речі, самостійний наслідок дефекту 053: підкинувши
  -- розклад першим, атакувальник ще й ПОЗБАВЛЯЄ жертву власного.
  UPDATE properties SET status='occupied' WHERE id='f0000000-0000-0000-0000-00000000000a';
  UPDATE rent_payments rp
     SET due_day = q.d, notify_days_before = 3, is_active = true
    FROM (SELECT EXTRACT(DAY FROM current_date + INTERVAL '3 day')::INT AS d) q
   WHERE rp.property_id = 'f0000000-0000-0000-0000-00000000000a' AND q.d BETWEEN 1 AND 28;

  IF EXISTS (SELECT 1 FROM rent_payments rp
             WHERE rp.property_id='f0000000-0000-0000-0000-00000000000a'
               AND rp.due_day = EXTRACT(DAY FROM current_date + INTERVAL '3 day')::INT) THEN
    SELECT count(*) INTO n FROM get_due_reminders_today()
    WHERE property_id = 'f0000000-0000-0000-0000-00000000000a';
    IF n <> 1 THEN
      RAISE EXCEPTION '053: ЗАКОННЕ нагадування власника не повертається (% рядків) — гард був би вакуумним', n;
    END IF;
  END IF;

  RAISE NOTICE '  ✓ RLS: підкинутий розклад не потрапляє в розсилку (053, глибинний захист)';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- ── 9. Storage: ОДНЕ джерело особи (054) ────────────────────────────────
  -- Цей блок починався з ВАКУУМНОГО тесту: «Аліса не зітре фото Богдана»
  -- проходив, бо Аліса не могла зітерти й ВЛАСНЕ фото — політика відмовляла
  -- всім. Тому тут ОБОВʼЯЗКОВА пара: спершу «своє зникає», потім «чуже
  -- лишається». Без першої половини друга нічого не доводить.
  --
  -- Ключова умова заміру: виставляємо ЛИШЕ `sub`-клейм. Саме так виглядає
  -- storage-контекст, заради ненадійності якого 030 і завела
  -- `*_from_auth_uid`-варіанти. До 054 підзапит усередині політики йшов по
  -- `properties` під RLS, тобто мовчки вимагав ще й email-клейм.
  INSERT INTO storage.objects (bucket_id,name,owner) VALUES
    ('photos','f0000000-0000-0000-0000-00000000000a/mine.jpg',NULL),
    ('photos','f0000000-0000-0000-0000-00000000000b/hers.jpg',NULL);

  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims', '', true);
  PERFORM set_config('request.jwt.claim.sub', 'e0000000-0000-0000-0000-00000000000a', true);

  DELETE FROM storage.objects WHERE name = 'f0000000-0000-0000-0000-00000000000a/mine.jpg';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN
    RAISE EXCEPTION '054: власник НЕ МОЖЕ видалити власне фото (% рядків) — політика вимагає email-клейм, якого в storage-контексті може не бути', n;
  END IF;

  DELETE FROM storage.objects WHERE name = 'f0000000-0000-0000-0000-00000000000b/hers.jpg';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN
    RAISE EXCEPTION 'storage: Аліса видалила фото Богдана';
  END IF;
  RESET ROLE;

  RAISE NOTICE '  ✓ storage: своє видаляється лише по sub-клейму, чуже — ні (054)';
END $$;

DO $$
DECLARE bad TEXT;
BEGIN
  -- ── 10. Каскадне видалення бази не лишає сиріт ──────────────────────────
  -- OWASP-таблиця в CLAUDE.md стверджує «Cascade deletes tested» (A08) — але
  -- жоден тест цього не виконував: e2e ганяються проти мока, де FK не існує.
  -- Тут перевіряється РЕЗУЛЬТАТ по всіх десяти залежних таблицях одразу.
  --
  -- Дві НЕ-каскадні звʼязки лишаються свідомо і перевіряються окремо:
  -- `guest_links.guest_user_id` (SET NULL — лінк переживає видалення гостя) і
  -- `property_views.viewer_id` (NO ACTION — саме тому `delete_my_account`
  -- знеособлює його ПЕРЕД видаленням, інакше одна переглядова позначка
  -- блокувала б видалення акаунта).
  INSERT INTO auth.users (id,email) VALUES ('e1000000-0000-0000-0000-000000000001','910001@telegram.propspace.app');
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('a1000000-0000-0000-0000-000000000001',910001,'Каскад','owner');
  INSERT INTO databases (id,owner_id,name,type) VALUES ('d1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001','Каскадна','business_center');
  INSERT INTO property_folders (id,db_id,owner_id,name) VALUES ('90000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001','Папка');
  INSERT INTO properties (id,db_id,owner_id,name,status,folder_id) VALUES ('f1000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001','Обʼєкт','occupied','90000000-0000-0000-0000-000000000001');
  INSERT INTO property_photos (property_id,storage_path,sort_order) VALUES ('f1000000-0000-0000-0000-000000000001','f1000000-0000-0000-0000-000000000001/a.jpg',0);
  INSERT INTO property_files (property_id,owner_id,file_name,storage_path,mime_type,file_size) VALUES ('f1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001','d.pdf','f1000000-0000-0000-0000-000000000001/d.pdf','application/pdf',10);
  INSERT INTO rent_payments (property_id,owner_id,due_day,notify_days_before,is_active) VALUES ('f1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001',5,3,true);
  INSERT INTO rent_payment_records (property_id,owner_id,due_date,status) VALUES ('f1000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-000000000001',current_date,'pending');
  -- `property_views_one_target`: рівно ОДНА ціль на рядок, тож лише property_id.
  INSERT INTO property_views (property_id) VALUES ('f1000000-0000-0000-0000-000000000001');
  INSERT INTO guest_links (owner_id,property_id,label) VALUES ('a1000000-0000-0000-0000-000000000001','f1000000-0000-0000-0000-000000000001','Гість');
  INSERT INTO db_members (db_id,label) VALUES ('d1000000-0000-0000-0000-000000000001','Редактор');
  INSERT INTO realtor_subscriptions (realtor_id,db_id) VALUES ('a1000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001');

  -- Антивакуум: дані мусять реально ІСНУВАТИ до видалення, інакше «сиріт
  -- немає» означало б «нічого й не було».
  IF (SELECT count(*) FROM property_views WHERE property_id='f1000000-0000-0000-0000-000000000001') <> 1 THEN
    RAISE EXCEPTION 'каскад: фікстура не посіялась — перевірка була б вакуумною';
  END IF;

  DELETE FROM databases WHERE id='d1000000-0000-0000-0000-000000000001';

  SELECT string_agg(t||'='||c, ', ') INTO bad FROM (
    SELECT 'properties' t, count(*) c FROM properties WHERE db_id='d1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'photos', count(*) FROM property_photos WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'files', count(*) FROM property_files WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'rent_payments', count(*) FROM rent_payments WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'rent_records', count(*) FROM rent_payment_records WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'views', count(*) FROM property_views WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'guest_links', count(*) FROM guest_links WHERE property_id='f1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'db_members', count(*) FROM db_members WHERE db_id='d1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'subs', count(*) FROM realtor_subscriptions WHERE db_id='d1000000-0000-0000-0000-000000000001'
    UNION ALL SELECT 'folders', count(*) FROM property_folders WHERE db_id='d1000000-0000-0000-0000-000000000001'
  ) s WHERE c > 0;

  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'каскад: після видалення бази лишились сироти — %', bad;
  END IF;

  RAISE NOTICE '  ✓ каскад: видалення бази не лишає сиріт у жодній із 10 залежних таблиць';
END $$;

DO $$
DECLARE r RECORD; v JSONB; n INT;
BEGIN
  -- ── 11. Відкликання СПРАВДІ відкликає ───────────────────────────────────
  -- Клас «дія скасовує ефект безпекової операції» цей проєкт уже ловив
  -- (revoke ставив expiry, а токен лишався, тож будь-який set_expiry оживляв
  -- мертвий лінк). Тут перевіряються ДВА входи, які досі не виконувались
  -- жодного разу, і ОБИДВА — парою з позитивом: «not_found» однаково
  -- пояснюється і правильною відмовою, і зламаною функцією.
  INSERT INTO auth.users (id,email) VALUES
    ('e2000000-0000-0000-0000-000000000001','920001@telegram.propspace.app'),
    ('e2000000-0000-0000-0000-000000000002','920002@telegram.propspace.app');
  INSERT INTO users (id,tg_id,first_name,role) VALUES
    ('a2000000-0000-0000-0000-000000000001',920001,'Власник2','owner'),
    ('a2000000-0000-0000-0000-000000000002',920002,'Рієлтор2','realtor');
  INSERT INTO databases (id,owner_id,name,type,share_token,share_expires_at) VALUES
    ('d2000000-0000-0000-0000-000000000001','a2000000-0000-0000-0000-000000000001','Протермінована','business_center','tok_expired', now() - INTERVAL '1 day'),
    ('d2000000-0000-0000-0000-000000000002','a2000000-0000-0000-0000-000000000001','Жива','business_center','tok_alive', NULL);
  INSERT INTO guest_links (id,owner_id,db_id,invite_token,label,status) VALUES
    ('c2000000-0000-0000-0000-000000000001','a2000000-0000-0000-0000-000000000001','d2000000-0000-0000-0000-000000000002','tok_revoked_guest','Гість','revoked');

  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims','{"email":"920002@telegram.propspace.app"}',true);

  -- ПОЗИТИВ: живий токен мусить працювати, інакше негатив нижче вакуумний.
  SELECT * INTO r FROM subscribe_to_shared_db('tok_alive');
  IF r.error IS NOT NULL THEN
    RAISE EXCEPTION 'підписка: ЖИВИЙ токен відмовив (%) — негативна перевірка була б вакуумною', r.error;
  END IF;

  -- НЕГАТИВ: протермінований не пускає і не створює підписки.
  SELECT * INTO r FROM subscribe_to_shared_db('tok_expired');
  IF r.error IS DISTINCT FROM 'not_found' THEN
    RAISE EXCEPTION 'підписка: ПРОТЕРМІНОВАНИЙ токен віддав % замість not_found', COALESCE(r.error,'NULL');
  END IF;
  SELECT count(*) INTO n FROM realtor_subscriptions rs WHERE rs.db_id='d2000000-0000-0000-0000-000000000001';
  IF n <> 0 THEN RAISE EXCEPTION 'підписка: створена по ПРОТЕРМІНОВАНОМУ токену'; END IF;

  -- Відкликаний гостьовий лінк не клеймиться і не воскресає.
  v := claim_guest_link('tok_revoked_guest');
  IF v->>'error' IS DISTINCT FROM 'revoked' THEN
    RAISE EXCEPTION 'гість: ВІДКЛИКАНИЙ лінк віддав % замість revoked', COALESCE(v->>'error','NULL');
  END IF;
  RESET ROLE;

  IF (SELECT gl.status FROM guest_links gl WHERE gl.id='c2000000-0000-0000-0000-000000000001') <> 'revoked' THEN
    RAISE EXCEPTION 'гість: спроба клейму ОЖИВИЛА відкликаний лінк';
  END IF;

  RAISE NOTICE '  ✓ відкликання: протермінований шер і revoked-лінк не пускають, живий — пускає';
END $$;

DO $$
DECLARE r RECORD; v JSONB; n INT; tok TEXT;
BEGIN
  -- ── 12. КОЖЕН клієнтський RPC — на УСПІШНІЙ гілці ────────────────────────
  -- Узагальнення знахідки 055: `subscribe_to_shared_db` падала рівно на
  -- успішній гілці (`ON CONFLICT` з неоднозначним `db_id`), а всі негативні
  -- перевірки її проходили, бо виходили з функції раніше. Отже кожен RPC,
  -- виданий anon/authenticated, мусить бути ВИКЛИКАНИЙ там, де він має
  -- ПРАЦЮВАТИ, а не лише там, де має відмовити.
  INSERT INTO auth.users (id,email) VALUES ('e3000000-0000-0000-0000-000000000001','930001@telegram.propspace.app');
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('a3000000-0000-0000-0000-000000000001',930001,'Свіп','realtor');
  INSERT INTO databases (id,owner_id,name,type,share_token) VALUES
    ('d3000000-0000-0000-0000-000000000001','a2000000-0000-0000-0000-000000000001','Свіп-база','business_center','tok_sweep_db');
  INSERT INTO properties (id,db_id,owner_id,name,status,share_token) VALUES
    ('f3000000-0000-0000-0000-000000000001','d3000000-0000-0000-0000-000000000001','a2000000-0000-0000-0000-000000000001','Свіп-обʼєкт','free','tok_sweep_prop');
  INSERT INTO collections (id,realtor_id,name,share_token) VALUES
    ('11113000-0000-0000-0000-000000000001','a3000000-0000-0000-0000-000000000001','Свіп-підбірка','tok_sweep_col');
  INSERT INTO collection_properties (collection_id,property_id) VALUES
    ('11113000-0000-0000-0000-000000000001','f3000000-0000-0000-0000-000000000001');
  -- Підписка ОБОВʼЯЗКОВА для фікстури: публічна підбірка показує лише ті
  -- обʼєкти, до баз яких рієлтор має доступ. Без цього рядка превʼю законно
  -- віддає нуль — і перша версія свіпу репортувала «дефект», якого немає.
  INSERT INTO realtor_subscriptions (realtor_id,db_id) VALUES
    ('a3000000-0000-0000-0000-000000000001','d3000000-0000-0000-0000-000000000001');

  -- 056: підбірка мусить бути ОПУБЛІКОВАНА — `is_draft` дефолтом TRUE, а
  -- превʼю має `AND c.is_draft = false`. Саме на цьому спалилась перша
  -- «спростована гіпотеза»: нуль рядків пояснювався чернеткою, а не
  -- фільтрацією чужого обʼєкта.
  UPDATE collections SET is_draft = false WHERE id='11113000-0000-0000-0000-000000000001';

  -- anon-гілка: усі три публічні превʼю + лічильник переглядів.
  SET LOCAL ROLE anon;
  PERFORM set_config('request.jwt.claims','',true);

  SELECT count(*) INTO n FROM get_public_db_preview('tok_sweep_db');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: get_public_db_preview не віддала жодного рядка'; END IF;
  SELECT count(*) INTO n FROM get_public_property_preview('tok_sweep_prop');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: get_public_property_preview не віддала жодного рядка'; END IF;
  SELECT count(*) INTO n FROM get_public_collection_preview('tok_sweep_col');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: get_public_collection_preview не віддала жодного рядка'; END IF;
  PERFORM record_public_view('tok_sweep_db','db');
  PERFORM record_public_view('tok_sweep_prop','property');
  RESET ROLE;

  -- authenticated-гілка: lookup-и й ротація власного шеру.
  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims','{"email":"930001@telegram.propspace.app"}',true);
  SELECT count(*) INTO n FROM lookup_shared_db('tok_sweep_db');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: lookup_shared_db не знайшла базу за живим токеном'; END IF;
  SELECT count(*) INTO n FROM lookup_shared_property('tok_sweep_prop');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: lookup_shared_property не знайшла обʼєкт'; END IF;
  SELECT count(*) INTO n FROM lookup_shared_collection('tok_sweep_col');
  IF n < 1 THEN RAISE EXCEPTION 'RPC-свіп: lookup_shared_collection не знайшла підбірку'; END IF;
  RESET ROLE;

  -- manage_share на ВЛАСНІЙ базі: ротація мусить справді змінити токен.
  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims','{"email":"920001@telegram.propspace.app"}',true);
  SELECT * INTO r FROM manage_share('db','d3000000-0000-0000-0000-000000000001','rotate',NULL);
  IF r.error IS NOT NULL THEN
    RAISE EXCEPTION 'RPC-свіп: manage_share(rotate) на ВЛАСНІЙ базі відмовила: %', r.error;
  END IF;
  RESET ROLE;

  SELECT d.share_token INTO tok FROM databases d WHERE d.id='d3000000-0000-0000-0000-000000000001';
  IF tok = 'tok_sweep_db' THEN
    RAISE EXCEPTION 'RPC-свіп: manage_share(rotate) відзвітувала успіх, але токен не змінився';
  END IF;

  RAISE NOTICE '  ✓ RPC-свіп: усі клієнтські функції відпрацьовують на УСПІШНІЙ гілці';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- ── 13. 056: чужий обʼєкт не потрапляє у ПУБЛІЧНУ підбірку ──────────────
  -- Гіпотеза, яку я спершу «спростував» ХИБНИМ заміром (підбірка була
  -- чернеткою, тож превʼю віддавало нуль рядків з іншої причини). На
  -- ОПУБЛІКОВАНІЙ підбірці вона підтвердилась: рієлтор публікував назву,
  -- ціну й фото чужого обʼєкта поруч зі СВОЇМИ контактами.
  INSERT INTO auth.users (id,email) VALUES ('e9000000-0000-0000-0000-000000000001','940001@telegram.propspace.app');
  INSERT INTO users (id,tg_id,first_name,role) VALUES ('a9000000-0000-0000-0000-000000000001',940001,'ЖертваК','owner');
  INSERT INTO databases (id,owner_id,name,type,share_token) VALUES
    ('d9000000-0000-0000-0000-000000000001','a9000000-0000-0000-0000-000000000001','База жертви','business_center','tok_victim9');
  INSERT INTO properties (id,db_id,owner_id,name,status,share_token) VALUES
    ('f9000000-0000-0000-0000-000000000001','d9000000-0000-0000-0000-000000000001','a9000000-0000-0000-0000-000000000001','ТАЄМНИЙ ОБʼЄКТ ЖЕРТВИ','for_sale','tok_vprop9');
  -- Рієлтор `a3000000…` НЕ підписаний на базу жертви, підбірка опублікована.
  UPDATE collections SET is_draft = false WHERE id='11113000-0000-0000-0000-000000000001';

  SET LOCAL ROLE authenticated;
  PERFORM set_config('request.jwt.claims','{"email":"930001@telegram.propspace.app"}',true);
  BEGIN
    INSERT INTO collection_properties (collection_id, property_id)
    VALUES ('11113000-0000-0000-0000-000000000001','f9000000-0000-0000-0000-000000000001');
    RAISE EXCEPTION '056: рієлтор поклав ЧУЖИЙ обʼєкт у свою підбірку';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RESET ROLE;

  -- Друга половина: рядок, посаджений В ОБХІД політики (як зробила б будь-яка
  -- майбутня діра або як лежать легасі-рядки), не мусить світитись публічно.
  INSERT INTO collection_properties (collection_id, property_id)
  VALUES ('11113000-0000-0000-0000-000000000001','f9000000-0000-0000-0000-000000000001');

  SET LOCAL ROLE anon;
  PERFORM set_config('request.jwt.claims','',true);
  SELECT count(*) INTO n FROM get_public_collection_preview('tok_sweep_col')
   WHERE property_name = 'ТАЄМНИЙ ОБʼЄКТ ЖЕРТВИ';
  IF n <> 0 THEN
    RAISE EXCEPTION '056: публічна підбірка світить ЧУЖИЙ обʼєкт (% рядків)', n;
  END IF;
  -- Антивакуум: ВЛАСНИЙ обʼєкт підбірки мусить лишатись видимим.
  SELECT count(*) INTO n FROM get_public_collection_preview('tok_sweep_col')
   WHERE property_name = 'Свіп-обʼєкт';
  IF n <> 1 THEN
    RAISE EXCEPTION '056: фікс приховав і ЗАКОННИЙ обʼєкт підбірки (% рядків)', n;
  END IF;
  RESET ROLE;

  RAISE NOTICE '  ✓ 056: чужий обʼєкт не потрапляє й не світиться в публічній підбірці';
END $$;
