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

  RESET ROLE;
  RAISE NOTICE '  ✓ RLS: власник не читає, не пише, не змінює і не видаляє чуже';
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
