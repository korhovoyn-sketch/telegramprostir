-- ============================================================================
-- verify_release.sql — одна перевірка готовності БД до публікації.
-- Запусти в Supabase Dashboard → SQL Editor. Кожен рядок результату має бути
-- OK; будь-який MISSING = відповідна міграція не застосована (файл вказано).
--
-- Той самий запит ВКЛЕЄНО в кінець supabase/RELEASE.sql (після COMMIT), тож
-- один запуск того файлу і накочує міграції, і показує цю таблицю. Окремо
-- цей файл потрібен, щоб перевірити стан, нічого не застосовуючи.
--
-- ПРАВИЛО ДЛЯ НОВИХ РЯДКІВ: перевірка не сміє ПАДАТИ на базі ДО накату, де
-- таблиць із нових міграцій ще немає, — лише показувати MISSING. Тому про
-- нову таблицю питаємо КАТАЛОГ (`pg_class`, `to_regclass`), а не саму
-- таблицю: запит до неї там — ERROR, і замість відповіді «чого бракує»
-- людина побачила б помилку. З тієї ж причини `to_regclass(...)`, а не
-- `'...'::regclass`. Гард — scripts/verify-migrations.sh (база 001..047).
-- ============================================================================

WITH checks(ord, item, migration, ok) AS (VALUES
  -- 026: security audit fixes
  -- 049 ВИДАЛИЛА get_shared_collection як IDOR (SECURITY DEFINER по UUID,
  -- виданий anon, без звірки токена — ротація лінка її не стосувалась).
  -- Тому перевіряємо ВІДСУТНІСТЬ, а не наявність терміну дії: доти цей рядок
  -- вічно світив «MISSING → виконай 026» і посилав оператора не туди.
  (1,  'get_shared_collection ВІДСУТНЯ (IDOR, прибрано 049)', '049_drop_idor_get_shared_collection.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public' AND p.proname='get_shared_collection')),
  (2,  'індекс idx_audit_log_user_created', '026_security_audit_fixes.sql',
      EXISTS (SELECT 1 FROM pg_indexes WHERE indexname='idx_audit_log_user_created')),

  -- 036/037: share management + db share fixes
  (3,  'RPC subscribe_to_shared_db', '036/037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='subscribe_to_shared_db')),
  (4,  'RPC manage_share', '036/037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='manage_share')),
  (5,  'databases.share_token NOT NULL', '037_db_share_fixes.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_name='databases' AND column_name='share_token' AND is_nullable='NO')),

  -- 038: storage write hardening (пермісивні політики МАЮТЬ зникнути)
  -- УВАГА: тут стояло «виконай 038», і це була НЕБЕЗПЕЧНА порада. 038 несе
  -- копію get_app_user_id_from_auth_uid() ДО 031 — без доменного якоря і
  -- tg_id>0 — тож на базі, де 045 застосована, а 038 ні (реальний стан
  -- проду), запуск 038 відкотив би фікс і знову відкрив захоплення акаунта.
  -- 062 робить лише те, чого бракує, і функцій ідентичності не чіпає.
  (6,  'photos: пермісивні політики запису ВИДАЛЕНІ', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='storage'
                  AND tablename='objects'
                  AND policyname IN ('photos_insert_auth','photos_delete_auth'))),
  (7,  'photos: строга storage_photos_insert існує', '038_storage_write_hardening.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='storage'
              AND tablename='objects' AND policyname='storage_photos_insert')),
  (8,  'property_files: INSERT вимагає володіння об''єктом', '038_storage_write_hardening.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='property_files'
              AND cmd='INSERT' AND with_check LIKE '%properties%')),

  -- 039: parking
  (9,  'properties.parking_type + ev_charger', '039_parking_fields.sql',
      (SELECT count(*)=2 FROM information_schema.columns
       WHERE table_name='properties' AND column_name IN ('parking_type','ev_charger'))),
  (10, 'rent_type CHECK містить per_day', '039_parking_fields.sql',
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname='properties_rent_type_check'
              AND pg_get_constraintdef(oid) LIKE '%per_day%')),

  -- 040: public preview fixes
  (11, 'get_public_property_preview віддає owner_currency', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_property_preview'
              AND pg_get_function_result(oid) LIKE '%owner_currency%')),
  (12, 'get_public_db_preview віддає sale_price + currency', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_db_preview'
              AND pg_get_function_result(oid) LIKE '%property_sale_price%')),
  (13, 'record_public_view(p_token, p_kind)', '040_public_preview_fixes.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='record_public_view'
              AND pg_get_function_arguments(oid) LIKE '%p_kind%')),
  (14, 'property_views.db_id/collection_id', '040_public_preview_fixes.sql',
      (SELECT count(*)=2 FROM information_schema.columns
       WHERE table_name='property_views' AND column_name IN ('db_id','collection_id'))),

  -- 041: team members
  (18, 'db_members існує з RLS', '041_team_members.sql',
      EXISTS (SELECT 1 FROM pg_class WHERE relname='db_members' AND relrowsecurity)),
  (19, 'редакторські політики на properties/payments', '041_team_members.sql',
      (SELECT count(*)>=2 FROM pg_policies WHERE policyname IN ('props_editor_all','rent_payments_editor_all'))),
  (20, 'RPC claim_team_invite', '041_team_members.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='claim_team_invite')),

  -- 045: КРИТИЧНО — регресія ідентифікації (038/041 стерли фікс 031). Маркер
  -- `tg_id > 0` унікальний для виправленої версії — вразлива копія (038/041) її
  -- не має, тож самої substring-перевірки досить (без неоднозначності LIKE-екранування бекслеша в regex-літералі).
  (21, 'get_app_user_id_from_auth_uid має tg_id>0 (031/045 hardening)', '045_fix_auth_uid_identity_regression.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_app_user_id_from_auth_uid'
              AND prosrc LIKE '%tg_id > 0%')),
  (22, 'get_editor_db_ids_from_auth_uid має tg_id>0 (045 hardening)', '045_fix_auth_uid_identity_regression.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_editor_db_ids_from_auth_uid'
              AND prosrc LIKE '%tg_id > 0%')),

  (23, 'нагадування ВЗАГАЛІ викликаються (тип результату полагоджено)', '052_reminders_fix_and_lockdown.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_reminders_today'
              AND prosrc LIKE '%p.name::TEXT%')),
  (24, 'anon НЕ має службових функцій (дефолтний PUBLIC знято)', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname='public'
                    AND p.proname IN ('get_due_reminders_today','get_due_guest_reminders','mark_overdue_payments')
                    AND has_function_privilege('anon', p.oid, 'EXECUTE'))),

  (25, 'props_owner_all перевіряє, що БАЗА твоя (не лише owner_id)', '053_owner_policies_target_ownership.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='properties'
              AND policyname='props_owner_all' AND with_check LIKE '%get_owner_db_ids%')),
  (26, 'платежі перевіряють, що ОБʼЄКТ твій', '053_owner_policies_target_ownership.sql',
      (SELECT count(*)=2 FROM pg_policies
       WHERE tablename IN ('rent_payments','rent_payment_records')
         AND with_check LIKE '%get_owner_property_ids%')),
  (27, 'нагадування не розсилають чужих даних (rp.owner_id = p.owner_id)', '053_owner_policies_target_ownership.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_reminders_today'
              AND prosrc LIKE '%rp.owner_id = p.owner_id%')),

  -- Підрядок — свідома МЕЖА цього файлу, не недогляд: у Dashboard не можна
  -- виконати успішну гілку, не створивши справжньої підписки. Доказ виконанням
  -- дає CI (`verify-rls.sql`, блок «відкликання», позитивний контроль).
  (28, 'subscribe_to_shared_db не падає на успішній гілці (ON CONFLICT)', '055_fix_subscribe_ambiguous_db_id.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='subscribe_to_shared_db'
              AND prosrc LIKE '%variable_conflict use_column%')),

  (29, 'підбірка не приймає чужий обʼєкт (056)', '056_collection_target_access.sql',
      EXISTS (SELECT 1 FROM pg_policies WHERE tablename='collection_properties'
              AND policyname='col_props_realtor_all' AND with_check LIKE '%get_realtor_property_ids%')),
  (30, 'публічна підбірка не світить чужий обʼєкт (056)', '056_collection_target_access.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_collection_preview'
              AND prosrc LIKE '%realtor_subscriptions rs%')),

  (31, 'revoke ЗНИЩУЄ токен, а не лише протермінює (060)', '060_revoke_destroys_token.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='manage_share'
              AND prosrc LIKE '%IN (''rotate'',''revoke'')%')),
  (32, 'телефон на /v лише за згодою (061)', '061_public_phone_opt_in.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_name='users' AND column_name='public_phone')
      AND EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_public_db_preview'
                  AND prosrc LIKE '%public_phone%')),

  -- Пермісивна політика поруч зі строгою робить строгу безглуздою: правила
  -- обʼєднуються через OR. Рядок 8 цього НЕ бачив — він перевіряє лише, що
  -- строга існує, а не що пермісивної немає. Знайдено на живій базі.
  (33, 'property_files: пермісивні realtor-політики ВИДАЛЕНІ', '062_legacy_permissive_and_acl.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='property_files'
                  AND policyname IN ('pfiles_insert_realtor','pfiles_update_realtor'))),

  -- Наскрізні інваріанти
  (15, 'RLS увімкнено на всіх 15 таблицях', 'будь-яка пропущена',
      (SELECT count(*)>=15 FROM pg_tables t JOIN pg_class c ON c.relname=t.tablename
       WHERE t.schemaname='public' AND c.relrowsecurity)),
  (16, 'handle_new_user тригер на auth.users ВІДСУТНІЙ', '003_reconcile.sql',
      NOT EXISTS (SELECT 1 FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid
                  JOIN pg_namespace n ON n.oid=c.relnamespace
                  WHERE n.nspname='auth' AND c.relname='users' AND tg.tgname LIKE '%handle_new_user%')),
  (17, 'current_app_user_id парсить email-claim', '002_rls/003_reconcile.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='current_app_user_id'
              AND prosrc LIKE '%email%')),

  -- Решта КЛІЄНТСЬКИХ RPC. Їх не було тут, і це прогалина саме того класу, що
  -- вже коштувала накату: файл спирався на `mark_overdue_payments`, якої в
  -- проді не існувало, бо 024 ніколи не застосовували. Тобто прогалини всередині
  -- 001–047 ДОВЕДЕНІ, а не гіпотетичні — отже присутність будь-якої функції з
  -- того діапазону треба ПИТАТИ, а не припускати.
  --
  -- `lookup_shared_collection` — найгірший випадок: визначена ЛИШЕ в 020/023,
  -- у RELEASE.sql її немає, тож накат 048–062 її не створює. Якщо в проді її
  -- немає, deep link `col_<token>` (вхід за посиланням на підбірку) падає, і
  -- жоден файл репозиторію про це не скаже.
  (34, 'RPC lookup_shared_collection', '020/023_public_share_tokens.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='lookup_shared_collection')),
  (35, 'RPC lookup_shared_property', '020/023, оновлює 059',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='lookup_shared_property')),
  (36, 'RPC claim_guest_link', '027_guest_role.sql, оновлює 048',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='claim_guest_link')),
  (37, 'RPC get_guest_property_preview', '027_guest_role.sql, оновлює 050',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_guest_property_preview')),
  (38, 'RPC delete_my_account', '051_delete_account_storage.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='delete_my_account')),

  -- 063: сліди переглядів. ДВІ окремі перевірки, бо політика має дві гілки і
  -- кожна лікує свій випадок: без першої редактор команди не пише слід на
  -- картці, без другої перегляд БАЗИ не пише НІХТО (рядок бази має
  -- `property_id = NULL`, а `NULL IN (...)` дає NULL, не FALSE — предикат не
  -- виконувався в принципі й при цьому мовчав).
  (39, 'views_insert_auth: гілка РЕДАКТОРА команди', '063_view_insert_editors_and_dbs.sql',
      EXISTS (SELECT 1 FROM pg_policies
               WHERE tablename='property_views' AND policyname='views_insert_auth'
                 AND with_check LIKE '%get_editor_property_ids%')),
  (40, 'views_insert_auth: гілка рядка БАЗИ (property_id IS NULL)', '063_view_insert_editors_and_dbs.sql',
      EXISTS (SELECT 1 FROM pg_policies
               WHERE tablename='property_views' AND policyname='views_insert_auth'
                 AND with_check LIKE '%get_editor_db_ids%')),
  -- Урок 062: «строга політика існує» НЕ означає, що вона діє — пермісивна
  -- поруч робить її безглуздою, бо правила обʼєднуються через OR. Тому
  -- окремо перевіряємо, що INSERT-політика на цій таблиці РІВНО ОДНА.
  (41, 'property_views: INSERT-політика рівно одна', '063_view_insert_editors_and_dbs.sql',
      (SELECT count(*) FROM pg_policies
        WHERE tablename='property_views' AND cmd='INSERT') = 1),

  -- 064: орендодавець. Колонки — на ОБИДВОХ таблицях: без бази немає дефолта,
  -- без обʼєкта немає перевизначення, і кожна половина окремо безглузда.
  -- Третій рядок — про ПРЕВʼЮ: колонки можуть бути на місці, а публічна /v
  -- усе одно нічого не показує, бо функція їх не віддає.
  (42, 'databases.landlord_name', '064_landlord_name.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='databases' AND column_name='landlord_name')),
  (43, 'properties.landlord_name', '064_landlord_name.sql',
      EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema='public' AND table_name='properties' AND column_name='landlord_name')),
  (44, 'усі три публічні превʼю віддають property_landlord_name', '064_landlord_name.sql',
      (SELECT count(*) FROM pg_proc
        WHERE proname IN ('get_public_property_preview','get_public_db_preview','get_public_collection_preview')
          AND pg_get_function_result(oid) LIKE '%property_landlord_name%') = 3),

  -- 065: нагадування про кінець договору. Перевіряємо ІСНУВАННЯ функції — те,
  -- що вона невидима для `anon`, тримає окремий гард (scripts/verify-behaviour),
  -- бо в тексті GRANT цього не видно (правило 12).
  (45, 'RPC get_due_lease_reminders', '065_lease_reminders.sql',
      EXISTS (SELECT 1 FROM pg_proc WHERE proname='get_due_lease_reminders')),

  -- 066-1: якір особи. Перевіряємо саме ТІЛО: `CREATE OR REPLACE` міг бути
  -- перекритий пізнішою копією без якоря — рівно так 038 колись стерла фікс
  -- 031, і по тексту міграції цього не видно.
  (46, 'current_app_user_id: домен заякорено і tg_id > 0', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT prosrc LIKE '%telegram\\.propspace\\.app$%' AND prosrc LIKE '%tg_id_val <= 0%'
         FROM pg_proc WHERE proname='current_app_user_id' LIMIT 1)),

  -- 066-2: бакет фото не перелічується. Перевіряємо ВІДСУТНІСТЬ пермісивного
  -- варіанта, а не наявність строгого: політики обʼєднуються через OR, тож
  -- пермісивна поруч зі строгою робить строгу безглуздою (урок 062).
  (47, 'storage_photos_select звужено до authenticated', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT COUNT(*) = 1 FROM pg_policies
        WHERE schemaname='storage' AND tablename='objects'
          AND policyname='storage_photos_select'
          AND 'authenticated' = ANY(roles) AND NOT ('public' = ANY(roles))
          AND qual LIKE '%get_owner_property_ids%')),

  -- 066-3: гостьовий лінк перевіряє ціль.
  (48, 'db_guest_select звіряє owner_id цілі з видавцем', '066_identity_anchor_storage_enum_guest_target.sql',
      (SELECT COUNT(*) = 1 FROM pg_policies
        WHERE tablename='databases' AND policyname='db_guest_select'
          AND qual LIKE '%owner_id%')),

  -- 067-1: сама таблиця архіву з RLS. Без неї екран працює, просто вимкнений.
  (49, 'tenancies: таблиця існує і RLS увімкнена', '067_tenancies.sql',
      (SELECT COALESCE((SELECT relrowsecurity FROM pg_class WHERE relname='tenancies'), false))),

  -- 067-2: ТРИГЕР, а не лише функція. Функція без тригера — це мертвий код:
  -- жоден зі ТРЬОХ клієнтських шляхів звільнення її не покличе, і архів
  -- лишиться назавжди порожнім, не подавши жодного сигналу.
  (50, 'trg_sync_tenancy висить на properties', '067_tenancies.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='properties' AND t.tgname='trg_sync_tenancy' AND NOT t.tgisinternal)),

  -- 067-3: рівно ОДНА відкрита оренда на обʼєкт. Без цього індексу повторне
  -- відкриття плодило б дублі, і «отримано» рахувалось би двічі.
  (51, 'частковий UNIQUE: одна відкрита оренда на обʼєкт', '067_tenancies.sql',
      (SELECT COUNT(*) = 1 FROM pg_indexes
        WHERE tablename='tenancies' AND indexname='idx_tenancies_one_open')),

  -- 068: архів — ЛИШЕ читання для клієнтів, двома шарами. Перевіряється
  -- ВІДСУТНІСТЬ політик запису, а не наявність SELECT-політики: строга
  -- політика поруч із пермісивною нічого не значить (урок рядка 33).
  (52, 'tenancies: клієнт не має права запису (політики + табличні права)', '068_tenancies_read_only.sql',
      (SELECT NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tenancies' AND cmd <> 'SELECT')
          AND EXISTS (SELECT 1 FROM pg_policies WHERE tablename='tenancies' AND cmd = 'SELECT')
          AND COALESCE((SELECT NOT has_table_privilege('authenticated', c.oid, 'DELETE')
                               AND NOT has_table_privilege('authenticated', c.oid, 'UPDATE')
                               AND NOT has_table_privilege('authenticated', c.oid, 'INSERT')
                          FROM pg_class c WHERE c.relname='tenancies' AND c.relkind='r'), false))),

  -- 069-1: гостьове запрошення не знижує власника, що МАЄ бази. Без цього
  -- власник, який прийняв чуже запрошення, втрачає таббар «Бази» назавжди.
  (53, 'claim_guest_link не знижує власника з базами', '069_access_integrity.sql',
      (SELECT COUNT(*) >= 1 FROM pg_proc
        WHERE proname='claim_guest_link'
          AND prosrc LIKE '%NOT EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = v_uid)%')),

  -- 069-2: «Відкликати доступ» / «Оновити посилання» забирають доступ у вже
  -- підписаних рієлторів. Без цього шит обіцяв те, чого сервер не робив.
  (54, 'manage_share: rotate/revoke знімають підписки рієлторів', '069_access_integrity.sql',
      (SELECT COUNT(*) >= 1 FROM pg_proc
        WHERE proname='manage_share'
          AND prosrc LIKE '%DELETE FROM realtor_subscriptions%')),

  -- 069-3: ремонт відпрацював — знижених власників не лишилось. Перевіряє
  -- ДАНІ, а не код: функцію можна виправити, а людей так і не повернути.
  (55, 'немає гостей, що володіють базами (ремонт 069)', '069_access_integrity.sql',
      (SELECT NOT EXISTS (SELECT 1 FROM users u
                           WHERE u.role='guest'
                             AND EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = u.id)))),

  -- 070: нагадування НЕ йде про вже підтверджений платіж. Обидві функції —
  -- власницька й гостьова: орендар-гість отримував те саме хибне «оплата
  -- через 3 дні», хоч сам уже заплатив.
  (56, 'нагадування пропускають підтверджені платежі (власник і гість)', '070_reminders_skip_paid.sql',
      (SELECT COUNT(*) = 2 FROM pg_proc
        WHERE proname IN ('get_due_reminders_today','get_due_guest_reminders')
          AND prosrc LIKE '%FROM rent_payment_records r%'
          AND prosrc LIKE '%r.status = ''paid''%')),

  -- 071-1: надходження — окрема таблиця з RLS, і обидві політики питають про
  -- ЦІЛЬ (обʼєкт власника чи бази команди), а не лише «чи це мій рядок».
  (57, 'rent_payment_parts: RLS увімкнена, власник і редактор', '071_partial_payments.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='rent_payment_parts' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='rent_payment_parts'
                  AND policyname IN ('parts_owner_all','parts_editor_all')
                  AND with_check LIKE '%property_ids%'))),

  -- 071-2: ТРИГЕР, а не лише функція — інакше надходження пишуться, а
  -- підсумок періоду (сума, статус) лишається старим, і календар бреше.
  (58, 'trg_sync_rent_record_from_parts висить на rent_payment_parts', '071_partial_payments.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='rent_payment_parts' AND t.tgname='trg_sync_rent_record_from_parts' AND NOT t.tgisinternal)),

  -- 071-3: статус «частково» легальний. Без нового CHECK тригер падав би на
  -- КОЖНОМУ неповному надходженні, тобто фіча працювала б лише для повних.
  (59, 'rent_payment_records.status приймає partial', '071_partial_payments.sql',
      (SELECT COUNT(*) >= 1 FROM pg_constraint
        WHERE conrelid = to_regclass('public.rent_payment_records') AND contype='c'
          AND pg_get_constraintdef(oid) LIKE '%partial%')),

  -- 071-4: RPC є, автентифікованому доступна, анонімові — ні (правило 12:
  -- без явного REVOKE дефолтний PUBLIC лишився б).
  (60, 'record_rent_payment: authenticated так, anon ні', '071_partial_payments.sql',
      (SELECT COALESCE((SELECT has_function_privilege('authenticated', p.oid, 'EXECUTE')
                               AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
                          FROM pg_proc p WHERE p.proname='record_rent_payment' LIMIT 1), false))),

  -- 072-1: історія умов — лише ЧИТАННЯ для клієнтів (урок 068). Друга
  -- половина важливіша за першу: без неї «політика за зразком» відкрила б
  -- запис мовчки, і «ставка, що діяла тоді» стала б тим, що захотіли.
  (61, 'property_rent_terms: RLS, лише SELECT, запис клієнтам закритий', '072_rent_terms_history.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='property_rent_terms' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='property_rent_terms' AND cmd='SELECT'
                  AND policyname IN ('rent_terms_owner_select','rent_terms_editor_select'))
          AND (SELECT COUNT(*) = 0 FROM pg_policies
                WHERE tablename='property_rent_terms' AND cmd <> 'SELECT')
          AND CASE WHEN to_regclass('public.property_rent_terms') IS NULL THEN false
                   ELSE NOT has_table_privilege('authenticated', 'public.property_rent_terms', 'INSERT') END)),

  -- 072-2: ТРИГЕР, а не лише функція — без нього історія лишається порожньою
  -- назавжди, і борг рахується з поточної ставки БЕЗ жодного сигналу.
  (62, 'trg_record_rent_terms висить на properties', '072_rent_terms_history.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='properties' AND t.tgname='trg_record_rent_terms' AND NOT t.tgisinternal)),

  -- 072-3: сума за період — authenticated так, anon ні (правило 12).
  (63, 'set_rent_amount_due: authenticated так, anon ні', '072_rent_terms_history.sql',
      (SELECT COALESCE((SELECT has_function_privilege('authenticated', p.oid, 'EXECUTE')
                               AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
                          FROM pg_proc p WHERE p.proname='set_rent_amount_due' LIMIT 1), false))),

  -- 073-1: журнал змін — лише ЧИТАННЯ для клієнтів (урок 068): журнал, який
  -- редактор може підправити, не відповідає на «хто це зробив».
  (64, 'db_activity: RLS, лише SELECT, запис клієнтам закритий', '073_db_activity.sql',
      (SELECT COALESCE((SELECT c.relrowsecurity FROM pg_class c
                          WHERE c.relname='db_activity' AND c.relkind='r'), false)
          AND (SELECT COUNT(*) = 2 FROM pg_policies
                WHERE tablename='db_activity' AND cmd='SELECT'
                  AND policyname IN ('activity_owner_select','activity_editor_select'))
          AND (SELECT COUNT(*) = 0 FROM pg_policies
                WHERE tablename='db_activity' AND cmd <> 'SELECT')
          AND CASE WHEN to_regclass('public.db_activity') IS NULL THEN false
                   ELSE NOT has_table_privilege('authenticated', 'public.db_activity', 'INSERT') END)),

  -- 073-2: ТРИГЕРИ на всіх пʼяти таблицях. Таблиця без тригерів — це журнал,
  -- що мовчить завжди, тобто «змін не було», яке читається як правда.
  (65, 'журнал: тригери на properties, надходженнях, періодах, розкладі, документах, фото', '073_db_activity.sql',
      (SELECT COUNT(*) = 6 FROM pg_trigger t
        WHERE NOT t.tgisinternal AND t.tgname IN (
          'trg_activity_property', 'trg_activity_rent_part', 'trg_activity_rent_record',
          'trg_activity_rent_schedule', 'trg_activity_property_files', 'trg_activity_property_photos'))),

  -- 073-3: автора надходження ставить сервер — інакше редактор міг би
  -- «записати» гроші від імені власника.
  (66, 'rent_payment_parts: автор ставиться тригером', '073_db_activity.sql',
      (SELECT COUNT(*) = 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE c.relname='rent_payment_parts' AND t.tgname='trg_stamp_rent_part_author' AND NOT t.tgisinternal)),

  -- 074-1: автор надходження звільняється, коли акаунт видалено. Без винятку
  -- тригер 073 скасовував каскад `SET NULL`, і ключ лишався на неіснуючому
  -- користувачі — логічний бекап на такому обмеженні не відновлюється.
  (67, 'автор надходження не висне після видалення акаунта', '074_account_erasure.sql',
      (SELECT COALESCE(bool_or(p.prosrc LIKE '%NOT EXISTS (SELECT 1 FROM users u WHERE u.id = OLD.created_by)%'), false)
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'stamp_rent_part_author')),

  -- 074-2: імʼя йде слідом за посиланням — у журналі, переглядах і гостьових
  -- лінках. Без тригерів «видалити акаунт і всі повʼязані дані» з Політики
  -- лишається неправдою щодо чужих баз.
  (68, 'видалений акаунт: імʼя стирається з журналу, переглядів і гостьових лінків', '074_account_erasure.sql',
      (SELECT COUNT(*) = 3 FROM pg_trigger t
        WHERE NOT t.tgisinternal
          AND t.tgname IN ('trg_erase_viewer_name', 'trg_erase_guest_name', 'trg_erase_actor_name'))),

  -- 051: стирання файлів при видаленні акаунта тримається на ЗОВНІШНІЙ умові —
  -- власник функції обходить RLS (у Supabase це `postgres`), бо delete-політики
  -- storage видані лише `authenticated`. Доти це показувала тільки хвостова
  -- вибірка самої 051, а редактор SQL показує ЛИШЕ ОСТАННЮ таблицю — тож у
  -- RELEASE.sql із вбудованою перевіркою її вже не видно. Тому вона тут.
  -- Порада правильна: 051 дропає функцію і створює заново, тобто повторний
  -- запуск у SQL Editor робить її власником саме `postgres`.
  -- Що anon її НЕ кличе, тримає рядок 70 (075): `delete_my_account` поза
  -- allowlist-ом. Тут лише те, що дає сама 051, — інакше ❌ радив би
  -- перезапустити не ту міграцію.
  (69, 'delete_my_account: власник обходить RLS, authenticated кличе', '051_delete_account_storage.sql',
      (SELECT COALESCE(bool_and(
                  has_function_privilege('authenticated', p.oid, 'EXECUTE')
              AND COALESCE((SELECT r.rolbypassrls FROM pg_roles r
                             WHERE r.rolname = pg_get_userbyid(p.proowner)), false)), false)
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname = 'delete_my_account')),

  -- 075-1: anon виконує лише свідомо публічні функції. Supabase видає EXECUTE
  -- на КОЖНУ нову функцію `anon` і `authenticated` прямим грантом, тож
  -- `REVOKE ... FROM PUBLIC` у міграції його не знімає — так у проді й
  -- лишились відкритими get_due_lease_reminders і log_db_activity. Список —
  -- той самий, що в 075 і в scripts/verify-behaviour.sql (звіряє юніт-тест).
  (70, 'anon кличе лише свідомо публічні функції', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public' AND p.prokind = 'f'
                     AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
                     AND NOT EXISTS (SELECT 1 FROM pg_depend d
                                      WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
                     AND has_function_privilege('anon', p.oid, 'EXECUTE')
                     AND p.proname NOT IN (
                       'get_public_db_preview', 'get_public_property_preview',
                       'get_public_collection_preview', 'get_guest_property_preview',
                       'record_public_view',
                       'current_app_user_id', 'get_app_user_id_from_auth_uid',
                       'get_owner_db_ids', 'get_owner_property_ids',
                       'get_editor_db_ids', 'get_editor_db_ids_from_auth_uid', 'get_editor_property_ids',
                       'get_realtor_db_ids', 'get_realtor_property_ids', 'get_realtor_collection_ids',
                       'is_guest_of_property'))),

  -- 075-2: службові функції — лише service_role. Перевірка вище дивиться на
  -- anon, а цим не можна й тим, хто увійшов: одна віддає дані ВСІХ власників,
  -- друга пише в журнал БУДЬ-ЯКОЇ бази.
  (71, 'службові функції не кличе ні anon, ні authenticated', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public'
                     AND p.proname IN ('get_due_lease_reminders', 'get_due_reminders_today',
                                       'get_due_guest_reminders', 'mark_overdue_payments', 'log_db_activity')
                     AND (has_function_privilege('anon', p.oid, 'EXECUTE')
                          OR has_function_privilege('authenticated', p.oid, 'EXECUTE')))),

  -- 075-3: ДЖЕРЕЛО класу — default privileges. Поки в них anon/authenticated,
  -- наступна службова функція знову відкриється сама.
  -- Схемний І глобальний запис: схемні default privileges додаються до
  -- глобальних, тож глобальний грант пережив би схемний REVOKE.
  (72, 'нова функція не відкривається anon/authenticated сама', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
                   WHERE (d.defaclnamespace = 0 OR n.nspname = 'public') AND d.defaclobjtype = 'f'
                     AND pg_get_userbyid(d.defaclrole) = 'postgres'
                     AND array_to_string(d.defaclacl, ',') ~ '(^|,)(anon|authenticated)=')),

  -- 075-4: друга межа периметра. Закривши функцію для anon, легко зачепити
  -- хелпер, який кличе САМА політика з роллю {public}: анонімний запит до
  -- таблиці тоді падає помилкою замість порожнечі, тобто /v ламається.
  -- Питаємо фінальні політики, а не текст міграцій.
  (73, 'політики {public} кличуть лише функції, доступні anon', '075_function_acl_supabase_defaults.sql',
      NOT EXISTS (SELECT 1 FROM pg_policies pol
                   CROSS JOIN LATERAL regexp_matches(coalesce(pol.qual, '') || ' ' || coalesce(pol.with_check, ''),
                                                     '([a-z_][a-z0-9_]*)\(', 'g') AS m
                   JOIN pg_proc f ON f.proname = m[1]
                   JOIN pg_namespace ns ON ns.oid = f.pronamespace AND ns.nspname = 'public'
                  WHERE ('public' = ANY (pol.roles) OR 'anon' = ANY (pol.roles))
                    AND NOT has_function_privilege('anon', f.oid, 'EXECUTE'))),

  -- 075 закрила log_db_activity для клієнтів, тож журнал живе лише тим, що
  -- тригери — SECURITY DEFINER, а їхній власник сам має EXECUTE. Тригер,
  -- перестворений іншою роллю чи як INVOKER, валив би саму ДІЮ (його виклик
  -- журналу не загорнутий у перехоплення), а не лише подію журналу.
  (74, 'тригери журналу можуть писати в журнал', '073_db_activity.sql',
      (SELECT COALESCE(bool_and(c.prosecdef AND has_function_privilege(c.proowner, l.oid, 'EXECUTE')), false)
         FROM pg_proc l JOIN pg_namespace ln ON ln.oid = l.pronamespace AND ln.nspname = 'public'
         JOIN pg_proc c ON c.prosrc LIKE '%log_db_activity(%' AND c.oid <> l.oid
         JOIN pg_namespace cn ON cn.oid = c.pronamespace AND cn.nspname = 'public'
        WHERE l.proname = 'log_db_activity')),

  -- 076: особу засвідчує app_metadata, яку пише лише службовий ключ. Без
  -- цього email у токені — єдине джерело особи, а його можна обрати самому
  -- (самореєстрація в Auth, зміна email, анонімний вхід + зміна email).
  (75, 'особа засвідчується сервером (app_metadata), а не лише email', '076_identity_server_provenance.sql',
      (SELECT count(*) = 2 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public'
        WHERE p.proname IN ('current_app_user_id', 'get_app_user_id_from_auth_uid')
          AND p.prosrc LIKE '%raw_app_meta_data%')),

  -- 076, друга половина: жоден справжній користувач не лишився без
  -- засвідчення — інакше він тихо бачить порожній застосунок. ❌ тут після
  -- накату означає, що edge-функцію `telegram-auth` не передеплоєно (стара
  -- версія створює нових користувачів без app_metadata).
  (76, 'усі користувачі входу засвідчені (app_metadata.tg_id)', '076_identity_server_provenance.sql',
      NOT EXISTS (SELECT 1 FROM auth.users au
                   WHERE au.email ~ '^\d{1,20}@telegram\.propspace\.app$'
                     AND au.email_confirmed_at IS NOT NULL
                     AND EXISTS (SELECT 1 FROM public.users u WHERE u.tg_id::text = split_part(au.email, '@', 1))
                     AND au.raw_app_meta_data->>'tg_id' IS DISTINCT FROM split_part(au.email, '@', 1)))
)
SELECT
  CASE WHEN ok THEN '✅ OK     ' ELSE '❌ MISSING' END AS status,
  item,
  CASE WHEN ok THEN '' ELSE '→ виконай ' || migration END AS action
FROM checks ORDER BY ord;
