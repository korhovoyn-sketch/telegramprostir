-- ============================================================================
-- 062 — залишок 038 БЕЗ його регресії, плюс ACL, що пережив 052
-- ============================================================================
--
-- ЗНАЙДЕНО НАКАТОМ У ПРОДІ, не аудитом: `verify_release.sql` дав два MISSING
-- на базі, де все інше зелене.
--
-- ── ЧОМУ НЕ ПРОСТО «ВИКОНАЙ 038» ───────────────────────────────────────────
-- Саме це радив `verify_release.sql`, і ця порада НЕБЕЗПЕЧНА. 038 містить
-- власну «самодостатню» копію `get_app_user_id_from_auth_uid()`, узяту ДО
-- 031 — без доменного якоря (`email ~ '^\d{1,20}@telegram\.propspace\.app$'`)
-- і без `tg_id > 0`. Це рівно та регресія, яку лікувала 045 (див. CLAUDE.md
-- §0h): без якоря `SPLIT_PART(email,'@',1) = tg_id` дозволяє самостійну
-- реєстрацію під `<чийсь_tg_id>@будь-що.example` і резолвиться в `users.id`
-- ЖЕРТВИ, тобто дає запис і видалення її фото.
--
-- У базі, де 038 ніколи не застосовувалась, а 045 застосована, запуск 038
-- зараз ВІДКОТИВ БИ фікс. Тому 062 бере з 038 лише те, чого бракує —
-- прибирання пермісивних політик — і не чіпає жодної функції ідентичності.
--
-- Порада в `verify_release.sql` виправлена тим самим дифом: рядок 6 тепер
-- вказує сюди. Гард, що радить небезпечну дію, гірший за відсутній — той
-- самий клас, що вже описаний для стенда, який плутав збій зʼєднання з
-- дефектом міграції.
--
-- ── ЩО САМЕ ЛІКУЄ ──────────────────────────────────────────────────────────
-- 1. `photos_insert_auth` / `photos_delete_auth` (з 008) дозволяють БУДЬ-ЯКОМУ
--    автентифікованому користувачу писати й видаляти БУДЬ-ЯКИЙ шлях у бакеті
--    photos. Політики обʼєднуються через OR, тож строгі правила 054 нічого не
--    обмежують, поки ці двоє живі: строга + пермісивна = пермісивна.
--    А `/v` публічно віддає `storage_path` кожного фото, тож ціль не треба
--    вгадувати.
-- 2. `pfiles_insert_realtor` / `pfiles_update_realtor` — те саме на таблиці
--    `property_files`: підписаний рієлтор вставляє файловий рядок на ЧУЖИЙ
--    обʼєкт. `verify_release` рядок 8 цього не бачив — він перевіряє лише, що
--    СТРОГА політика існує, а не що пермісивної немає.
-- 3. `storage_photos_update` — 054 відтворила insert/delete, але не update.
-- 4. Дефолтний PUBLIC на функціях нагадувань. 052 його знімала, але в проді
--    він лишився — отже там є варіант функції, до якого `REVOKE` за точною
--    сигнатурою не дійшов (інша сигнатура, або перевантаження). Тому тут
--    REVOKE йде ДИНАМІЧНО по ВСІХ перевантаженнях за іменем: так це працює
--    незалежно від того, яка саме форма лежить у базі.
--
-- Ідемпотентна.

-- ── 1. Пермісивні політики запису в storage ─────────────────────────────────
DROP POLICY IF EXISTS "photos_insert_auth" ON storage.objects;
DROP POLICY IF EXISTS "photos_delete_auth" ON storage.objects;

-- ── 2. Пермісивні політики на property_files ────────────────────────────────
DROP POLICY IF EXISTS "pfiles_insert_realtor" ON property_files;
DROP POLICY IF EXISTS "pfiles_update_realtor" ON property_files;

-- ── 3. UPDATE на фото — той самий рецепт, що insert/delete у 054 ────────────
-- Одне джерело особи (sub-клейм через хелпер), без залежності від email-клейма
-- — див. 054 про політику, що впізнавала людину двома незалежними способами.
DROP POLICY IF EXISTS "storage_photos_update" ON storage.objects;
CREATE POLICY storage_photos_update ON storage.objects
  FOR UPDATE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── 4. Дефолтний PUBLIC на службових функціях ───────────────────────────────
-- По ІМЕНІ, а не по сигнатурі: у проді лишився грант, якого точний REVOKE із
-- 052 не зняв, отже там інша форма функції. `oid::regprocedure` дає повний
-- підпис для будь-якого перевантаження.
DO $$
DECLARE r RECORD; n INT := 0;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
     WHERE ns.nspname = 'public'
       AND p.proname IN ('get_due_reminders_today',
                         'get_due_guest_reminders',
                         'mark_overdue_payments')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', r.sig);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM anon', r.sig);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM authenticated', r.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', r.sig);
    n := n + 1;
    RAISE NOTICE '062: замкнено %', r.sig;
  END LOOP;
  IF n = 0 THEN
    RAISE NOTICE '062: функцій нагадувань не знайдено — 052 не застосована?';
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

-- ── Verification ────────────────────────────────────────────────────────────
-- Має показати нуль рядків. Кожен рядок = пермісивна політика або відкрита
-- службова функція, що лишились.
SELECT 'політика' AS kind, policyname AS name
  FROM pg_policies
 WHERE policyname IN ('photos_insert_auth','photos_delete_auth',
                      'pfiles_insert_realtor','pfiles_update_realtor')
UNION ALL
SELECT 'функція відкрита для anon', p.oid::regprocedure::TEXT
  FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
 WHERE ns.nspname = 'public'
   AND p.proname IN ('get_due_reminders_today','get_due_guest_reminders','mark_overdue_payments')
   AND has_function_privilege('anon', p.oid, 'EXECUTE');
