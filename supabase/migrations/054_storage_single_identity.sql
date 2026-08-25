-- ============================================================================
-- 054 — storage-політики: ОДНЕ джерело особи замість двох
-- ============================================================================
-- Знайдено ВИКОНАННЯМ політик (`scripts/verify-rls.sql`), і знайдено як
-- ВАКУУМНИЙ ТЕСТ: перевірка «Аліса не зітре фото Богдана» проходила — але
-- Аліса не могла зітерти й ВЛАСНЕ фото. Тобто політика відмовляла всім, і
-- «доказ» не доводив нічого. Антивакуумна пара (те саме, але зі своїм
-- файлом) це й проявила.
--
-- ── ЧОМУ ТАК ВИХОДИЛО ──────────────────────────────────────────────────────
-- `storage_photos_delete` (038) перевіряє власність через
-- `get_app_user_id_from_auth_uid()` — тобто по `sub`-клейму. Але робить це
-- ПІДЗАПИТОМ `FROM properties`, а на `properties` діє RLS, яка резолвить
-- особу через `current_app_user_id()` — тобто по EMAIL-клейму. Отже кожен
-- запис у storage мовчки вимагає ОБИДВА клейми одночасно.
--
-- Заміряно на живій БД:
--   обидва клейми → DELETE 1
--   лише `sub`    → DELETE 0   (мовчки, без помилки)
--
-- Це рівно та крихкість, через яку 030 і завела `*_from_auth_uid`-варіанти:
-- `current_app_user_id()` у storage-контексті ненадійний. 038 замінила
-- ЗОВНІШНІЙ предикат і лишила внутрішній підзапит під тією ж функцією, а
-- `pfiles_storage_insert`/`delete` узагалі лишились на email-клеймі напряму.
--
-- **Це НЕ звіт про живий баг:** чи присутній email-клейм у storage-контексті
-- проду, з цього середовища перевірити неможливо (мережі до Supabase немає).
-- Якщо присутній — усе працює, і 054 просто прибирає непотрібну залежність;
-- якщо ні — 054 лагодить видалення фото й документів. У будь-якому разі
-- політика, що залежить від ДВОХ незалежних джерел особи, не має на це
-- причин: обидва описують ТУ САМУ людину.
--
-- ── ЯК ЛІКУЄТЬСЯ ───────────────────────────────────────────────────────────
-- Підзапит іде через SECURITY DEFINER хелпери (`get_owner_property_ids`,
-- `get_editor_property_ids`, `get_realtor_db_ids`), які обходять RLS на
-- `properties`. Рівно так уже зроблено в політиках `public.property_photos`
-- (`photos_owner_all`) — тобто це не новий прийом, а вирівнювання storage по
-- вже наявному.
--
-- СЕМАНТИКА НЕ МІНЯЄТЬСЯ: ті самі бакети, ті самі ролі, ті самі права.
-- Міняється лише те, ЧИМ політика впізнає людину.
-- ============================================================================

-- ── photos: власник ────────────────────────────────────────────────────────
DROP POLICY IF EXISTS storage_photos_insert ON storage.objects;
CREATE POLICY storage_photos_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS storage_photos_delete ON storage.objects;
CREATE POLICY storage_photos_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── photos: редактор команди (041) ─────────────────────────────────────────
DROP POLICY IF EXISTS storage_photos_editor_insert ON storage.objects;
CREATE POLICY storage_photos_editor_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS storage_photos_editor_delete ON storage.objects;
CREATE POLICY storage_photos_editor_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'photos'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- ── property-files ─────────────────────────────────────────────────────────
-- Ці дві були найгіршим випадком: `current_app_user_id()` НАПРЯМУ, без
-- жодного auth_uid-варіанта.
DROP POLICY IF EXISTS pfiles_storage_insert ON storage.objects;
CREATE POLICY pfiles_storage_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'property-files'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

DROP POLICY IF EXISTS pfiles_storage_delete ON storage.objects;
CREATE POLICY pfiles_storage_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'property-files'
    AND split_part(name, '/', 1) IN (
      SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
    )
  );

-- Читання: власник АБО підписаний рієлтор — той самий набір, що й був
-- (026 + 038), лише без підзапитів під RLS.
DROP POLICY IF EXISTS pfiles_storage_select ON storage.objects;
CREATE POLICY pfiles_storage_select ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'property-files'
    AND (
      split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_owner_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_realtor_property_ids(get_app_user_id_from_auth_uid()) p
      )
      OR split_part(name, '/', 1) IN (
        SELECT p::TEXT FROM get_editor_property_ids(get_app_user_id_from_auth_uid()) p
      )
    )
  );
