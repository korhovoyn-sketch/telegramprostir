-- ============================================================================
-- 053 — КРИТИЧНО: політика власника перевіряла ЛИШЕ `owner_id = я`,
--       але не те, що ЦІЛЬ (база / обʼєкт) належить мені
-- ============================================================================
-- Той самий клас, що вже виправляла 046 для `guest_links`, і рівно те, що
-- Security rules описують правилом 11 — але на ЦЕНТРАЛЬНІЙ таблиці застосунку.
-- Знайдено ВИКОНАННЯМ політик (`scripts/verify-rls.sql`): RLS у цьому проєкті
-- досі не виконувалась жодного разу — e2e ганяються проти герметичного мока,
-- де політик не існує, а юніт-гарди читають SQL як текст.
--
-- Асиметрія видно неозброєним оком, щойно політики покласти поруч:
--   props_editor_all (041): db_id IN get_editor_db_ids(...) AND owner_id = <власник бази>
--   props_owner_all  (009): owner_id = current_app_user_id()          ← і все
-- Тобто редакторський бік, написаний пізніше, робить перевірку правильно, а
-- власницький — ні.
--
-- ── ЩО ЦЕ ДАВАЛО (перевірено, не припущено) ────────────────────────────────
-- Будь-який автентифікований власник вставляє СВІЙ рядок у ЧУЖУ базу:
--   INSERT INTO properties (db_id, owner_id, …) VALUES (<чужа база>, <я>, …)
-- `WITH CHECK` проходить, бо owner_id справді мій. Далі:
--   • рядок ВИДНО на публічній /v сторінці жертви (`get_public_db_preview` —
--     SECURITY DEFINER, вибирає по db_id, тобто RLS її не обмежує);
--   • рядок ВИДНО кожному підписаному рієлтору жертви — як обʼєкт власника;
--   • жертва його НЕ БАЧИТЬ (її політика фільтрує по owner_id), тобто не може
--     ні знайти, ні видалити з застосунку.
-- `db_id` жертви для цього не треба вгадувати: його віддає
-- `get_public_db_preview(token)` — тобто досить будь-якого шер-лінка, а це і
-- є призначення фічі.
--
-- ── ТОЙ САМИЙ КЛАС НА ПЛАТЕЖАХ, І ВІН ЛЕДЬ НЕ СТАВ ЖИВИМ ───────────────────
-- `rent_payments`/`rent_payment_records` мають те саме `owner_id = я` без
-- перевірки, що обʼєкт мій. Наслідок конкретний: `get_due_reminders_today()`
-- джойнить `rent_payments → properties → users` по `rp.owner_id`, тож
-- підкинутий на ЧУЖИЙ обʼєкт розклад щомісяця надсилає АТАКУВАЛЬНИКУ в
-- Telegram назву обʼєкта жертви та ІМʼЯ ЇЇ ОРЕНДАРЯ. Перевірено на живій БД:
-- «отримає: Аліса | Офіс Богдана | ТАЄМНИЙ ОРЕНДАР БОГДАНА».
--
-- **Це вмикається рівно тоді, коли 052 полагодить нагадування** — доти
-- функція падала на типі результату і не віддавала нічого. Тобто 052 без 053
-- гірша за жодну з них: вона активує канал витоку. Тому 053 — обовʼязкова
-- пара до 052.
--
-- ── ГІПОТЕЗА, ЯКУ Я СПЕРШУ «СПРОСТУВАВ» ХИБНО (див. 056) ───────────────────
-- `collection_properties` має ту саму форму, і тут спершу було записано, що
-- публічної поверхні в цього немає. **Це було НЕПРАВДОЮ через хибний замір:**
-- тестова підбірка створювалась без `is_draft`, а дефолт цієї колонки TRUE,
-- тоді як превʼю фільтрує `is_draft = false`. Тобто нуль рядків пояснювався
-- ЧЕРНЕТКОЮ. На опублікованій підбірці гіпотеза підтвердилась — виправлено
-- міграцією 056.
-- ============================================================================

-- ── 1. ЗАПИС ───────────────────────────────────────────────────────────────
DROP POLICY IF EXISTS props_owner_all ON properties;
CREATE POLICY props_owner_all ON properties FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
  );

DROP POLICY IF EXISTS "owner manages rent_payments" ON rent_payments;
CREATE POLICY "owner manages rent_payments" ON rent_payments FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  );

DROP POLICY IF EXISTS "owner manages payment_records" ON rent_payment_records;
CREATE POLICY "owner manages payment_records" ON rent_payment_records FOR ALL
  USING (owner_id = current_app_user_id())
  WITH CHECK (
    owner_id = current_app_user_id()
    AND property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  );

-- ── 2. ВЖЕ ПОСАДЖЕНІ РЯДКИ ─────────────────────────────────────────────────
-- Урок 046 дослівно: правити треба ОБИДВА боки, інакше рядки, вставлені до
-- фікса, продовжують діяти. Тут вони ще й НЕВИДИМІ для жертви, тож самотужки
-- вона їх не прибере.
--
-- Ремонт — ПЕРЕПРИВЛАСНЕННЯ, а не видалення: `owner_id` стає власником бази
-- (для платежів — власником обʼєкта). Так рядок повертається під контроль
-- того, кому належить ціль, і той сам вирішує, лишити чи прибрати. Видалення
-- тут було б необоротним, а серед розбіжностей можуть бути й легасі-рядки
-- від `moveToDatabase` з ненадійним `?? user.id` (описано в CLAUDE.md).
DO $$
DECLARE n_props INT; n_pay INT; n_rec INT;
BEGIN
  UPDATE properties p SET owner_id = d.owner_id
  FROM databases d WHERE d.id = p.db_id AND p.owner_id <> d.owner_id;
  GET DIAGNOSTICS n_props = ROW_COUNT;

  UPDATE rent_payments rp SET owner_id = p.owner_id
  FROM properties p WHERE p.id = rp.property_id AND rp.owner_id <> p.owner_id;
  GET DIAGNOSTICS n_pay = ROW_COUNT;

  UPDATE rent_payment_records rr SET owner_id = p.owner_id
  FROM properties p WHERE p.id = rr.property_id AND rr.owner_id <> p.owner_id;
  GET DIAGNOSTICS n_rec = ROW_COUNT;

  RAISE NOTICE '053: переприсвоєно власника — обʼєктів %, розкладів %, платежів %',
    n_props, n_pay, n_rec;
END $$;

-- ── 3. ГЛИБИННИЙ ЗАХИСТ У САМІЙ ФУНКЦІЇ НАГАДУВАНЬ ─────────────────────────
-- Політика тепер не пропустить нового підкидня, а ремонт вище прибрав старих.
-- Але канал витоку варто закрити і з боку споживача: нагадування має сенс
-- ЛИШЕ коли розклад і обʼєкт належать одній особі. Один рядок, і жодна
-- майбутня діра в записі вже не перетворюється на розсилку чужих даних.
CREATE OR REPLACE FUNCTION get_due_reminders_today()
RETURNS TABLE (
  owner_id      UUID,
  tg_id         BIGINT,
  property_id   UUID,
  property_name TEXT,
  due_day       INT,
  tenant_name   TEXT,
  due_date      DATE
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE v_today DATE := current_date;
BEGIN
  RETURN QUERY
  SELECT rp.owner_id, u.tg_id, rp.property_id,
         p.name::TEXT,
         rp.due_day::INT,
         p.tenant_name::TEXT,
         make_date(
           EXTRACT(YEAR  FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           EXTRACT(MONTH FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT,
           LEAST(
             rp.due_day,
             EXTRACT(DAY FROM (
               DATE_TRUNC('month', (v_today + rp.notify_days_before * INTERVAL '1 day'))
               + INTERVAL '1 month' - INTERVAL '1 day'
             ))::INT
           )
         )
  FROM rent_payments rp
  JOIN properties p ON p.id = rp.property_id
  JOIN users u ON u.id = rp.owner_id
  WHERE rp.is_active = true
    AND p.status = 'occupied'
    AND rp.owner_id = p.owner_id   -- 053: не розсилати чужі дані власнику розкладу
    AND EXTRACT(DAY FROM (v_today + rp.notify_days_before * INTERVAL '1 day'))::INT = rp.due_day
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.user_id = rp.owner_id
        AND n.type = 'rent_reminder'
        AND (n.data->>'property_id')::UUID = rp.property_id
        AND DATE_TRUNC('month', n.created_at) = DATE_TRUNC('month', v_today::TIMESTAMPTZ)
    );
END;
$$;
REVOKE ALL ON FUNCTION get_due_reminders_today() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO service_role;

NOTIFY pgrst, 'reload schema';
