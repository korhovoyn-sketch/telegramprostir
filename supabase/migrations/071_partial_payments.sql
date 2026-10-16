-- ============================================================================
-- 071 — ЧАСТКОВА ОПЛАТА: платіж за період складається з НАДХОДЖЕНЬ
-- ============================================================================
-- Доти `rent_payment_records` мав рівно один стан «отримано»: рядок на
-- (обʼєкт, дату платежу) зі статусом `paid` і сумою. Орендар, що заплатив
-- $1 000 із $1 800, давав власнику два погані варіанти: підтвердити як
-- `paid` (і борг $800 зникав з календаря, лічильника й нагадувань) або не
-- підтверджувати (і $1 000, які вже в кишені, не існували для архіву).
--
-- МОДЕЛЬ: рядок `rent_payment_records` лишається ПЕРІОДОМ (нарахуванням), а
-- гроші, що прийшли, — окремі НАДХОДЖЕННЯ в `rent_payment_parts`, кожне зі
-- своєю датою й приміткою. Підсумок періоду (`amount`, `paid_at`, `status`)
-- рахує СЕРВЕР тригером, а не клієнт:
--   * сума надходжень ≥ `amount_due`  → `paid`;
--   * більше нуля, але менше          → `partial`;
--   * надходжень немає                → `pending` (024 зробить `overdue`).
--
-- ЧОМУ ТАК, А НЕ «ОДНА СУМА, ЯКУ ДОПИСУЮТЬ». Дописування втрачає ДАТИ
-- надходжень («коли він доплатив?» — перше питання будь-якої суперечки), а
-- читання-зміна-запис з двох пристроїв (власник і редактор) губить одне з
-- надходжень. Тут сума — агрегат під блокуванням рядка періоду.
--
-- ЧОМУ ВСІ НАЯВНІ СПОЖИВАЧІ НЕ ЛАМАЮТЬСЯ. `amount` лишається «скільки
-- отримано за період», `status = 'paid'` лишається «закрито повністю». Тобто
-- календар, нагадування (070 пропускає лише `paid`), архів оренд — усі
-- читають той самий контракт; частковий період для них просто НЕ закритий.
--
-- `amount_due` — ЗАМОРОЖЕНА очікувана сума. Ставка оренди змінюється, і
-- старий період, порахований за новою ставкою, раптом ставав би «частковим»
-- (або «закритим») заднім числом. Тому сума фіксується в мить ПЕРШОГО
-- надходження і далі не рухається. NULL — очікуване невідоме (обʼєкт без
-- ставки): тоді будь-яке надходження закриває період, як і доти.
-- ============================================================================

BEGIN;

-- ── 1. Період: заморожена очікувана сума і стан «частково» ─────────────────
ALTER TABLE rent_payment_records ADD COLUMN IF NOT EXISTS amount_due NUMERIC(12,2);

-- Імʼя CHECK-обмеження автозгенероване (021/023 оголошували його інлайном),
-- тож шукаємо за ВИЗНАЧЕННЯМ, а не за назвою: у базі, накоченій вручну, воно
-- могло назватись інакше (урок 055 — не покладатись на автоімена).
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'public.rent_payment_records'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ~* 'status'
  LOOP
    EXECUTE format('ALTER TABLE public.rent_payment_records DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

ALTER TABLE rent_payment_records ADD CONSTRAINT rent_payment_records_status_check
  CHECK (status IN ('pending', 'paid', 'overdue', 'partial'));

-- ── 2. Надходження ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rent_payment_parts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- CASCADE: «Скасувати платіж» у календарі видаляє ПЕРІОД, і надходження
  -- без періоду не мають сенсу — їх ніде показати.
  record_id   UUID NOT NULL REFERENCES rent_payment_records(id) ON DELETE CASCADE,
  amount      NUMERIC(12,2) NOT NULL CHECK (amount > 0 AND amount <= 10000000000),
  paid_at     TIMESTAMPTZ NOT NULL,
  notes       TEXT CHECK (notes IS NULL OR char_length(notes) <= 200),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rent_payment_parts_record ON rent_payment_parts(record_id, paid_at);

ALTER TABLE rent_payment_parts ENABLE ROW LEVEL SECURITY;

-- Ціль перевіряється на ОБОХ боках (правило 11): надходження можна вписати
-- лише в період обʼєкта, яким ти володієш або який редагуєш. Знати
-- `record_id` чужого платежу недостатньо — підзапит іде під RLS періодів і
-- ще й явно фільтрується по власних обʼєктах.
--
-- Гостя й рієлтора тут свідомо НЕМАЄ: жоден клієнтський екран не показує їм
-- надходжень, а найменші права — ті, яких не видали.
DROP POLICY IF EXISTS "parts_owner_all"  ON rent_payment_parts;
DROP POLICY IF EXISTS "parts_editor_all" ON rent_payment_parts;

CREATE POLICY "parts_owner_all" ON rent_payment_parts
  FOR ALL
  USING (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  ))
  WITH CHECK (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_owner_property_ids(current_app_user_id()))
  ));

CREATE POLICY "parts_editor_all" ON rent_payment_parts
  FOR ALL
  USING (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
  ))
  WITH CHECK (record_id IN (
    SELECT r.id FROM rent_payment_records r
    WHERE r.property_id IN (SELECT get_editor_property_ids(current_app_user_id()))
  ));

-- Анонімові таблиця не потрібна ні для чого; RLS його й так не пустить, але
-- дефолтні права Supabase видають запис УСІМ ролям — знімаємо явно, щоб
-- рішення було видно в дифі (той самий хід, що 068).
REVOKE ALL ON rent_payment_parts FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON rent_payment_parts TO authenticated;

-- ── 3. Підсумок періоду рахує сервер ───────────────────────────────────────
-- SECURITY INVOKER — і це свідомо, на відміну від тригера оренд (067). Сюди
-- потрапляє лише той, кого вже пропустила політика надходжень, а вона
-- вимагає права на обʼєкт; оновлення періоду під ТИМИ САМИМИ правами не
-- розширює нічого. Definer тут був би зайвим периметром.
--
-- Логіка ВБУДОВАНА в тригер, а не винесена в окрему функцію: вкладений виклик
-- перевіряє EXECUTE у ПОТОЧНОГО користувача, тобто окрему функцію довелось би
-- видати `authenticated` — ще одна точка входу, якої ніхто не просив.
CREATE OR REPLACE FUNCTION public.sync_rent_record_from_parts()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_ids  UUID[];
  v_rid  UUID;
  v_due  NUMERIC;
  v_n    INT;
  v_sum  NUMERIC;
  v_last TIMESTAMPTZ;
BEGIN
  -- Перенесене надходження міняє ДВА періоди: той, звідки, і той, куди.
  IF TG_OP = 'INSERT' THEN v_ids := ARRAY[NEW.record_id];
  ELSIF TG_OP = 'DELETE' THEN v_ids := ARRAY[OLD.record_id];
  ELSIF NEW.record_id IS DISTINCT FROM OLD.record_id THEN v_ids := ARRAY[OLD.record_id, NEW.record_id];
  ELSE v_ids := ARRAY[NEW.record_id];
  END IF;

  FOREACH v_rid IN ARRAY v_ids LOOP
    -- БЛОКУВАННЯ ПЕРІОДУ ПЕРЕД АГРЕГАТОМ. Два надходження з двох пристроїв
    -- (власник і редактор) інакше рахували б суму кожен у своєму знімку, і
    -- той, хто записав ОСТАННІМ, затер би чуже надходження з підсумку. Після
    -- блокування наступний SELECT у READ COMMITTED бере свіжий знімок і
    -- бачить уже закомічене.
    SELECT amount_due INTO v_due FROM rent_payment_records WHERE id = v_rid FOR UPDATE;
    -- Періоду немає — його саме видаляють (каскад «Скасувати платіж»), і
    -- оновлювати нічого.
    CONTINUE WHEN NOT FOUND;

    SELECT count(*), COALESCE(sum(amount), 0), max(paid_at)
      INTO v_n, v_sum, v_last
      FROM rent_payment_parts WHERE record_id = v_rid;

    IF v_n = 0 THEN
      UPDATE rent_payment_records
         SET amount = NULL, paid_at = NULL, status = 'pending', updated_at = now()
       WHERE id = v_rid;
    ELSE
      UPDATE rent_payment_records
         SET amount = v_sum, paid_at = v_last,
             status = CASE WHEN v_due IS NULL OR v_sum >= v_due THEN 'paid' ELSE 'partial' END,
             updated_at = now()
       WHERE id = v_rid;
    END IF;
  END LOOP;

  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.sync_rent_record_from_parts() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_sync_rent_record_from_parts ON rent_payment_parts;
CREATE TRIGGER trg_sync_rent_record_from_parts
  AFTER INSERT OR UPDATE OR DELETE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.sync_rent_record_from_parts();

-- ── 4. Одна дія клієнта — один виклик ──────────────────────────────────────
-- «Отримав гроші» = створити період, якщо його ще немає (із ЗАМОРОЖЕНОЮ
-- очікуваною сумою), і вписати надходження. Двома запитами з клієнта це не
-- атомарно: збій другого лишав би порожній період. Тут обидва кроки — одна
-- транзакція.
--
-- SECURITY INVOKER: усі права перевіряє RLS (періоду — політики 041/053,
-- надходження — політики вище). UUID обʼєкта тут НЕ є ключем доступу, тож
-- IDOR-клас (§5 Audit playbook) не виникає; anon не має EXECUTE узагалі.
--
-- Наявний період свою `amount_due` НЕ міняє: заморожена сума — це сенс
-- заморожування. Тому `p_amount_due` діє лише на НОВИЙ період.
CREATE OR REPLACE FUNCTION public.record_rent_payment(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount      NUMERIC,
  p_paid_at     TIMESTAMPTZ,
  p_notes       TEXT DEFAULT NULL,
  p_amount_due  NUMERIC DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_owner UUID;
  v_rid   UUID;
  v_part  UUID;
  v_rec   RECORD;
BEGIN
  IF p_amount IS NULL OR p_amount <= 0 OR p_amount > 10000000000 THEN
    RETURN jsonb_build_object('error', 'invalid_amount');
  END IF;
  -- День наперед — запас на пояс: локальна північ Києва — це ще вчора в UTC.
  IF p_paid_at IS NULL OR p_paid_at > now() + INTERVAL '1 day' THEN
    RETURN jsonb_build_object('error', 'invalid_date');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  INSERT INTO rent_payment_records (property_id, owner_id, due_date, amount_due, status)
  VALUES (p_property_id, v_owner, p_due_date,
          CASE WHEN p_amount_due > 0 THEN round(p_amount_due, 2) END, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Період, підтверджений СТАРИМ клієнтом уже після міграції (кешована
  -- вкладка в Telegram пише `status='paid'` + суму напряму, без надходжень).
  -- Без цього кроку перше ж нове надходження перерахувало б суму з нуля, і
  -- отримані раніше гроші зникли б із підсумку. Той самий перенос, що й
  -- бекфіл нижче, — лише для одного періоду й у тій самій транзакції.
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  SELECT r.id, round(r.amount::NUMERIC, 2),
         COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
         NULLIF(btrim(left(r.notes, 200)), '')
    FROM rent_payment_records r
   WHERE r.id = v_rid AND r.status IN ('paid', 'partial') AND r.amount > 0
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  VALUES (v_rid, round(p_amount, 2), p_paid_at, NULLIF(btrim(p_notes), ''))
  RETURNING id INTO v_part;

  SELECT r.status, r.amount, r.amount_due INTO v_rec
    FROM rent_payment_records r WHERE r.id = v_rid;

  RETURN jsonb_build_object(
    'record_id',  v_rid,
    'part_id',    v_part,
    'status',     v_rec.status,
    'amount',     v_rec.amount,
    'amount_due', v_rec.amount_due,
    'error',      NULL
  );
END;
$$;

-- Правило 12: дефолтний PUBLIC знімається ДО гранту, інакше функція
-- лишається викликабельною з anon-ключа.
REVOKE ALL ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC) TO authenticated;

-- ── 5. Наявні підтвердження стають надходженнями ───────────────────────────
-- Без цього кожен уже підтверджений платіж виглядав би «отриманим без
-- жодного надходження», а перше ж редагування (додати частину) перерахувало
-- б суму з нуля. Очікувана сума такого періоду = отримана: він уже був
-- закритий, і заднім числом робити його частковим не можна.
--
-- Ідемпотентно: лише періоди без жодного надходження.
UPDATE rent_payment_records r
   SET amount_due = round(r.amount::NUMERIC, 2)
 WHERE r.status = 'paid' AND r.amount > 0 AND r.amount_due IS NULL
   AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
SELECT r.id, round(r.amount::NUMERIC, 2),
       COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
       NULLIF(btrim(left(r.notes, 200)), '')
  FROM rent_payment_records r
 WHERE r.status = 'paid' AND r.amount > 0
   AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

NOTIFY pgrst, 'reload schema';

COMMIT;
