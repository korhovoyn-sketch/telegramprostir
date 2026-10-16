-- ============================================================================
-- 072 — УМОВИ ОРЕНДИ В ЧАСІ: борг рахується за ставкою, що ДІЯЛА тоді
-- ============================================================================
-- ЩО ЛІКУЄ. Очікувана сума неоплаченого періоду рахувалась із ПОТОЧНОЇ
-- ставки обʼєкта. Підняв оренду з $1 800 до $2 000 у жовтні — і серпневий
-- борг, якого ще не сплатили, теж ставав $2 000. Тобто зміна ставки
-- переписувала минулі борги заднім числом, і саме в ту суму, про яку
-- сперечаються з орендарем. 071 заморожує суму лише в мить ПЕРШОГО
-- надходження — до нього період був беззахисним.
--
-- ДВІ РЕЧІ, і друга — не «заодно»:
--
--   1. ІСТОРІЯ УМОВ. Тригер записує СТАРІ умови (ставка, тип, площі, база
--      розрахунку) в мить, коли вони змінились, з міткою `valid_until`.
--      Умови на дату D = найраніший рядок, що діяв після D; якщо такого
--      немає — поточні умови обʼєкта. Формула грошей при цьому лишається В
--      ОДНОМУ МІСЦІ (клієнтська `expectedRent`): сервер зберігає ФАКТИ, а не
--      рахує суми, тож дрейфу між двома реалізаціями формули бути не може.
--
--   2. СУМА ЗА КОНКРЕТНИЙ ПЕРІОД (`set_rent_amount_due`). Історія НЕ
--      розрізняє «підняв ставку» і «виправив описку»: обидва — зміна. Без
--      виходу виправлена описка ($18 000 → $1 800) лишила б серпень із
--      очікуваними $18 000, тобто вічним «частковим» боргом — і навіть
--      «Скасувати платіж» не допоміг би, бо повторний запис знову взяв би
--      ставку з історії. Той самий вихід потрібен і без описок: неповний
--      перший місяць (заїхав 18-го), знижка, домовленість — сума періоду
--      відрізняється від ставки законно.
--
-- ЧЕСНА МЕЖА. Історія починається з цієї міграції: як змінювалась ставка
-- ДОТИ, ніде не записано, тож для старих періодів діє поточна ставка — як і
-- було. Вигадувати минуле з архіву оренд не можна: він фіксує ставку на
-- кінець ОРЕНДИ, а не на кожну дату.
-- ============================================================================

BEGIN;

-- ── 1. Історія ─────────────────────────────────────────────────────────────
-- CASCADE: історія умов має сенс лише разом із платежами обʼєкта, а ті
-- видаляються з ним (021). Архів правовідносин живе окремо (067) і власну
-- ставку на момент закриття оренди зберігає сам.
CREATE TABLE IF NOT EXISTS property_rent_terms (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id    UUID NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  rent_rate      DOUBLE PRECISION,
  rent_type      TEXT,
  utilities_rate DOUBLE PRECISION,
  area_basis     TEXT,
  area_useful    DOUBLE PRECISION,
  area_total     DOUBLE PRECISION,
  -- Мить, до якої ці умови ДІЯЛИ (тобто мить зміни).
  valid_until    TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE property_rent_terms ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_property_rent_terms_prop
  ON property_rent_terms (property_id, valid_until);

-- ── RLS: бачать ті, хто бачить платежі; писати не може НІХТО з клієнтів ───
-- Урок 068: історія цінна тим, що правдива. Запис, який власник чи редактор
-- може «підправити», доказом при суперечці не є, а редактор — принципал,
-- якого запрошують і відкликають. Рядки пише лише тригер (SECURITY DEFINER).
DROP POLICY IF EXISTS "rent_terms_owner_select"  ON property_rent_terms;
CREATE POLICY "rent_terms_owner_select" ON property_rent_terms
  FOR SELECT
  USING (property_id IN (SELECT get_owner_property_ids(current_app_user_id())));

DROP POLICY IF EXISTS "rent_terms_editor_select" ON property_rent_terms;
CREATE POLICY "rent_terms_editor_select" ON property_rent_terms
  FOR SELECT
  USING (property_id IN (SELECT get_editor_property_ids(current_app_user_id())));

-- Другий шар (068): без явного GRANT майбутня «політика за зразком» не
-- відкриє запис мовчки.
REVOKE ALL ON property_rent_terms FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON property_rent_terms FROM authenticated;
GRANT SELECT ON property_rent_terms TO authenticated;

-- ── Тригер ───────────────────────────────────────────────────────────────
-- SECURITY DEFINER — той самий випадок, що 067: службовий облік, усі
-- значення з OLD, вводу ззовні немає. Редактор міняє ставку під своїми
-- правами на `properties`, а запис в історію не впирається в його політику
-- (якої для запису й немає).
CREATE OR REPLACE FUNCTION public.record_rent_terms_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO property_rent_terms (
    property_id, rent_rate, rent_type, utilities_rate,
    area_basis, area_useful, area_total, valid_until
  ) VALUES (
    OLD.id, OLD.rent_rate, OLD.rent_type, OLD.utilities_rate,
    OLD.area_basis, OLD.area_useful, OLD.area_total, now()
  );
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.record_rent_terms_change() FROM PUBLIC;

-- `WHEN`, а не лише `UPDATE OF`: форма шле ВСІ поля при кожному збереженні,
-- тож `UPDATE OF` спрацьовує і тоді, коли ставку ніхто не чіпав. Без умови
-- кожне перейменування обʼєкта плодило б рядок «змін», яких не було.
DROP TRIGGER IF EXISTS trg_record_rent_terms ON properties;
CREATE TRIGGER trg_record_rent_terms
  AFTER UPDATE OF rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total
  ON properties
  FOR EACH ROW
  WHEN (
       OLD.rent_rate      IS DISTINCT FROM NEW.rent_rate
    OR OLD.rent_type      IS DISTINCT FROM NEW.rent_type
    OR OLD.utilities_rate IS DISTINCT FROM NEW.utilities_rate
    OR OLD.area_basis     IS DISTINCT FROM NEW.area_basis
    OR OLD.area_useful    IS DISTINCT FROM NEW.area_useful
    OR OLD.area_total     IS DISTINCT FROM NEW.area_total
  )
  EXECUTE FUNCTION public.record_rent_terms_change();

-- ── 2. Сума за конкретний період ───────────────────────────────────────────
-- SECURITY INVOKER, як і `record_rent_payment` (071): права перевіряє RLS
-- періодів і надходжень, тож чужий обʼєкт тут просто невидимий. UUID обʼєкта
-- не є ключем доступу — IDOR-клас (§5) не виникає; anon EXECUTE не має.
--
-- Підсумок рахується тут же, а не тригером: тригер 071 висить на
-- НАДХОДЖЕННЯХ, а тут міняється сам період. Логіка та сама — сума
-- надходжень проти очікуваної — під блокуванням рядка періоду.
CREATE OR REPLACE FUNCTION public.set_rent_amount_due(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount_due  NUMERIC
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_owner  UUID;
  v_rid    UUID;
  v_due    NUMERIC := round(p_amount_due, 2);
  v_n      INT;
  v_sum    NUMERIC;
  v_status TEXT;
BEGIN
  IF p_amount_due IS NULL OR p_amount_due <= 0 OR p_amount_due > 10000000000 THEN
    RETURN jsonb_build_object('error', 'invalid_amount');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Сума ставиться ОКРЕМИМ UPDATE нижче, а не тут, навіть для нового
  -- періоду: так зміна суми — завжди зміна рядка, і журнал змін (073) бачить
  -- її однаково, був період до того чи ні.
  INSERT INTO rent_payment_records (property_id, owner_id, due_date, status)
  VALUES (p_property_id, v_owner, p_due_date, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date
   FOR UPDATE;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  -- Період, підтверджений СТАРИМ клієнтом (сума без надходжень), — той самий
  -- перенос, що в `record_rent_payment`: інакше перерахунок нижче не побачив
  -- би отриманих грошей і назвав би оплачений період неоплаченим.
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  SELECT r.id, round(r.amount::NUMERIC, 2),
         COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
         NULLIF(btrim(left(r.notes, 200)), '')
    FROM rent_payment_records r
   WHERE r.id = v_rid AND r.status IN ('paid', 'partial') AND r.amount > 0
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

  SELECT count(*), COALESCE(sum(amount), 0) INTO v_n, v_sum
    FROM rent_payment_parts WHERE record_id = v_rid;

  v_status := CASE WHEN v_n = 0 THEN 'pending'
                   WHEN v_sum >= v_due THEN 'paid'
                   ELSE 'partial' END;

  UPDATE rent_payment_records
     SET amount_due = v_due, status = v_status, updated_at = now()
   WHERE id = v_rid;

  RETURN jsonb_build_object(
    'record_id',  v_rid,
    'status',     v_status,
    'amount_due', v_due,
    'error',      NULL
  );
END;
$$;

REVOKE ALL ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) TO authenticated;

NOTIFY pgrst, 'reload schema';

COMMIT;
