-- ============================================================================
-- 078: ТЕ, ЩО КЛІЄНТ НЕ СМІЄ ПИСАТИ САМ — особа, членство, слід, суми
-- ============================================================================
-- Наскрізний прогін УСІХ дій з базою на живому Postgres (листопад 2026):
-- кожен клієнтський RPC краєвими входами, кожна таблиця — записом від імені
-- ролі, якій політика ЦЕ дозволяє. Усе нижче — те, що RLS пропускає, бо
-- відповідає на питання «чий це рядок?», а не «що в ньому написано?».
-- Прод на момент роботи ЧИСТИЙ: жодного рядка, що порушив би нові правила
-- (перевірено читанням), тож обмеження ставляться валідованими.
--
-- 1. `users.tg_id` МІНЯВСЯ КЛІЄНТОМ. Політика `users_own` пускає UPDATE будь-
--    якої колонки власного рядка, а `prevent_privilege_escalation` стереже лише
--    `role` і `plan`. Edge-функція входу шукає користувача ПО `tg_id` і
--    оновлює знайдений рядок, тобто хто виставив своєму рядку чужий
--    (ще не зареєстрований) `tg_id`, той «займає» особу наперед: майбутня
--    жертва під час першого входу успадковує рядок зловмисника разом з усім,
--    що він у нього посадив (бази з відомими йому токенами, `db_members` зі
--    своїм другим акаунтом як редактором). Власний акаунт зловмисника при
--    цьому відвалюється, тож це не «захват чужого», а «отруєння чужого
--    майбутнього» — але від першого входу людини до першого запису в такій
--    базі нічого не видно. `tg_id` — якір особи (076): його пише лише
--    службовий ключ.
--
-- 2. ЧЛЕНСТВО І ГОСТЬОВИЙ ДОСТУП МОЖНА БУЛО ПОСАДИТИ БЕЗ ЗГОДИ. Політики
--    `members_owner_all`/`glinks_owner_all` перевіряють, що БАЗА моя, але не
--    що пишеться в колонки, які ставить ЛИШЕ клейм: власник вставляв
--    `status='active'` з чужим `user_id` і довільним `member_name` — людина
--    опинялась редактором чужої бази, не знаючи про це, а в журналі стояло
--    придумане власником імʼя. Клейм (SECURITY DEFINER) лишається єдиним
--    шляхом ставити `user_id`/`guest_user_id`/імʼя/`claimed_at`.
--
-- 3. СЛІД ПЕРЕГЛЯДУ ПИСАВ КЛІЄНТ ЦІЛКОМ. Політика вставки перевіряє, що ЦІЛЬ
--    доступна, і що `viewer_id` — це я або NULL. Але `viewer_name` — довільний
--    рядок (рієлтор підписувався «Президент»; 100 000 символів лягали в таблицю
--    як є), а `viewer_id = NULL` разом із службовим підписом «Веб-перегляд»
--    дозволяв накручувати ЛІЧИЛЬНИК анонімних відкриттів, за яким власник
--    вирішує ціну й канали. Тепер для клієнтських ролей особу й імʼя ставить
--    сервер; анонімні рядки пише лише `record_public_view`.
--
-- 4. ПЛАТЕЖІ. (а) `record_rent_payment` приймав `NaN` як очікувану суму —
--    період лишався «частково» назавжди з сумою, яку не показує жоден екран
--    (редактор команди міг так зіпсувати період власника); (б) дата періоду
--    без меж: 2999-01-01 і 1900-01-01 створювали фантомні записи в архіві;
--    (в) примітка понад 200 символів падала голим check_violation посеред
--    функції; (г) два надходження ОДНОГО періоду одночасно давали
--    `deadlock detected` (заміряно: 16 із 20 паралельних) — вставка надходження
--    бере FOR KEY SHARE на період, а тригер підсумку просить FOR UPDATE, тобто
--    обидві сесії тримають слабше й чекають сильнішого. Період блокується ДО
--    вставки, як це вже робить `set_rent_amount_due`.
--
-- 5. ЗНАЧЕННЯ БЕЗ МЕЖ. Ставки й площі — double precision без жодного CHECK:
--    `NaN`, `Infinity`, мінус 50 і 99 999 999 999 м² лягали як є й їхали на
--    публічну /v, рієлторам, у експорт; порожня назва обʼєкта/бази/підбірки і
--    кінець договору раніше за початок — теж. UI це не пропускає, тож
--    стосується лише змінених клієнтів — а саме вони й є моделлю зловмисника.
--
-- 6. ГІСТЬ БАЧИВ ДОКУМЕНТИ, ЯКІ НЕ МІГ ВІДКРИТИ. `pfiles_select_guest` (027)
--    віддавала гостю РЯДКИ файлів (назви на кшталт «Договір_ТОВ_X.pdf»), а
--    політики сховища гостьової гілки не мають: список малювався, а кожен тап
--    давав «Не вдалося відкрити файл». Тобто вміст недоступний, а назви витікали.
--    Яка з двох половин задумана, з коду не видно; безпечний напрямок — не
--    віддавати назв. Якщо власник вирішить, що гість читає документи, треба
--    додавати гілку в політики сховища (через `*_from_auth_uid`), а не
--    повертати цю.
-- ============================================================================
BEGIN;

-- ── 1. tg_id — лише службовий ключ ─────────────────────────────────────────
-- INVOKER, а не DEFINER: потрібна РОЛЬ ВИКЛИКАЧА. Усередині DEFINER-функції
-- `current_user` — це її власник, і перевірка не відрізнила б клієнта від
-- служби. Шляхи, що легально міняють `tg_id` (edge-функція під service_role,
-- SQL Editor під postgres, `delete_my_account` як DEFINER), цього тригера
-- не зачіпають.
CREATE OR REPLACE FUNCTION public.guard_user_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.tg_id IS DISTINCT FROM OLD.tg_id AND current_user IN ('authenticated', 'anon') THEN
    RAISE EXCEPTION 'not authorized: tg_id is set by the server only'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_user_identity ON public.users;
CREATE TRIGGER trg_guard_user_identity
  BEFORE UPDATE OF tg_id ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.guard_user_identity();

-- ── 2. Членство й гостьовий доступ — поля клейму пише лише клейм ───────────
CREATE OR REPLACE FUNCTION public.guard_member_claim_fields()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF current_user NOT IN ('authenticated', 'anon') THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.status IS DISTINCT FROM 'pending' OR NEW.user_id IS NOT NULL
       OR NEW.member_name IS NOT NULL OR NEW.claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'not authorized: a membership is created pending and claimed by the invitee'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    -- Власник може лише ВІДКЛИКАТИ (і міняти підпис). Усе, що робить людину
    -- членом, — клейм.
    IF NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.member_name IS DISTINCT FROM OLD.member_name
       OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
       OR NEW.invite_token IS DISTINCT FROM OLD.invite_token
       OR NEW.db_id IS DISTINCT FROM OLD.db_id
       OR (NEW.status IS DISTINCT FROM OLD.status AND NEW.status <> 'revoked') THEN
      RAISE EXCEPTION 'not authorized: only revoking is allowed on a membership'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_member_claim_fields ON public.db_members;
CREATE TRIGGER trg_guard_member_claim_fields
  BEFORE INSERT OR UPDATE ON public.db_members
  FOR EACH ROW EXECUTE FUNCTION public.guard_member_claim_fields();

CREATE OR REPLACE FUNCTION public.guard_guest_claim_fields()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF current_user NOT IN ('authenticated', 'anon') THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.status IS DISTINCT FROM 'pending' OR NEW.guest_user_id IS NOT NULL
       OR NEW.guest_name IS NOT NULL OR NEW.claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'not authorized: a guest link is created pending and claimed by the guest'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    IF NEW.guest_user_id IS DISTINCT FROM OLD.guest_user_id
       OR NEW.guest_name IS DISTINCT FROM OLD.guest_name
       OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
       OR NEW.invite_token IS DISTINCT FROM OLD.invite_token
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR NEW.db_id IS DISTINCT FROM OLD.db_id
       OR NEW.property_id IS DISTINCT FROM OLD.property_id
       OR (NEW.status IS DISTINCT FROM OLD.status AND NEW.status <> 'revoked') THEN
      RAISE EXCEPTION 'not authorized: only revoking is allowed on a guest link'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_guest_claim_fields ON public.guest_links;
CREATE TRIGGER trg_guard_guest_claim_fields
  BEFORE INSERT OR UPDATE ON public.guest_links
  FOR EACH ROW EXECUTE FUNCTION public.guard_guest_claim_fields();

-- ── 3. Слід перегляду: особу й імʼя ставить сервер ─────────────────────────
-- `record_public_view` — SECURITY DEFINER, тож для нього `current_user` —
-- власник функції, і цей тригер його не чіпає: анонімні рядки лишаються його
-- монополією.
CREATE OR REPLACE FUNCTION public.stamp_property_view()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  v_uid  UUID;
  v_name TEXT;
BEGIN
  IF current_user NOT IN ('authenticated', 'anon') THEN
    RETURN NEW;
  END IF;

  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authorized: a view trace needs a signed-in user'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- Чужий `viewer_id` політика відхиляла й раніше; тригер іде ПЕРЕД перевіркою
  -- політики, тож без цього рядка підміну тихо «виправило» б перезаписом і
  -- спробу не було б видно як спробу.
  IF NEW.viewer_id IS NOT NULL AND NEW.viewer_id <> v_uid THEN
    RAISE EXCEPTION 'not authorized: a view trace is written as the viewer'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  SELECT NULLIF(btrim(concat_ws(' ', u.first_name, u.last_name)), '')
    INTO v_name FROM users u WHERE u.id = v_uid;

  NEW.viewer_id   := v_uid;
  NEW.viewer_name := left(COALESCE(v_name, ''), 200);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_stamp_property_view ON public.property_views;
CREATE TRIGGER trg_stamp_property_view
  BEFORE INSERT ON public.property_views
  FOR EACH ROW EXECUTE FUNCTION public.stamp_property_view();

-- ── 4. Платежі ─────────────────────────────────────────────────────────────
-- Тіло — з ЗІБРАНОЇ БД (071), з чотирма змінами, позначеними `078`.
CREATE OR REPLACE FUNCTION public.record_rent_payment(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount      NUMERIC,
  p_paid_at     TIMESTAMPTZ,
  p_notes       TEXT    DEFAULT NULL,
  p_amount_due  NUMERIC DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SET search_path TO 'public', 'pg_temp'
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
  -- 078: `NaN` > 0 істинне, тож без цього він ставав «очікуваною сумою».
  IF p_amount_due IS NOT NULL
     AND (p_amount_due = 'NaN'::NUMERIC OR p_amount_due > 10000000000 OR p_amount_due < 0) THEN
    RETURN jsonb_build_object('error', 'invalid_amount');
  END IF;
  -- День наперед — запас на пояс: локальна північ Києва — це ще вчора в UTC.
  IF p_paid_at IS NULL OR p_paid_at > now() + INTERVAL '1 day' THEN
    RETURN jsonb_build_object('error', 'invalid_date');
  END IF;
  -- 078: календар веде періоди від розкладу вперед на кілька місяців, і ніхто
  -- не підтверджує платіж за 1900-й чи 2999-й рік.
  IF p_due_date IS NULL OR p_due_date < DATE '2000-01-01'
     OR p_due_date > (CURRENT_DATE + INTERVAL '2 years')::DATE THEN
    RETURN jsonb_build_object('error', 'invalid_period');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  INSERT INTO rent_payment_records (property_id, owner_id, due_date, amount_due, status)
  VALUES (p_property_id, v_owner, p_due_date,
          CASE WHEN p_amount_due > 0 THEN round(p_amount_due, 2) END, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  -- 078: період блокується ДО вставки надходження. Вставка бере FOR KEY SHARE
  -- (зовнішній ключ), а тригер підсумку просить FOR UPDATE — дві сесії, що
  -- тримають слабше й чекають сильнішого, дають deadlock.
  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date
   FOR UPDATE;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  SELECT r.id, round(r.amount::NUMERIC, 2),
         COALESCE(r.paid_at, r.updated_at, r.created_at, now()),
         NULLIF(btrim(left(r.notes, 200)), '')
    FROM rent_payment_records r
   WHERE r.id = v_rid AND r.status IN ('paid', 'partial') AND r.amount > 0
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = r.id);

  -- 078: ліміт довжини — як у переносу вище, а не голий check_violation.
  INSERT INTO rent_payment_parts (record_id, amount, paid_at, notes)
  VALUES (v_rid, round(p_amount, 2), p_paid_at, NULLIF(btrim(left(p_notes, 200)), ''))
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

REVOKE ALL ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC)
  FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_rent_payment(UUID, DATE, NUMERIC, TIMESTAMPTZ, TEXT, NUMERIC)
  TO authenticated;

-- `set_rent_amount_due` — ті самі межі дати: без них фантомний період
-- створювався цією дорогою (Infinity/NaN вона вже відсікала).
CREATE OR REPLACE FUNCTION public.set_rent_amount_due(
  p_property_id UUID,
  p_due_date    DATE,
  p_amount_due  NUMERIC
) RETURNS JSONB
LANGUAGE plpgsql
SET search_path TO 'public', 'pg_temp'
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
  IF p_due_date IS NULL OR p_due_date < DATE '2000-01-01'
     OR p_due_date > (CURRENT_DATE + INTERVAL '2 years')::DATE THEN
    RETURN jsonb_build_object('error', 'invalid_period');
  END IF;

  SELECT p.owner_id INTO v_owner FROM properties p WHERE p.id = p_property_id;
  IF v_owner IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  INSERT INTO rent_payment_records (property_id, owner_id, due_date, status)
  VALUES (p_property_id, v_owner, p_due_date, 'pending')
  ON CONFLICT (property_id, due_date) DO NOTHING;

  SELECT r.id INTO v_rid FROM rent_payment_records r
   WHERE r.property_id = p_property_id AND r.due_date = p_due_date
   FOR UPDATE;
  IF v_rid IS NULL THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

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

REVOKE ALL ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_rent_amount_due(UUID, DATE, NUMERIC) TO authenticated;

-- Уже збережену `NaN`-суму очікування (якщо така є) знімаємо: період
-- повертається до «без очікуваної суми», а підсумок перерахує тригер.
UPDATE rent_payment_records SET amount_due = NULL
 WHERE amount_due IS NOT NULL AND (amount_due = 'NaN'::NUMERIC OR amount_due <= 0);

-- ── 5. Межі значень ────────────────────────────────────────────────────────
-- `BETWEEN` на double precision відкидає NaN (він «більший за все»), а
-- Infinity — верхньою межею. NULL проходить: поле необовʼязкове.
-- `NOT VALID`: нові записи перевіряються одразу, а наявні рядки міграція НЕ
-- чіпає й не валіться на них. Прод на момент роботи не мав жодного, що
-- порушує (перевірено читанням), тож `VALIDATE CONSTRAINT` можна виконати
-- пізніше окремо — але лише ЯК ВОНО Є: наявний порушник не зможе й оновитись
-- (Postgres перевіряє такі обмеження на кожному оновленому рядку).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'properties_numbers_sane') THEN
    ALTER TABLE properties ADD CONSTRAINT properties_numbers_sane CHECK (
      (rent_rate       IS NULL OR rent_rate       BETWEEN 0 AND 1e12) AND
      (utilities_rate  IS NULL OR utilities_rate  BETWEEN 0 AND 1e9)  AND
      (area_useful     IS NULL OR area_useful     BETWEEN 0 AND 1e9)  AND
      (area_total      IS NULL OR area_total      BETWEEN 0 AND 1e9)  AND
      (sale_price      IS NULL OR sale_price      BETWEEN 0 AND 1e12)
    ) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'properties_lease_order') THEN
    ALTER TABLE properties ADD CONSTRAINT properties_lease_order CHECK (
      lease_start_date IS NULL OR lease_end_date IS NULL OR lease_end_date >= lease_start_date
    ) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'properties_name_not_blank') THEN
    ALTER TABLE properties ADD CONSTRAINT properties_name_not_blank CHECK (btrim(name) <> '') NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'databases_name_not_blank') THEN
    ALTER TABLE databases ADD CONSTRAINT databases_name_not_blank CHECK (btrim(name) <> '') NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'collections_name_not_blank') THEN
    ALTER TABLE collections ADD CONSTRAINT collections_name_not_blank CHECK (btrim(name) <> '') NOT VALID;
  END IF;
END $$;

-- Тригерні функції не викликає ніхто, крім самого Postgres, — і Postgres не
-- питає EXECUTE при спрацюванні (075).
REVOKE ALL ON FUNCTION public.guard_user_identity()      FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.guard_member_claim_fields() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.guard_guest_claim_fields()  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.stamp_property_view()       FROM PUBLIC, anon, authenticated;

-- ── 6. Гість не бачить назв документів, яких не може відкрити ──────────────
DROP POLICY IF EXISTS "pfiles_select_guest" ON property_files;

NOTIFY pgrst, 'reload schema';

COMMIT;
