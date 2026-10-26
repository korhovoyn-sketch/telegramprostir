-- ============================================================================
-- 073 — ХТО ЩО ЗРОБИВ: автор надходження і журнал змін бази
-- ============================================================================
-- ЩО ЛІКУЄ. Команда (041) дала редакторам право писати в базу власника:
-- обʼєкти, ставки, орендарів, гроші. Але жоден рядок не відповідав на
-- питання «хто це зробив». Власник бачив, що ставку змінили, обʼєкт
-- видалили, а надходження $1 000 «записане» — і не мав як дізнатись, ким.
-- Для обліку грошей у команді це перше питання будь-якої розбіжності.
--
-- ДВІ ЧАСТИНИ:
--
--   1. АВТОР НАДХОДЖЕННЯ — колонки на самому `rent_payment_parts`. Ставить
--      ТРИГЕР, а не клієнт: значення з тіла запиту — це те, що клієнт
--      захотів написати, і редактор міг би «записати» гроші від імені
--      власника. Тригер перезаписує будь-що з тіла, а на UPDATE тримає
--      старе — автор не міняється від виправлення суми.
--
--   2. ЖУРНАЛ ЗМІН БАЗИ — `db_activity`. Пишуть ЛИШЕ тригери (SECURITY
--      DEFINER), клієнтам — лише читання (урок 068: журнал, який можна
--      підправити, доказом не є). Подія ПІДСУМКОВА, а не сирий діф: «Здано
--      в оренду: ТОВ Х» замість семи змінених колонок, і ім'я дійової особи
--      заморожене в рядку — переживає вихід людини з команди.
--
-- ЩО СВІДОМО НЕ ПИШЕТЬСЯ:
--   * дії без особи (крон, міграції, service-role) — це не «хтось зробив»;
--   * каскади: видалили обʼєкт — це ОДНА подія, а не ще десять «видалено
--     надходження / документ / розклад» під ним;
--   * шум без змісту: порядок, папки, опис, додавання фото (пакет із 20
--     знімків дав би 20 рядків). Видалення фото — пишеться: воно незворотне.
--
-- ЖУРНАЛ НЕ СМІЄ ЛАМАТИ ДІЮ. Будь-яка помилка запису події ковтається з
-- WARNING: втрачений рядок журналу — прикро, а «не вдалося зберегти
-- платіж» через журнал — неприпустимо. Це журнал змін, а не механізм
-- безпеки; права, як і доти, тримає RLS.
-- ============================================================================

BEGIN;

-- ── 1. Автор надходження ───────────────────────────────────────────────────
ALTER TABLE rent_payment_parts
  ADD COLUMN IF NOT EXISTS created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS created_by_name TEXT;

CREATE OR REPLACE FUNCTION public.stamp_rent_part_author()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    NEW.created_by      := OLD.created_by;
    NEW.created_by_name := OLD.created_by_name;
    RETURN NEW;
  END IF;

  -- Перенесене підтвердження СТАРОГО клієнта (071: сума на періоді без
  -- надходжень стає першим надходженням). Гроші вписав хтось раніше, і
  -- приписати їх тому, чия дія спричинила перенос, було б неправдою.
  -- Звичайний перший платіж періоду так не виглядає: період без надходжень
  -- має порожню суму (її обнуляє тригер 071).
  IF EXISTS (SELECT 1 FROM rent_payment_records r
              WHERE r.id = NEW.record_id AND r.amount > 0
                AND r.status IN ('paid', 'partial'))
     AND NOT EXISTS (SELECT 1 FROM rent_payment_parts pp WHERE pp.record_id = NEW.record_id) THEN
    NEW.created_by      := NULL;
    NEW.created_by_name := NULL;
    RETURN NEW;
  END IF;

  NEW.created_by      := NULL;
  NEW.created_by_name := NULL;
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO NEW.created_by, NEW.created_by_name
    FROM users u WHERE u.id = current_app_user_id();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.stamp_rent_part_author() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_stamp_rent_part_author ON rent_payment_parts;
CREATE TRIGGER trg_stamp_rent_part_author
  BEFORE INSERT OR UPDATE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.stamp_rent_part_author();

-- ── 2. Журнал ──────────────────────────────────────────────────────────────
-- `db_id` CASCADE: журнал живе в базі. `property_id` SET NULL: подія про
-- видалений обʼєкт лишається — назва заморожена в рядку.
CREATE TABLE IF NOT EXISTS db_activity (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  db_id         UUID NOT NULL REFERENCES databases(id)  ON DELETE CASCADE,
  property_id   UUID          REFERENCES properties(id) ON DELETE SET NULL,
  property_name TEXT,
  actor_id      UUID          REFERENCES users(id)      ON DELETE SET NULL,
  actor_name    TEXT,
  kind          TEXT NOT NULL CHECK (kind IN (
    'property_created', 'property_deleted', 'property_renamed', 'property_moved',
    'property_rented', 'property_vacated', 'property_status', 'tenant_changed',
    'terms_changed',
    'payment_received', 'payment_edited', 'payment_deleted', 'payment_cancelled',
    'due_changed', 'schedule_set', 'schedule_deleted',
    'file_added', 'file_deleted', 'photo_deleted'
  )),
  details       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE db_activity ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_db_activity_db ON db_activity (db_id, created_at DESC, id DESC);

-- Бачать ті, хто веде базу: власник і редактор. Редактор бачить і чужі
-- дії, і власні — журнал, у якому видно лише себе, нічого не пояснює.
-- Рієлтор і гість — ні: це внутрішня кухня власника.
DROP POLICY IF EXISTS "activity_owner_select"  ON db_activity;
CREATE POLICY "activity_owner_select" ON db_activity
  FOR SELECT
  USING (db_id IN (SELECT get_owner_db_ids(current_app_user_id())));

DROP POLICY IF EXISTS "activity_editor_select" ON db_activity;
CREATE POLICY "activity_editor_select" ON db_activity
  FOR SELECT
  USING (db_id IN (SELECT get_editor_db_ids(current_app_user_id())));

REVOKE ALL ON db_activity FROM anon;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON db_activity FROM authenticated;
GRANT SELECT ON db_activity TO authenticated;

-- Один запис події. Не видається НІКОМУ: його кличуть лише тригери нижче,
-- які є SECURITY DEFINER і виконуються від власника функцій.
CREATE OR REPLACE FUNCTION public.log_db_activity(
  p_db_id         UUID,
  p_property_id   UUID,
  p_property_name TEXT,
  p_kind          TEXT,
  p_details       JSONB
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_uid  UUID;
  v_name TEXT;
BEGIN
  SELECT u.id, NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
    INTO v_uid, v_name
    FROM users u WHERE u.id = current_app_user_id();
  -- Без особи — не «хтось зробив», а система: крон, міграція, service-role.
  IF v_uid IS NULL OR p_db_id IS NULL THEN RETURN; END IF;
  -- Базу саме видаляють (каскад) — писати нікуди, і вставка впала б на FK.
  IF NOT EXISTS (SELECT 1 FROM databases d WHERE d.id = p_db_id) THEN RETURN; END IF;

  INSERT INTO db_activity (db_id, property_id, property_name, actor_id, actor_name, kind, details)
  VALUES (
    p_db_id,
    CASE WHEN p_property_id IS NOT NULL
          AND EXISTS (SELECT 1 FROM properties p WHERE p.id = p_property_id)
         THEN p_property_id END,
    p_property_name, v_uid, v_name, p_kind, COALESCE(p_details, '{}'::jsonb)
  );
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'db_activity: подію % не записано (%)', p_kind, SQLERRM;
END;
$$;

REVOKE ALL ON FUNCTION public.log_db_activity(UUID, UUID, TEXT, TEXT, JSONB) FROM PUBLIC;

-- ── Обʼєкти ────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_property()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_terms_old JSONB;
  v_terms_new JSONB;
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_created',
      jsonb_build_object('status', NEW.status));
    RETURN NULL;
  END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM log_db_activity(OLD.db_id, NULL, OLD.name, 'property_deleted',
      jsonb_build_object('tenant', OLD.tenant_name));
    RETURN NULL;
  END IF;

  -- Переміщення — подія в ОБОХ базах: у старій обʼєкт зник, у новій зʼявився.
  IF NEW.db_id IS DISTINCT FROM OLD.db_id THEN
    PERFORM log_db_activity(OLD.db_id, NEW.id, NEW.name, 'property_moved',
      jsonb_build_object('direction', 'out', 'db', (SELECT d.name FROM databases d WHERE d.id = NEW.db_id)));
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_moved',
      jsonb_build_object('direction', 'in', 'db', (SELECT d.name FROM databases d WHERE d.id = OLD.db_id)));
  END IF;

  IF NEW.name IS DISTINCT FROM OLD.name THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_renamed',
      jsonb_build_object('from', OLD.name, 'to', NEW.name));
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'occupied' THEN
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_rented',
        jsonb_build_object('tenant', NEW.tenant_name, 'lease_start', NEW.lease_start_date, 'lease_end', NEW.lease_end_date));
    ELSIF OLD.status = 'occupied' THEN
      -- Орендар — з OLD: та сама операція обнуляє його в NEW (той самий
      -- урок, що в тригері оренд 067).
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_vacated',
        jsonb_build_object('tenant', OLD.tenant_name, 'to', NEW.status));
    ELSE
      PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'property_status',
        jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
  ELSIF NEW.status = 'occupied' AND NEW.tenant_name IS DISTINCT FROM OLD.tenant_name THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'tenant_changed',
      jsonb_build_object('from', OLD.tenant_name, 'to', NEW.tenant_name));
  END IF;

  v_terms_old := jsonb_build_object('rent_rate', OLD.rent_rate, 'rent_type', OLD.rent_type,
    'utilities_rate', OLD.utilities_rate, 'area_basis', OLD.area_basis,
    'area_useful', OLD.area_useful, 'area_total', OLD.area_total);
  v_terms_new := jsonb_build_object('rent_rate', NEW.rent_rate, 'rent_type', NEW.rent_type,
    'utilities_rate', NEW.utilities_rate, 'area_basis', NEW.area_basis,
    'area_useful', NEW.area_useful, 'area_total', NEW.area_total);
  IF v_terms_old IS DISTINCT FROM v_terms_new THEN
    PERFORM log_db_activity(NEW.db_id, NEW.id, NEW.name, 'terms_changed',
      jsonb_build_object('from', v_terms_old, 'to', v_terms_new));
  END IF;

  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_property() FROM PUBLIC;

-- Список колонок обовʼязковий: перестановка порядку (`sort_order`) і папки
-- міняють десятки рядків за раз, і тригер на кожен з них був би марною
-- роботою — подій там немає.
DROP TRIGGER IF EXISTS trg_activity_property ON properties;
CREATE TRIGGER trg_activity_property
  AFTER INSERT OR DELETE OR UPDATE OF
    db_id, name, status, tenant_name,
    rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total
  ON properties
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property();

-- ── Надходження ────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_part()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_rec RECORD;
BEGIN
  SELECT r.due_date, p.id AS property_id, p.db_id, p.name INTO v_rec
    FROM rent_payment_records r JOIN properties p ON p.id = r.property_id
   WHERE r.id = COALESCE(NEW.record_id, OLD.record_id);
  -- Періоду чи обʼєкта вже немає — це каскад, і його подію вже записано
  -- вище («Скасовано платіж», «Видалено обʼєкт»).
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'INSERT' THEN
    -- Без автора — перенесене підтвердження старого клієнта (див. штамп):
    -- це не нова дія, а запис про гроші, які прийшли раніше.
    IF NEW.created_by IS NULL THEN RETURN NULL; END IF;
    PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_received',
      jsonb_build_object('due_date', v_rec.due_date, 'amount', NEW.amount, 'paid_at', NEW.paid_at));
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.amount IS DISTINCT FROM OLD.amount OR NEW.paid_at IS DISTINCT FROM OLD.paid_at THEN
      PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_edited',
        jsonb_build_object('due_date', v_rec.due_date, 'from', OLD.amount, 'to', NEW.amount,
                           'from_paid_at', OLD.paid_at, 'to_paid_at', NEW.paid_at));
    END IF;
  ELSE
    PERFORM log_db_activity(v_rec.db_id, v_rec.property_id, v_rec.name, 'payment_deleted',
      jsonb_build_object('due_date', v_rec.due_date, 'amount', OLD.amount));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_part() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_part ON rent_payment_parts;
CREATE TRIGGER trg_activity_rent_part
  AFTER INSERT OR UPDATE OR DELETE ON rent_payment_parts
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_part();

-- ── Періоди: скасування платежу і сума за період ──────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_record()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.amount_due IS DISTINCT FROM OLD.amount_due THEN
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'due_changed',
        jsonb_build_object('due_date', NEW.due_date, 'from', OLD.amount_due, 'to', NEW.amount_due));
    END IF;
  ELSIF OLD.status IN ('paid', 'partial') AND OLD.amount > 0 THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'payment_cancelled',
      jsonb_build_object('due_date', OLD.due_date, 'amount', OLD.amount));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_record() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_record ON rent_payment_records;
CREATE TRIGGER trg_activity_rent_record
  AFTER DELETE OR UPDATE OF amount_due ON rent_payment_records
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_record();

-- ── Розклад платежів ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_rent_schedule()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'schedule_deleted', '{}'::jsonb);
  ELSIF TG_OP = 'INSERT'
     OR NEW.due_day IS DISTINCT FROM OLD.due_day
     OR NEW.is_active IS DISTINCT FROM OLD.is_active THEN
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'schedule_set',
      jsonb_build_object('due_day', NEW.due_day, 'active', NEW.is_active,
                         'from', CASE WHEN TG_OP = 'UPDATE' THEN OLD.due_day END));
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_rent_schedule() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_rent_schedule ON rent_payments;
CREATE TRIGGER trg_activity_rent_schedule
  AFTER INSERT OR UPDATE OF due_day, is_active OR DELETE ON rent_payments
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_rent_schedule();

-- ── Документи і фото ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.activity_on_property_media()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_prop RECORD;
BEGIN
  SELECT p.id, p.db_id, p.name INTO v_prop
    FROM properties p WHERE p.id = COALESCE(NEW.property_id, OLD.property_id);
  IF NOT FOUND THEN RETURN NULL; END IF;

  IF TG_TABLE_NAME = 'property_files' THEN
    IF TG_OP = 'INSERT' THEN
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'file_added',
        jsonb_build_object('name', NEW.file_name));
    ELSE
      PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'file_deleted',
        jsonb_build_object('name', OLD.file_name));
    END IF;
  ELSE
    PERFORM log_db_activity(v_prop.db_id, v_prop.id, v_prop.name, 'photo_deleted', '{}'::jsonb);
  END IF;
  RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.activity_on_property_media() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_activity_property_files ON property_files;
CREATE TRIGGER trg_activity_property_files
  AFTER INSERT OR DELETE ON property_files
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property_media();

DROP TRIGGER IF EXISTS trg_activity_property_photos ON property_photos;
CREATE TRIGGER trg_activity_property_photos
  AFTER DELETE ON property_photos
  FOR EACH ROW EXECUTE FUNCTION public.activity_on_property_media();

NOTIFY pgrst, 'reload schema';

COMMIT;
