-- ============================================================================
-- 067_tenancies.sql — АРХІВ ПРАВОВІДНОСИН З ОРЕНДАРЯМИ.
-- Ідемпотентна. Виконувати в Supabase Dashboard → SQL Editor.
--
-- ЩО ЛІКУЄ. Звільнення обʼєкта ОБНУЛЯЄ `tenant_name`, `lease_start_date`,
-- `lease_end_date` просто в рядку `properties` — тобто правовідносини
-- ЗНИКАЮТЬ БЕЗСЛІДНО. Єдиний шлях назад сьогодні — кнопка «Скасувати» в
-- тості, і вона живе в памʼяті сторінки: перезавантажив — втрачено назавжди.
--
-- ОРЕНДА СТАЄ СУТНІСТЮ: рядок ВІДКРИВАЄТЬСЯ, коли обʼєкт стає зайнятим, і
-- ЗАКРИВАЄТЬСЯ, коли перестає. `properties.tenant_name` лишається як був —
-- тепер це КЕШ активної оренди, тож жоден наявний екран, експорт і публічна
-- `/v` не потребують правок.
--
-- ЧОМУ ТРИГЕР, А НЕ КОД ЕКРАНА. Орендаря обнуляють ТРИ різні шляхи:
--   1. «Звільнити обʼєкт»            — PropertyDetailScreen
--   2. пакетне «Вільно»              — useProperties.batchUpdateStatus
--   3. збереження форми зі статусом ≠ «Зайнято» — PropertyFormScreen
-- Тригер — єдине місце, де вони сходяться, і він накриває ще й ті шляхи,
-- яких сьогодні немає (прямий UPDATE, майбутній імпорт). Запис в обробнику
-- кнопки покрив би один шлях із трьох — рівно той клас дефекту, який у цьому
-- проєкті вже повторювався (див. правило 8 у Security rules).
--
-- ФАКТИЧНИЙ ПЕРІОД ≠ ДОГОВІРНИЙ, і це не педантизм: дати договору
-- НЕОБОВʼЯЗКОВІ (`RentPropertyScreen` пише `leaseStart || undefined`), тож
-- оренда цілком може не мати жодної дати. Тому `started_at`/`ended_at` —
-- моменти САМИХ ДІЙ, а `lease_*` зберігаються поруч як окремі факти.
-- Наслідок, заради якого це й зроблено: «платежі цієї оренди» = записи,
-- чий `due_date` потрапляє в `[started_at, ended_at)`. Це правило ТОЧНЕ, а
-- не наближене — обʼєкт має рівно один статус, тож дві оренди не можуть
-- перекриватись у часі, — і воно працює для ВЖЕ НАЯВНИХ платежів, чого
-- колонка `tenancy_id` на `rent_payment_records` не вміла б.
-- ============================================================================

-- ── Таблиця ──────────────────────────────────────────────────────────────────
-- `db_id` CASCADE, а `property_id` SET NULL — і ця пара не випадкова:
-- архів ЖИВЕ В БАЗІ (рішення власника), тож без бази він недосяжний за
-- побудовою; а от видалення ОДНОГО обʼєкта не сміє стирати фінансову
-- історію — назва обʼєкта заморожена в самому рядку.
CREATE TABLE IF NOT EXISTS tenancies (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      UUID NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  db_id         UUID NOT NULL REFERENCES databases(id)  ON DELETE CASCADE,
  property_id   UUID          REFERENCES properties(id) ON DELETE SET NULL,

  -- ЗАМОРОЖЕНІ факти: архівна картка мусить читатись і тоді, коли обʼєкт
  -- перейменували, змінили ставку або видалили зовсім.
  property_name TEXT NOT NULL,
  tenant_name   TEXT,
  landlord_name TEXT,
  rent_rate     DOUBLE PRECISION,
  rent_type     TEXT,
  utilities_rate DOUBLE PRECISION,
  area_basis    TEXT,
  area_useful   DOUBLE PRECISION,
  area_total    DOUBLE PRECISION,
  currency      TEXT,

  -- Договірні дати — окремо від фактичних, обидві можуть бути NULL.
  lease_start_date DATE,
  lease_end_date   DATE,

  -- ФАКТИЧНИЙ період: моменти дій.
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenancies ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_tenancies_db    ON tenancies (db_id, ended_at DESC NULLS FIRST, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenancies_prop  ON tenancies (property_id, started_at DESC);

-- Рівно ОДНА відкрита оренда на обʼєкт. Часткового унікального індексу тут
-- досить: закритих може бути скільки завгодно.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenancies_one_open
  ON tenancies (property_id) WHERE ended_at IS NULL AND property_id IS NOT NULL;

-- ── RLS: власник бази + редактор команди ────────────────────────────────────
-- Дзеркалить `property_folders` (043). `WITH CHECK` форсить, що `owner_id` —
-- це власник БАЗИ, а не той, хто пише: редактор не привласнить історію собі.
-- Рієлтор і гість не мають політики ВЗАГАЛІ — комерційна історія власника не
-- є частиною лістингу.
DROP POLICY IF EXISTS "tenancies_owner_all" ON tenancies;
CREATE POLICY "tenancies_owner_all" ON tenancies
  FOR ALL
  USING      (db_id IN (SELECT get_owner_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_owner_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

DROP POLICY IF EXISTS "tenancies_editor_all" ON tenancies;
CREATE POLICY "tenancies_editor_all" ON tenancies
  FOR ALL
  USING      (db_id IN (SELECT get_editor_db_ids(current_app_user_id())))
  WITH CHECK (
    db_id IN (SELECT get_editor_db_ids(current_app_user_id()))
    AND owner_id = (SELECT d.owner_id FROM databases d WHERE d.id = db_id)
  );

-- ── Тригер ───────────────────────────────────────────────────────────────────
-- SECURITY DEFINER: це СЛУЖБОВИЙ облік, а не дія користувача. Усі значення
-- виводяться з рядка `properties`, жодного вводу ззовні немає, тож
-- розширення прав тут нічого не відкриває — зате редактор команди може
-- звільнити обʼєкт, не впираючись у власну політику запису.
CREATE OR REPLACE FUNCTION public.sync_tenancy_on_property_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  -- ВІКНО СКАСУВАННЯ. «Скасувати» в тості повертає обʼєкт у «Зайнято», тобто
  -- з погляду тригера це НОВА здача — і наївна гілка відкриття створила б
  -- ДРУГУ оренду замість повернення першої. Тому щойно закрита оренда з ТИМ
  -- САМИМ орендарем повертається, а не дублюється. Тост живе ~6 секунд;
  -- двох хвилин вистачає з запасом на повільну мережу, а збіг орендаря
  -- робить хибне спрацювання практично неможливим.
  undo_window CONSTANT INTERVAL := INTERVAL '2 minutes';
  reopened    UUID;
  was_occupied BOOLEAN := (TG_OP = 'UPDATE' AND OLD.status = 'occupied');
  is_occupied  BOOLEAN := (NEW.status = 'occupied');
BEGIN
  -- ── ЗАКРИТТЯ ──────────────────────────────────────────────────────────────
  -- Факти беруться з OLD: та сама операція, що міняє статус, ОДНОЧАСНО
  -- обнуляє орендаря й дати, тож у NEW їх уже немає.
  IF was_occupied AND NOT is_occupied THEN
    UPDATE tenancies SET
      ended_at         = now(),
      tenant_name      = OLD.tenant_name,
      lease_start_date = OLD.lease_start_date,
      lease_end_date   = OLD.lease_end_date,
      rent_rate        = OLD.rent_rate,
      rent_type        = OLD.rent_type,
      utilities_rate   = OLD.utilities_rate,
      area_basis       = OLD.area_basis,
      area_useful      = OLD.area_useful,
      area_total       = OLD.area_total,
      landlord_name    = OLD.landlord_name,
      property_name    = OLD.name,
      updated_at       = now()
    WHERE property_id = NEW.id AND ended_at IS NULL;
    RETURN NEW;
  END IF;

  -- ── ВІДКРИТТЯ ─────────────────────────────────────────────────────────────
  IF is_occupied AND (TG_OP = 'INSERT' OR NOT was_occupied) THEN
    UPDATE tenancies SET ended_at = NULL, updated_at = now()
    WHERE id = (
      SELECT t.id FROM tenancies t
      WHERE t.property_id = NEW.id
        AND t.ended_at IS NOT NULL
        AND t.ended_at > now() - undo_window
        AND t.tenant_name IS NOT DISTINCT FROM NEW.tenant_name
      ORDER BY t.ended_at DESC
      LIMIT 1
    )
    RETURNING id INTO reopened;

    IF reopened IS NULL THEN
      INSERT INTO tenancies (
        owner_id, db_id, property_id, property_name, tenant_name, landlord_name,
        rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total,
        currency, lease_start_date, lease_end_date, started_at
      )
      SELECT
        NEW.owner_id, NEW.db_id, NEW.id, NEW.name, NEW.tenant_name, NEW.landlord_name,
        NEW.rent_rate, NEW.rent_type, NEW.utilities_rate, NEW.area_basis,
        NEW.area_useful, NEW.area_total,
        (SELECT u.currency FROM users u WHERE u.id = NEW.owner_id),
        NEW.lease_start_date, NEW.lease_end_date,
        COALESCE(NEW.lease_start_date::timestamptz, now());
    END IF;
    RETURN NEW;
  END IF;

  -- ── ЗМІНА ВСЕРЕДИНІ ОРЕНДИ ────────────────────────────────────────────────
  -- Перейменування орендаря при живій оренді НЕ ділить її надвоє, і це
  -- рішення, а не спрощення: у застосунку немає дії «замінити орендаря» —
  -- справжня зміна йде через звільнення й нову здачу. Розділяти тут означало
  -- б, що виправлення одруківки в імені ФАБРИКУЄ неіснуючі правовідносини.
  -- Відкритий рядок просто тримається в актуальному стані, тож на момент
  -- закриття він несе фінальні значення.
  IF was_occupied AND is_occupied THEN
    UPDATE tenancies SET
      tenant_name      = NEW.tenant_name,
      lease_start_date = NEW.lease_start_date,
      lease_end_date   = NEW.lease_end_date,
      rent_rate        = NEW.rent_rate,
      rent_type        = NEW.rent_type,
      utilities_rate   = NEW.utilities_rate,
      area_basis       = NEW.area_basis,
      area_useful      = NEW.area_useful,
      area_total       = NEW.area_total,
      landlord_name    = NEW.landlord_name,
      property_name    = NEW.name,
      updated_at       = now()
    WHERE property_id = NEW.id AND ended_at IS NULL;
  END IF;

  RETURN NEW;
END;
$$;

-- Правило 12 Security rules: дефолтний грант PUBLIC знімається ЯВНО. Тригерну
-- функцію не викликають напряму, але гард ACL сканує ВСІ SECURITY DEFINER.
REVOKE ALL ON FUNCTION public.sync_tenancy_on_property_change() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_sync_tenancy ON properties;
CREATE TRIGGER trg_sync_tenancy
  AFTER INSERT OR UPDATE OF status, tenant_name, lease_start_date, lease_end_date,
                            rent_rate, rent_type, utilities_rate, area_basis,
                            area_useful, area_total, landlord_name, name
  ON properties
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_tenancy_on_property_change();

-- ── Бекфіл ───────────────────────────────────────────────────────────────────
-- Без нього історія почалась би з нуля, а вже зайняті обʼєкти не мали б
-- ЖОДНОГО запису — тобто фіча виглядала б зламаною саме там, де в неї
-- найбільше даних (той самий урок, що з іменами гостей у 048).
INSERT INTO tenancies (
  owner_id, db_id, property_id, property_name, tenant_name, landlord_name,
  rent_rate, rent_type, utilities_rate, area_basis, area_useful, area_total,
  currency, lease_start_date, lease_end_date, started_at
)
SELECT
  p.owner_id, p.db_id, p.id, p.name, p.tenant_name, p.landlord_name,
  p.rent_rate, p.rent_type, p.utilities_rate, p.area_basis,
  p.area_useful, p.area_total,
  (SELECT u.currency FROM users u WHERE u.id = p.owner_id),
  p.lease_start_date, p.lease_end_date,
  COALESCE(p.lease_start_date::timestamptz, p.created_at, now())
FROM properties p
WHERE p.status = 'occupied'
  AND NOT EXISTS (
    SELECT 1 FROM tenancies t WHERE t.property_id = p.id AND t.ended_at IS NULL
  );
