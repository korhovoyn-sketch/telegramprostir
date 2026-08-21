-- ============================================================================
-- 055 — КРИТИЧНО: підписка на спільну базу падала НА КОЖНОМУ УСПІШНОМУ виклику
-- ============================================================================
-- Знайдено ВИКОНАННЯМ (`scripts/verify-rls.sql`), і знайдено лише тому, що до
-- негативної перевірки («протермінований токен не пускає») додалась ПОЗИТИВНА
-- («живий — пускає»). Негативна проходила й на зламаному коді: гілка
-- `not_found` виходить із функції РАНІШЕ, ніж доходить до дефектного рядка.
--
-- ── ДЕФЕКТ ─────────────────────────────────────────────────────────────────
-- `subscribe_to_shared_db` оголошена як
--     RETURNS TABLE (db_id UUID, db_name TEXT, error TEXT)
-- тобто plpgsql заводить ЗМІННУ `db_id`. А в тілі стоїть
--     INSERT INTO realtor_subscriptions (realtor_id, db_id)
--     VALUES (v_uid, v_db.id)
--     ON CONFLICT (realtor_id, db_id) DO NOTHING;
-- Список колонок INSERT-а підстановці НЕ підлягає, а от ЦІЛЬ `ON CONFLICT`
-- парситься як вираз — і `db_id` там збігається і з колонкою, і зі змінною:
--     ERROR: column reference "db_id" is ambiguous
--
-- Тобто **кожна успішна підписка рієлтора на спільну базу кидала виняток**, а
-- клієнт показував «Помилка запиту». Це дослівно збігається зі скаргою
-- власника, записаною в Pending manual actions §0 («розділ поділитися базою не
-- працює, підключення бази падає з Помилка запиту») — там причину списали на
-- невідсутні 036/037. Міграції могли бути застосовані: причина в них самих,
-- і обидві (036 і 037) несуть той самий рядок.
--
-- ── ЧОМУ ЦЬОГО НЕ БАЧИВ НІХТО ──────────────────────────────────────────────
--  • e2e мокають RPC через `page.route` — тіла функції там не існує;
--  • `verify_release.sql` перевіряв лише ІСНУВАННЯ функції;
--  • джерельні гарди звіряють підрядки, а тут синтаксис валідний — помилка
--    виникає при ВИКОНАННІ, і лише на успішній гілці.
--
-- ── ФІКС ───────────────────────────────────────────────────────────────────
-- Ціль конфлікту вказується ІМЕНЕМ ОБМЕЖЕННЯ, а не переліком колонок — тоді
-- підставляти нічого й неоднозначності не виникає в принципі. Перейменування
-- OUT-параметра було б ламкою зміною: клієнт читає саме `db_id`.
-- ============================================================================

CREATE OR REPLACE FUNCTION subscribe_to_shared_db(p_token TEXT)
RETURNS TABLE (db_id UUID, db_name TEXT, error TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_uid UUID;
  v_db  RECORD;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_authenticated'::TEXT; RETURN;
  END IF;

  SELECT d.id, d.owner_id, d.name INTO v_db FROM databases d
  WHERE d.share_token = p_token
    AND (d.share_expires_at IS NULL OR d.share_expires_at > now())
  LIMIT 1;

  IF v_db.id IS NULL THEN
    RETURN QUERY SELECT NULL::UUID, NULL::TEXT, 'not_found'::TEXT; RETURN;
  END IF;
  IF v_db.owner_id = v_uid THEN
    RETURN QUERY SELECT v_db.id, v_db.name::TEXT, 'own_db'::TEXT; RETURN;
  END IF;

  -- Ціль конфлікту — ІМʼЯ обмеження: перелік колонок тут неоднозначний через
  -- OUT-параметр `db_id` (див. шапку файлу).
  INSERT INTO realtor_subscriptions (realtor_id, db_id)
  VALUES (v_uid, v_db.id)
  ON CONFLICT ON CONSTRAINT realtor_subscriptions_realtor_id_db_id_key DO NOTHING;

  -- Той, кому передали базу, діє як рієлтор. Користувач із дефолтною роллю
  -- 'owner', який жодної власної бази не створював, — саме такий випадок;
  -- нормалізуємо, щоб домашній екран збігався з роллю. Усталений власник
  -- (має >= 1 базу) лишається 'owner'. Тригер prevent_privilege_escalation
  -- дозволяє owner->realtor (блокує лише зворотне самопідвищення).
  UPDATE users SET role = 'realtor'
  WHERE id = v_uid
    AND role = 'owner'
    AND NOT EXISTS (SELECT 1 FROM databases d2 WHERE d2.owner_id = v_uid);

  RETURN QUERY SELECT v_db.id, v_db.name::TEXT, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION subscribe_to_shared_db(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION subscribe_to_shared_db(TEXT) TO authenticated, service_role;

NOTIFY pgrst, 'reload schema';
