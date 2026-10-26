-- ═══════════════════════════════════════════════════════════════════════════
-- 069 — цілісність доступів: хто що отримує і що справді забирається
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Два дефекти, обидва знайдені ВИКОНАННЯМ на живому Postgres (не читанням),
-- обидва — сервер робить не те, що обіцяє інтерфейс.
--
-- ── 1. Гостьове запрошення ЗНИЖУВАЛО власника до гостя — назавжди ──────────
-- `claim_guest_link` робив `UPDATE users SET role = 'guest' … AND role = 'owner'`
-- для БУДЬ-якого власника. Захист стояв лише від клейму ВЛАСНОГО запрошення,
-- тож власник, що має бази і прийняв чуже запрошення (він же орендар деінде —
-- цілком звичайна ситуація), ставав `guest`. Таббар будує вкладки за роллю, а
-- в гостя їх три: «Обʼєкти», «Сповіщення», «Профіль». Тобто ВЛАСНІ бази
-- зникали з інтерфейсу — дані цілі (RLS не залежить від ролі), але дійти до
-- них нема як. Повернути роль не можна навіть самому:
-- `prevent_privilege_escalation` блокує guest→owner за будь-якого контексту
-- (заміряно: `role_escalation_blocked: guest→owner not allowed`).
--
-- Сусідній `subscribe_to_shared_db` (037/055) цю умову вже має:
-- `AND NOT EXISTS (SELECT 1 FROM databases d2 WHERE d2.owner_id = v_uid)`.
-- Правило знали — його просто не застосували в другій функції тієї ж родини.
--
-- Тіло нижче — точна копія 048, змінено РІВНО один предикат (урок 050:
-- контракт відповіді не чіпаємо, бо його читає перший екран запрошеного).
--
-- ── 2. «Відкликати доступ» не забирав доступу в тих, хто ВЖЕ підписався ────
-- Шит поширення обіцяє: «Усі, з ким ви ділились, втратять доступ». А
-- `manage_share(revoke|rotate)` міняв лише токен і термін. Доступ рієлтора ж
-- тримається не на токені, а на рядку `realtor_subscriptions`
-- (`get_realtor_db_ids` читає саме його), і цей рядок лишався. Заміряно:
-- рієлтор, що підписався до відкликання, після нього бачив і базу, і обʼєкти.
--
-- Гард `share-handoff` цього не бачив за побудовою: він перевіряв, що СТАРИЙ
-- токен не дає НОВОЇ підписки, а не те, що наявна підписка зникає.
--
-- Тепер rotate/revoke бази видаляють її підписки в тій самій транзакції.
-- СВІДОМО НЕ чіпає: `set_expiry` (термін — про ЛІНК, тобто про нові
-- приєднання; хто вже працює з базою, лишається) і команду (`db_members` —
-- окремий механізм із власним відкликанням). Обидва рішення закріплені
-- стендом, щоб зміна була видимою, а не випадковою.
--
-- ── Ремонт ─────────────────────────────────────────────────────────────────
-- Ті, кого вже знизило, лишились би гостями назавжди: виправлення функції
-- нікого не повертає. Ознака однозначна — роль `guest` при ≥1 ВЛАСНІЙ базі:
-- гостьовий інтерфейс створити базу не дає, тож іншого шляху в такий стан
-- немає. Тригер ескалації блокує й це оновлення, тож його вимикаємо на час
-- одного UPDATE — УМОВНО: якщо тригера в базі немає, ALTER інакше повалив би
-- весь RELEASE.sql (урок 024: прод має прогалини всередині 001-047).
--
-- Підписки на бази, відкликані ДО цієї міграції, НЕ чистяться: відкликання й
-- закінчення терміну в базі нерозрізненні (обидва — минулий
-- `share_expires_at`), а друге забирати доступ не повинно. Таких власників
-- варто попросити натиснути «Оновити посилання» ще раз.
--
-- Ідемпотентна.

BEGIN;

CREATE OR REPLACE FUNCTION claim_guest_link(p_token TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid  UUID := current_app_user_id();
  v_link RECORD;
  v_name TEXT;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT id, property_id, db_id, guest_user_id, status, owner_id
  INTO v_link
  FROM guest_links
  WHERE invite_token = p_token
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_link.status = 'revoked' THEN
    RETURN jsonb_build_object('error', 'revoked');
  END IF;

  -- Owner must never claim their own invite: it would demote them to guest role,
  -- locking them out of all their databases with no client-side recovery path.
  IF v_uid = v_link.owner_id THEN
    RETURN jsonb_build_object('error', 'cannot_claim_own_link');
  END IF;

  -- Already claimed by this user → idempotent success
  IF v_link.status = 'active' AND v_link.guest_user_id = v_uid THEN
    RETURN jsonb_build_object(
      'property_id', v_link.property_id,
      'db_id',       v_link.db_id
    );
  END IF;

  -- Already claimed by someone else
  IF v_link.status = 'active' AND v_link.guest_user_id IS DISTINCT FROM v_uid THEN
    RETURN jsonb_build_object('error', 'already_claimed');
  END IF;

  SELECT NULLIF(trim(concat(u.first_name, ' ', coalesce(u.last_name, ''))), '')
  INTO v_name
  FROM users u WHERE u.id = v_uid;

  UPDATE guest_links
  SET guest_user_id = v_uid,
      status        = 'active',
      claimed_at    = now(),
      guest_name    = v_name
  WHERE id = v_link.id;

  -- Гостем стає лише ДЕФОЛТНИЙ власник — той, хто жодної бази не створював
  -- (онбординг лишає `owner` за замовчуванням). Власника з базами не чіпаємо:
  -- гостьовий таббар не має «Баз», а назад роль не повертає ніщо (069).
  UPDATE users SET role = 'guest'
  WHERE id = v_uid
    AND role = 'owner'
    AND NOT EXISTS (SELECT 1 FROM databases d WHERE d.owner_id = v_uid);

  RETURN jsonb_build_object(
    'property_id', v_link.property_id,
    'db_id',       v_link.db_id
  );
END;
$$;
REVOKE ALL ON FUNCTION claim_guest_link(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_guest_link(TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION manage_share(
  p_kind   TEXT,
  p_id     UUID,
  p_action TEXT,
  p_days   INT DEFAULT NULL
)
RETURNS TABLE (share_token TEXT, share_expires_at TIMESTAMPTZ, error TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid   UUID;
  v_owner UUID;
  v_tok   TEXT;
  v_exp   TIMESTAMPTZ;
BEGIN
  v_uid := current_app_user_id();
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'not_authenticated'::TEXT; RETURN;
  END IF;
  IF p_kind NOT IN ('db','prop','col') OR p_action NOT IN ('rotate','set_expiry','clear_expiry','revoke') THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;
  IF p_action = 'set_expiry' AND (p_days IS NULL OR p_days < 1 OR p_days > 365) THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'bad_request'::TEXT; RETURN;
  END IF;

  IF p_kind = 'db' THEN
    SELECT owner_id INTO v_owner FROM databases WHERE id = p_id FOR UPDATE;
  ELSIF p_kind = 'prop' THEN
    SELECT owner_id INTO v_owner FROM properties WHERE id = p_id FOR UPDATE;
  ELSE
    SELECT realtor_id INTO v_owner FROM collections WHERE id = p_id FOR UPDATE;
  END IF;

  IF v_owner IS NULL OR v_owner <> v_uid THEN
    RETURN QUERY SELECT NULL::TEXT, NULL::TIMESTAMPTZ, 'forbidden'::TEXT; RETURN;
  END IF;

  -- 060: `revoke` тепер у списку дій, що ротують токен, поруч із `rotate`.
  IF p_kind = 'db' THEN
    UPDATE databases SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE databases.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE databases.share_expires_at
                         END
    WHERE id = p_id
    RETURNING databases.share_token, databases.share_expires_at INTO v_tok, v_exp;

    -- 069: доступ рієлтора тримається на підписці, а не на токені, тож без
    -- цього рядка «Усі, з ким ви ділились, втратять доступ» було неправдою.
    -- `set_expiry` підписок свідомо не чіпає — див. шапку.
    IF p_action IN ('rotate','revoke') THEN
      DELETE FROM realtor_subscriptions rs WHERE rs.db_id = p_id;
    END IF;
  ELSIF p_kind = 'prop' THEN
    UPDATE properties SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE properties.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE properties.share_expires_at
                         END
    WHERE id = p_id
    RETURNING properties.share_token, properties.share_expires_at INTO v_tok, v_exp;
  ELSE
    UPDATE collections SET
      share_token      = CASE WHEN p_action IN ('rotate','revoke')
                              THEN encode(gen_random_bytes(12),'hex')
                              ELSE collections.share_token END,
      share_expires_at = CASE p_action
                           WHEN 'set_expiry'   THEN now() + make_interval(days => p_days)
                           WHEN 'clear_expiry' THEN NULL
                           WHEN 'revoke'       THEN now()
                           ELSE collections.share_expires_at
                         END
    WHERE id = p_id
    RETURNING collections.share_token, collections.share_expires_at INTO v_tok, v_exp;
  END IF;

  RETURN QUERY SELECT v_tok, v_exp, NULL::TEXT;
END;
$$;

REVOKE ALL ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION manage_share(TEXT, UUID, TEXT, INT) TO authenticated, service_role;

-- ── Ремонт: повернути роль тим, кого вже знизило ───────────────────────────
-- Ознака — `guest` при ≥1 власній базі (див. шапку). Тригер ескалації вимкнено
-- рівно на один UPDATE і лише якщо він є: інакше ALTER повалив би файл.
DO $$
DECLARE
  has_trg BOOLEAN;
  n INT;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = 'public.users'::regclass
      AND tgname  = 'trg_prevent_privilege_escalation'
      AND NOT tgisinternal
  ) INTO has_trg;

  IF has_trg THEN
    EXECUTE 'ALTER TABLE public.users DISABLE TRIGGER trg_prevent_privilege_escalation';
  END IF;

  UPDATE public.users u SET role = 'owner'
  WHERE u.role = 'guest'
    AND EXISTS (SELECT 1 FROM public.databases d WHERE d.owner_id = u.id);
  GET DIAGNOSTICS n = ROW_COUNT;

  IF has_trg THEN
    EXECUTE 'ALTER TABLE public.users ENABLE TRIGGER trg_prevent_privilege_escalation';
  END IF;

  IF n > 0 THEN
    RAISE NOTICE '069: повернуто роль власника % користувачам, яких знизило гостьове запрошення', n;
  END IF;
END $$;

NOTIFY pgrst, 'reload schema';

COMMIT;
