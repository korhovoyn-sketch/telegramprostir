#!/usr/bin/env bash
# Збирає ОДИН файл із міграцій, які ще не накочені в проді (048+).
#
# ЧОМУ ГЕНЕРАТОР, А НЕ РУЧНИЙ ФАЙЛ. Склеєна копія, яку правлять окремо від
# джерела, розходиться з ним за один раунд — і тоді оператор накочує НЕ ТЕ, що
# в репозиторії. Тут файл є ПОХІДНИМ: єдине джерело правди лишається в
# `supabase/migrations/`, а CI перевіряє, що зібране збігається (див.
# `verify-migrations.sh`).
set -euo pipefail

FROM=${FROM:-48}
OUT=${OUT:-supabase/RELEASE.sql}

files=$(ls supabase/migrations/*.sql | while read -r f; do
  b=$(basename "$f")
  # ЛИШЕ трицифровий префікс: 0050_/0060_ — це стара нумерація (легасі),
  # вона давно застосована і сюди потрапити не повинна.
  [[ "$b" =~ ^([0-9]{3})_ ]] || continue
  n=$((10#${BASH_REMATCH[1]}))
  [ "$n" -ge "$FROM" ] && echo "$f"
done | sort)

{
  echo "-- ============================================================================"
  echo "-- PropSpace — ОДИН файл для накату в Supabase Dashboard → SQL Editor"
  echo "--"
  echo "-- ЗГЕНЕРОВАНО: scripts/build-release-sql.sh. РУКАМИ НЕ ПРАВИТИ."
  echo "-- Джерело правди — supabase/migrations/; CI звіряє, що цей файл їм"
  echo "-- відповідає (робота \`migrations\`, крок «RELEASE.sql не розійшовся»)."
  echo "--"
  echo "-- Містить міграції $(echo "$files" | wc -l | tr -d ' ') шт., від $FROM і далі:"
  echo "$files" | sed 's#.*/#--   * #'
  echo "--"
  echo "-- ЯК НАКОЧУВАТИ: вставити цілком і виконати ОДИН раз."
  echo "--   * усе загорнуте в BEGIN/COMMIT — при будь-якій помилці НІЧОГО не"
  echo "--     застосується, тобто напівстану не буде;"
  echo "--   * файл ІДЕМПОТЕНТНИЙ (перевірено повторним накатом у CI), тож"
  echo "--     повторний запуск безпечний;"
  echo "--   * після нього запусти supabase/verify_release.sql — усі рядки"
  echo "--     мають бути ✅ OK."
  echo "-- ============================================================================"
  echo
  echo "BEGIN;"
  echo
  cat <<'PREFLIGHT'
-- ─────────────────────────────────────────────────────────────────────────
-- ПЕРЕДПОЛЬОТНА ПЕРЕВІРКА
-- ─────────────────────────────────────────────────────────────────────────
-- Накат у проді робився ВРУЧНУ і з прогалинами: реальний випадок — файл упав
-- на `mark_overdue_payments() does not exist`, бо міграція 024 туди так і не
-- потрапила. Помилка від Postgres називає лише сам обʼєкт, не кажучи ані що
-- саме бракує в цілому, ані яку міграцію запустити.
--
-- Тому спершу перевіряємо ВСЕ, на що спирається цей файл, і при потребі
-- падаємо ОДИН раз зі списком. Транзакція все одно відкотиться, тож стан бази
-- не змінюється — просто ви одразу бачите повну картину.
DO $$
DECLARE missing TEXT := '';
BEGIN
  -- Таблиці, на яких створюються політики або додаються колонки.
  IF to_regclass('public.users')                 IS NULL THEN missing := missing || E'\n  * таблиця users (001_schema)'; END IF;
  IF to_regclass('public.properties')            IS NULL THEN missing := missing || E'\n  * таблиця properties (001_schema)'; END IF;
  IF to_regclass('public.guest_links')           IS NULL THEN missing := missing || E'\n  * таблиця guest_links (027_guest_role)'; END IF;
  IF to_regclass('public.collection_properties') IS NULL THEN missing := missing || E'\n  * таблиця collection_properties (001_schema)'; END IF;
  IF to_regclass('public.rent_payments')         IS NULL THEN missing := missing || E'\n  * таблиця rent_payments (021_rent_payments)'; END IF;
  IF to_regclass('public.rent_payment_records')  IS NULL THEN missing := missing || E'\n  * таблиця rent_payment_records (021_rent_payments)'; END IF;
  IF to_regclass('public.db_members')            IS NULL THEN missing := missing || E'\n  * таблиця db_members (041_team_members)'; END IF;
  IF to_regclass('public.property_files')        IS NULL THEN missing := missing || E'\n  * таблиця property_files (033_property_files)'; END IF;
  IF to_regclass('public.collections')           IS NULL THEN missing := missing || E'\n  * таблиця collections (001_schema)'; END IF;
  IF to_regclass('public.databases')             IS NULL THEN missing := missing || E'\n  * таблиця databases (001_schema)'; END IF;
  IF to_regclass('public.property_views')        IS NULL THEN missing := missing || E'\n  * таблиця property_views (001_schema)'; END IF;
  IF to_regclass('public.realtor_subscriptions') IS NULL THEN missing := missing || E'\n  * таблиця realtor_subscriptions (001_schema)'; END IF;

  -- Колонки з ПІЗНІХ міграцій, які читають тіла функцій цього файлу. Саме цей
  -- клас і дав збій на `mark_overdue_payments`: прогалина всередині 001-047
  -- проявляється не на початку накату, а посеред нього — і повідомлення
  -- Postgres назве колонку, не сказавши, якої міграції бракує.
  IF to_regclass('public.properties') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='area_basis')
      THEN missing := missing || E'\n  * колонка properties.area_basis (042_area_basis)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='parking_type')
      THEN missing := missing || E'\n  * колонка properties.parking_type (039_parking_fields)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='properties' AND column_name='ev_charger')
      THEN missing := missing || E'\n  * колонка properties.ev_charger (039_parking_fields)'; END IF;
  END IF;
  IF to_regclass('public.property_views') IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='property_views' AND column_name='db_id')
      THEN missing := missing || E'\n  * колонка property_views.db_id (040_public_preview_fixes)'; END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema='public' AND table_name='property_views' AND column_name='collection_id')
      THEN missing := missing || E'\n  * колонка property_views.collection_id (040_public_preview_fixes)'; END IF;
  END IF;

  -- Хелпери, які викликаються з тіл функцій і предикатів політик.
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                 WHERE n.nspname='public' AND p.proname='current_app_user_id')
    THEN missing := missing || E'\n  * функція current_app_user_id() (002_rls / 003_reconcile)'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                 WHERE n.nspname='public' AND p.proname='get_app_user_id_from_auth_uid')
    THEN missing := missing || E'\n  * функція get_app_user_id_from_auth_uid() (030 / 045)'; END IF;

  IF missing <> '' THEN
    RAISE EXCEPTION E'У базі бракує того, на що спирається цей файл:%\n\nЗапустіть спершу вказані міграції з supabase/migrations/, потім цей файл ще раз.\nНІЧОГО не застосовано — транзакцію відкочено.', missing;
  END IF;
END $$;

PREFLIGHT
  echo
  cat <<'RESIGN'
-- ─────────────────────────────────────────────────────────────────────────
-- СКИДАННЯ ФУНКЦІЙ, ЧИЮ СИГНАТУРУ МІНЯЄ ПІЗНІША МІГРАЦІЯ В ЦЬОМУ Ж ФАЙЛІ
-- ─────────────────────────────────────────────────────────────────────────
-- Файл — КОНКАТЕНАЦІЯ, і саме тому тут потрібне те, чого не потрібно жодній
-- окремій міграції. Порядок усередині фіксований номерами: 061 переоголошує
-- публічні превʼю через `CREATE OR REPLACE`, а 064 ДОДАЄ їм колонку, тобто
-- міняє тип результату. Перший накат проходить (061 створює, 064 підміняє),
-- ДРУГИЙ падає: `CREATE OR REPLACE` у 061 наштовхується на функцію з іншим
-- типом результату (42P13, «cannot change return type of existing function»).
--
-- Тобто без цього блоку файл перестає бути ІДЕМПОТЕНТНИМ — властивість, яку
-- обіцяє його ж шапка і яку перевіряє CI повторним накатом.
--
-- Дропаємо перед усім: обидві міграції нижче створюють ці функції заново, а
-- транзакція гарантує, що проміжного стану ззовні не видно.
--
-- ДОДАВАТИ СЮДИ, щойно нова міграція в цьому вікні змінить тип результату
-- функції, яку раніша міграція створює через `CREATE OR REPLACE`. Забути не
-- страшно: повторний накат у CI впаде рівно з цієї причини.
DROP FUNCTION IF EXISTS get_public_property_preview(TEXT);
DROP FUNCTION IF EXISTS get_public_db_preview(TEXT);
DROP FUNCTION IF EXISTS get_public_collection_preview(TEXT);

RESIGN
  echo
  for f in $files; do
    echo "-- ─────────────────────────────────────────────────────────────────────────"
    echo "-- $(basename "$f")"
    echo "-- ─────────────────────────────────────────────────────────────────────────"
    cat "$f"
    echo
  done
  echo "COMMIT;"
} > "$OUT"

echo "✓ $OUT — $(echo "$files" | wc -l | tr -d ' ') міграцій, $(wc -l < "$OUT") рядків"
