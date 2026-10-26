#!/usr/bin/env bash
# Накочує ВСІ міграції на одноразовий Postgres і ганяє поведінкові перевірки.
#
# ЧОМУ ЦЕ ІСНУЄ. `supabase/migrations/` була ЄДИНОЮ текою репозиторію без
# жодної автоматичної перевірки — і саме там жили два найгірші дефекти
# останніх раундів рев'ю:
#   • `ORDER BY cp.created_at` при колонці `added_at` — весь батч відкотився б,
#     забравши з собою безпековий фікс, а оператор побачив би помилку про
#     підбірки й шукав би не там;
#   • перейменовані ключі JSON у RPC, чий єдиний споживач читав старі — екран
#     запрошеного гостя став би порожнім без жодного сигналу.
#
# Обидва ловляться цим скриптом за секунди. Юніт-гарди їх не бачили в принципі:
# вони звіряють ПІДРЯДКИ, а не виконують SQL.
set -euo pipefail

PGBIN=${PGBIN:-/usr/lib/postgresql/16/bin}
export PATH="$PGBIN:$PATH"
DATA=${PGDATA_DIR:-/tmp/pgshadow}
SOCK=${PGSOCK:-/tmp/pgshadow-run}
PORT=${PGPORT_SHADOW:-5433}
PSQL="psql -h $SOCK -p $PORT -U postgres -v ON_ERROR_STOP=1 -q"

cleanup() { pg_ctl -D "$DATA" stop -m immediate >/dev/null 2>&1 || true; }
trap cleanup EXIT

pkill -f "postgres.*$DATA" >/dev/null 2>&1 || true
rm -rf "$DATA" "$SOCK"; mkdir -p "$DATA" "$SOCK"
# initdb відмовляється працювати від root — під CI і локально запускаємо від
# невілейованого користувача, якщо ми root.
if [ "$(id -u)" = "0" ]; then
  chown -R postgres:postgres "$DATA" "$SOCK"
  RUN="su postgres -c"
  $RUN "PATH=$PGBIN:\$PATH initdb -D $DATA -U postgres --auth=trust" >/dev/null
  # `listen_addresses=''` — лише unix-сокет. TCP-порт міг би зіткнутись із
  # чужим кластером на тій самій машині, і скрипт падав би не через міграції.
  $RUN "PATH=$PGBIN:\$PATH pg_ctl -D $DATA -o '-p $PORT -k $SOCK -c listen_addresses=' -l $SOCK/pg.log start" >/dev/null
else
  initdb -D "$DATA" -U postgres --auth=trust >/dev/null
  pg_ctl -D "$DATA" -o "-p $PORT -k $SOCK -c listen_addresses=" -l "$SOCK/pg.log" start >/dev/null
fi

# Чекати на ГОТОВНІСТЬ, а не на секунди: під навантаженням (паралельний
# playwright, повільний раннер) фіксований sleep дає «connection failed» на
# рівному місці, і прогін падає не через міграції, а через власний старт.
for _ in $(seq 1 60); do
  pg_isready -h "$SOCK" -p $PORT -U postgres >/dev/null 2>&1 && break
  sleep 1
done
if ! pg_isready -h "$SOCK" -p $PORT -U postgres >/dev/null 2>&1; then
  echo "✗ Postgres не піднявся"; tail -20 "$SOCK/pg.log" 2>/dev/null; exit 2
fi

psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow" >/dev/null
$PSQL -d shadow -f scripts/pg-shim.sql >/dev/null

fail=0
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f")
  case "$b" in
    # Легасі, обидва НЕ застосовні і в проді:
    #  0041 — `CREATE POLICY IF NOT EXISTS`, синтаксису якого в Postgres немає;
    #  009  — діагностичний SELECT у кінці з невалідним ORDER BY по UNION.
    0041_*|009_*) continue;;
  esac
  if ! out=$($PSQL -d shadow -f "$f" 2>&1); then
    # psql віддає ненульовий код і тоді, коли впав НЕ SQL, а зʼєднання (сервер
    # не піднявся, кластер прибили ззовні). Без цієї гілки такий збій
    # репортується як «міграція зламана», і наступний читач шукає дефект у
    # файлі, з яким усе гаразд — спостережено один раз саме так.
    if ! echo "$out" | grep -q "ERROR:"; then
      echo "✗ ЗБІЙ ЗʼЄДНАННЯ, не міграції (на $b):"; echo "$out" | head -3
      echo "  (кластер не відповідає — це проблема стенда, а не SQL)"; exit 2
    fi
    echo "✗ $b"; echo "$out" | grep -E "ERROR|LINE" | head -3; fail=$((fail+1))
  fi
done

if [ $fail -gt 0 ]; then echo "МІГРАЦІЙ ІЗ ПОМИЛКАМИ: $fail"; exit 1; fi
echo "✓ усі міграції виконались"

$PSQL -d shadow -f scripts/verify-behaviour.sql
echo "✓ поведінкові перевірки пройдено"

# RLS ганяємо на ОКРЕМІЙ базі: попередній файл навмисно видаляє акаунти й
# лишає по собі напівпорожній стан, а тут кожен count() має бути точним.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_rls" >/dev/null
$PSQL -d shadow_rls -f scripts/pg-shim.sql >/dev/null 2>&1
# Помилки тут НЕ ковтаємо: другий прохід іде по тих самих файлах, але на
# чистій базі, і міграція, що падає ЛИШЕ тут, була б невидима за побудовою.
# (Перший прохід її не ловить: там інша послідовність станів — напр. дані,
# посаджені поведінковими перевірками.)
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*) continue;; esac
  if ! out=$($PSQL -d shadow_rls -f "$f" 2>&1); then
    echo "✗ (shadow_rls) $b"; echo "$out" | grep -E "ERROR|LINE" | head -3; exit 1
  fi
done
$PSQL -d shadow_rls -f scripts/verify-rls.sql
echo "✓ RLS-перевірки пройдено"

# ── Ремонтна половина 053 ───────────────────────────────────────────────────
# 053 має ДВА боки (урок 046): політика — щоб нових підкиднів не було, і
# переприсвоєння — щоб уже посаджені перестали діяти. Другий бік неможливо
# перевірити в загальному прогоні: він відпрацьовує ПІД ЧАС міграції, коли
# тестових даних ще немає. Тому саджаємо аномалію ПІСЛЯ (від postgres, тобто
# в обхід RLS — рівно як зробила б будь-яка майбутня діра) і виконуємо файл
# 053 ЩЕ РАЗ. Це заодно доводить його ідемпотентність.
$PSQL -d shadow_rls -c "
INSERT INTO properties (id,db_id,owner_id,name,status)
VALUES ('99990000-0000-0000-0000-000000000001',
        'd0000000-0000-0000-0000-00000000000b',
        'a0000000-0000-0000-0000-00000000000a','Підкидень','free');" >/dev/null
$PSQL -d shadow_rls -f supabase/migrations/053_owner_policies_target_ownership.sql >/dev/null
left=$($PSQL -d shadow_rls -At -c "
SELECT count(*) FROM properties p JOIN databases d ON d.id=p.db_id
WHERE p.owner_id <> d.owner_id;")
if [ "$left" != "0" ]; then
  echo "✗ 053: ремонтний блок не переприсвоїв підкинуті рядки (лишилось $left)"
  echo "  Тобто вже посаджені підкидні лишаються на публічній /v жертви, і вона"
  echo "  не може їх ні знайти, ні видалити — половина фікса не працює."
  exit 1
fi
echo "✓ 053: уже посаджені підкидні переприсвоєно власнику цілі"

# ── Ремонтна половина 069 ───────────────────────────────────────────────────
# Той самий клас, що 053: ремонт відпрацьовує ПІД ЧАС міграції, коли
# знижених ще немає. Знижуємо Алісу (має базу) так, як це робив старий
# `claim_guest_link` (owner→guest тригер пропускає), і виконуємо 069 ЩЕ РАЗ.
# Контроль із другого боку: Новачок69 — гість БЕЗ баз (див. verify-rls.sql),
# і ремонт не сміє зробити його власником.
$PSQL -d shadow_rls -c "UPDATE users SET role='guest' WHERE id='a0000000-0000-0000-0000-00000000000a';" >/dev/null
$PSQL -d shadow_rls -f supabase/migrations/069_access_integrity.sql >/dev/null
roles=$($PSQL -d shadow_rls -At -c "
SELECT string_agg(role, ',' ORDER BY id) FROM users
WHERE id IN ('a0000000-0000-0000-0000-00000000000a','a6900000-0000-0000-0000-000000000003');")
trg=$($PSQL -d shadow_rls -At -c "
SELECT tgenabled FROM pg_trigger WHERE tgrelid='public.users'::regclass
  AND tgname='trg_prevent_privilege_escalation';")
if [ "$roles" != "owner,guest" ]; then
  echo "✗ 069: ремонт ролей дав «$roles» замість «owner,guest»"
  echo "  (власник із базою мусить повернутись, гість без баз — лишитись)"
  exit 1
fi
if [ "$trg" != "O" ]; then
  echo "✗ 069: після ремонту тригер ескалації лишився ВИМКНЕНИМ ($trg) — самопідвищення відкрите"
  exit 1
fi
echo "✓ 069: знижених власників повернуто, гостя без баз не чіпано, тригер увімкнений"

# ── 074: ремонт залишків, що встигли статись ДО міграції ────────────────────
# Якщо 073 уже накотили і хтось видалив акаунт, у базі лежать висячий автор
# надходження й імена без посилання. Посадити такий залишок можна лише В ОБХІД
# тригерів і ключів (replica) — рівно так він і виникав: каскад скасовувався
# тригером, а перевірку ключа Postgres пропускав. Поруч — службовий підпис
# публічного перегляду: блокова чистка «імʼя без посилання» стерла б і його.
$PSQL -d shadow_rls -c "
SET session_replication_role = replica;
INSERT INTO databases (id,owner_id,name,type) VALUES
  ('d0740000-0000-0000-0000-000000000001','a0000000-0000-0000-0000-00000000000a','Ремонт 074','business_center');
INSERT INTO properties (id,db_id,owner_id,name,status) VALUES
  ('d0740000-0000-0000-0000-000000000002','d0740000-0000-0000-0000-000000000001','a0000000-0000-0000-0000-00000000000a','Обʼєкт 074','occupied');
INSERT INTO rent_payment_records (id,property_id,owner_id,due_date,status,amount) VALUES
  ('d0740000-0000-0000-0000-000000000003','d0740000-0000-0000-0000-000000000002','a0000000-0000-0000-0000-00000000000a','2026-09-05','partial',100);
INSERT INTO rent_payment_parts (record_id,amount,paid_at,created_by,created_by_name) VALUES
  ('d0740000-0000-0000-0000-000000000003',100,now(),'d0740000-dead-0000-0000-000000000074','Залишок');
INSERT INTO db_activity (db_id,kind,actor_id,actor_name) VALUES
  ('d0740000-0000-0000-0000-000000000001','photo_deleted',NULL,'Залишок');
INSERT INTO property_views (property_id,viewer_id,viewer_name,action) VALUES
  ('d0740000-0000-0000-0000-000000000002',NULL,'Залишок','view'),
  ('d0740000-0000-0000-0000-000000000002',NULL,'Веб-перегляд','view');
INSERT INTO guest_links (owner_id,property_id,invite_token,status,guest_user_id,guest_name) VALUES
  ('a0000000-0000-0000-0000-00000000000a','d0740000-0000-0000-0000-000000000002','tok_074_repair','revoked',NULL,'Залишок');
SET session_replication_role = origin;" >/dev/null
$PSQL -d shadow_rls -f supabase/migrations/074_account_erasure.sql >/dev/null
left=$($PSQL -d shadow_rls -At -c "
SELECT (SELECT count(*) FROM rent_payment_parts pp
         WHERE pp.created_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = pp.created_by))
     + (SELECT count(*) FROM rent_payment_parts WHERE created_by_name = 'Залишок')
     + (SELECT count(*) FROM db_activity        WHERE actor_name      = 'Залишок')
     + (SELECT count(*) FROM property_views     WHERE viewer_name     = 'Залишок')
     + (SELECT count(*) FROM guest_links        WHERE guest_name      = 'Залишок');")
kept=$($PSQL -d shadow_rls -At -c "
SELECT count(*) FROM property_views
 WHERE property_id = 'd0740000-0000-0000-0000-000000000002' AND viewer_name = 'Веб-перегляд';")
if [ "$left" != "0" ]; then
  echo "✗ 074: ремонт лишив $left залишків видаленого акаунта (висячий автор або імʼя без посилання)"
  exit 1
fi
if [ "$kept" != "1" ]; then
  echo "✗ 074: ремонт стер службовий підпис публічного перегляду — аналітика втратить «Веб-перегляд»"
  exit 1
fi
echo "✓ 074: висячого автора й імен без посилання не лишилось; службовий підпис цілий"

# ── verify_release.sql теж мусить бути живим ────────────────────────────────
# Це ЄДИНЕ джерело правди для власника про стан живої БД (мережі до Supabase
# звідси немає). Але його рядки — це підрядкові збіги по `prosrc`, і вони
# тихо протухають: перевірка №1 шукала термін дії в `get_shared_collection`,
# яку 049 ВИДАЛИЛА як IDOR, тобто вічно світила «MISSING → виконай 026» і
# посилала оператора не туди. На свіжозібраній БД MISSING не має бути жодного.
#
# АНТИВАКУУМ — повна кількість ✅, а не лише нуль ❌. Доти тут стояло
# `psql … | grep -c '❌' || true`, і під `pipefail` впалий psql давав
# порожній вивід, тобто «0 MISSING» — перевірка, що ПАДАЄ, проходила як
# зелена. Тепер і сама вона мусить виконатись, і вивести ВСІ пункти.
checks=$(grep -cE '^[[:space:]]+\([0-9]+,[[:space:]]' supabase/verify_release.sql)
if ! vr_all=$($PSQL -d shadow -At -f supabase/verify_release.sql 2>&1); then
  echo "✗ verify_release.sql ПАДАЄ на БД, зібраній з усіх міграцій:"
  echo "$vr_all" | grep -E "ERROR" | head -3
  exit 1
fi
oks=$(printf '%s\n' "$vr_all" | grep -c '✅' || true)
miss=$(printf '%s\n' "$vr_all" | grep -c '❌' || true)
if [ "$miss" != "0" ] || [ "$oks" != "$checks" ]; then
  echo "✗ verify_release.sql на БД з УСІХ міграцій: ✅ $oks із $checks, ❌ $miss —"
  echo "  тобто протухла сама перевірка, а не база:"
  printf '%s\n' "$vr_all" | grep '❌' || true
  exit 1
fi
echo "✓ verify_release.sql: усі $checks пунктів ✅"

# ── RELEASE.sql не розійшовся з міграціями ─────────────────────────────────
# Склеєний файл — ПОХІДНИЙ. Якщо він розійдеться з `supabase/migrations/`,
# оператор накотить у прод НЕ ТЕ, що лежить у репозиторії, і дізнається про це
# найгіршим способом. Тому перевіряємо байт у байт: перегенерувати й порівняти.
OUT=/tmp/RELEASE.regen.sql bash scripts/build-release-sql.sh >/dev/null
if ! diff -q supabase/RELEASE.sql /tmp/RELEASE.regen.sql >/dev/null; then
  echo "✗ supabase/RELEASE.sql розійшовся з supabase/migrations/"
  echo "  Перезібери: bash scripts/build-release-sql.sh"
  diff supabase/RELEASE.sql /tmp/RELEASE.regen.sql | head -20
  exit 1
fi
echo "✓ RELEASE.sql збігається з міграціями"

# ── І він СПРАВДІ дає ту саму схему, що поштучний накат ────────────────────
# Це не формальність: доводиться саме ЕКВІВАЛЕНТНІСТЬ, а не лише те, що файл
# виконується. База `shadow` вище вже зібрана поштучно — збираємо другу з
# прод-стану (до 048) плюс один файл і звіряємо хеші визначень.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_rel" >/dev/null
$PSQL -d shadow_rel -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*) continue;; esac
  if [[ "$b" =~ ^([0-9]{3})_ ]]; then n=$((10#${BASH_REMATCH[1]})); else n=0; fi
  [ "$n" -ge 48 ] && continue
  $PSQL -d shadow_rel -f "$f" >/dev/null 2>&1 || true
done
# ПЕРЕВІРКА ВБУДОВАНА В ФАЙЛ: оператор запускає ОДИН файл і читає таблицю в
# кінці. Тож гард питає рівно те, що побачить він: таблиця є, у ній УСІ
# пункти verify_release.sql і жодного MISSING. Повна кількість — антивакуум:
# таблиця, що не виконалась чи обірвалась, інакше теж «не має MISSING».
if ! rel_out=$($PSQL -d shadow_rel -f supabase/RELEASE.sql 2>&1); then
  echo "✗ RELEASE.sql падає на прод-подібній базі (001..047):"
  echo "$rel_out" | grep -E "ERROR" | head -3
  exit 1
fi
oks=$(printf '%s\n' "$rel_out" | grep -c '✅ OK' || true)
bad=$(printf '%s\n' "$rel_out" | grep -c '❌' || true)
if [ "$oks" != "$checks" ] || [ "$bad" != "0" ]; then
  echo "✗ вбудована перевірка RELEASE.sql: ✅ $oks із $checks, ❌ $bad —"
  echo "  оператор побачив би неповну або червону таблицю замість підтвердження"
  printf '%s\n' "$rel_out" | grep '❌' | head -5 || true
  exit 1
fi
echo "✓ RELEASE.sql сам показує таблицю перевірки: усі $checks пунктів ✅"
# Повторний накат — доказ ідемпотентності (оператор може натиснути двічі).
$PSQL -d shadow_rel -f supabase/RELEASE.sql >/dev/null
psql -h "$SOCK" -p $PORT -U postgres -d shadow     -At -f scripts/schema-fingerprint.sql > /tmp/fp_a.txt
psql -h "$SOCK" -p $PORT -U postgres -d shadow_rel -At -f scripts/schema-fingerprint.sql > /tmp/fp_b.txt
if ! diff -q /tmp/fp_a.txt /tmp/fp_b.txt >/dev/null; then
  echo "✗ RELEASE.sql дає ІНШУ схему, ніж поштучний накат:"
  diff /tmp/fp_a.txt /tmp/fp_b.txt | head -20
  exit 1
fi
echo "✓ RELEASE.sql еквівалентний поштучному накату ($(wc -l < /tmp/fp_a.txt) обʼєктів) і ідемпотентний"

# ── RELEASE.sql на базі З ПРОГАЛИНАМИ ──────────────────────────────────────
# ЧОМУ ЦЕ ОКРЕМА ПЕРЕВІРКА. Попередня доводить еквівалентність на
# ОПТИМІСТИЧНІЙ базі — тій, де застосовано всі 001..047. Прод такою НЕ Є:
# накат там робився вручну, і файл реально впав на
# `mark_overdue_payments() does not exist`, бо міграції 024 у проді немає.
# Тобто доказ був справжній, але передумова — хибна.
#
# Тому другий стенд: та сама база БЕЗ 024. Файл мусить пройти (ACL на
# відсутню функцію пропускається свідомо), а не впасти.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_gap" >/dev/null
$PSQL -d shadow_gap -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*|024_*) continue;; esac
  if [[ "$b" =~ ^([0-9]{3})_ ]]; then n=$((10#${BASH_REMATCH[1]})); else n=0; fi
  [ "$n" -ge 48 ] && continue
  $PSQL -d shadow_gap -f "$f" >/dev/null 2>&1 || true
done
if ! out=$($PSQL -d shadow_gap -f supabase/RELEASE.sql 2>&1); then
  echo "✗ RELEASE.sql падає на базі з прогалиною (немає 024) — саме цей клас уже стався в проді:"
  echo "$out" | grep -E "ERROR|ПІДКАЗКА|бракує" | head -5
  exit 1
fi
echo "✓ RELEASE.sql переживає прогалину в базі (024 відсутня)"

# ── АТОМАРНІСТЬ RELEASE.sql ────────────────────────────────────────────────
# ЧОМУ ЦЕ ОКРЕМА ПЕРЕВІРКА, І ЧОМУ ЇЇ ДОСІ НЕ БУЛО. Шапка файлу обіцяє «при
# будь-якій помилці НІЧОГО не застосується», і саме ця властивість урятувала
# прод, коли накат упав на `mark_overdue_payments()`. Але доказ був
# ОДНОРАЗОВИЙ — зроблений руками під час написання, — а сталого гарда не
# існувало. Обґрунтування, зроблене один раз, протухає мовчки: 065 додала
# власні BEGIN/COMMIT, і файл перестав бути атомарним, не зламавши жодного
# тесту.
#
# Механізм: у Postgres немає вкладених транзакцій. Внутрішній `BEGIN` дає лише
# WARNING, а внутрішній `COMMIT` ЗАКРИВАЄ зовнішню транзакцію — усе після
# нього йде в autocommit. Заміряно: збій у зоні 066 (БЕЗПЕКОВОЇ міграції)
# лишав обʼєкти 064 і 065 у базі, тобто напівзастосований стан рівно там, де
# оператор, за вже записаним уроком, вважає, що не застосувалось нічого.
#
# ДЕ САМЕ ламати — не деталь. Збій треба вставити перед ОСТАННІМ `COMMIT;`:
# перед першим він у зламаному файлі потрапляє ще всередину зовнішньої
# транзакції, відкат відбувається, і гард мовчить про дефект. На цьому я вже
# наступив, будуючи пробу.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_atomic" >/dev/null
$PSQL -d shadow_atomic -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*) continue;; esac
  if [[ "$b" =~ ^([0-9]{3})_ ]]; then n=$((10#${BASH_REMATCH[1]})); else n=0; fi
  [ "$n" -ge 48 ] && continue
  $PSQL -d shadow_atomic -f "$f" >/dev/null 2>&1 || true
done
probe_sql() { psql -h "$SOCK" -p $PORT -U postgres -d shadow_atomic -At -c "$1"; }
# АНТИВАКУУМ: якщо маркери вже є до накату, «їх немає після» не значить нічого.
LEASE_Q="SELECT count(*) FROM pg_proc WHERE proname='get_due_lease_reminders'"
LAND_Q="SELECT count(*) FROM information_schema.columns WHERE table_name='properties' AND column_name='landlord_name'"
if [ "$(probe_sql "$LEASE_Q")$(probe_sql "$LAND_Q")" != "00" ]; then
  echo "✗ стенд атомарності забруднений: маркери 064/065 є ще ДО накату — перевірка вакуумна"; exit 1
fi
LAST_COMMIT=$(grep -nE '^COMMIT;[[:space:]]*$' supabase/RELEASE.sql | tail -1 | cut -d: -f1)
[ -z "$LAST_COMMIT" ] && { echo "✗ у RELEASE.sql немає завершального COMMIT"; exit 1; }
awk -v k="$LAST_COMMIT" 'NR==k{print "SELECT 1/0;"} {print}' supabase/RELEASE.sql > "$SOCK/atomic_boom.sql"
$PSQL -d shadow_atomic -f "$SOCK/atomic_boom.sql" >/dev/null 2>&1 && {
  echo "✗ підставлений збій не завалив накат — проба атомарності нічого не міряє"; exit 1
}
left="$(probe_sql "$LEASE_Q")$(probe_sql "$LAND_Q")"
if [ "$left" != "00" ]; then
  echo "✗ RELEASE.sql НЕ атомарний: після збою в зоні останньої міграції в базі лишились"
  echo "  обʼєкти попередніх (get_due_lease_reminders/landlord_name = $left)."
  echo "  Причина майже напевно та сама: якась міграція несе власні BEGIN;/COMMIT;,"
  echo "  а внутрішній COMMIT закриває зовнішню транзакцію. Їх вирізає"
  echo "  scripts/build-release-sql.sh — перезбери файл і перевір його лічильник."
  exit 1
fi
echo "✓ RELEASE.sql атомарний: збій у зоні останньої міграції не лишає напівстану"

# ── Перевірка не ПАДАЄ на базі ДО накату ──────────────────────────────────
# Після відкату вище `shadow_atomic` — рівно прод-подібна база 001..047, де
# таблиць із нових міграцій (оренди, надходження, журнал…) ще НЕМАЄ. Саме тут
# оператор запускає verify_release.sql, щоб побачити, що бракує, — і рядок,
# який звертається до такої таблиці напряму, дав би ERROR замість MISSING:
# замість відповіді «чого бракує» людина отримала б помилку.
#
# Обидві половини обовʼязкові: повна кількість рядків доводить, що запит
# виконався, а ❌ > 0 — що база справді ДО накату, інакше гард нічого не міряв.
if ! vpre=$($PSQL -d shadow_atomic -At -f supabase/verify_release.sql 2>&1); then
  echo "✗ verify_release.sql ПАДАЄ на базі до накату, а мав би показати MISSING:"
  echo "$vpre" | grep -E "ERROR" | head -3
  exit 1
fi
rows=$(printf '%s\n' "$vpre" | grep -cE '✅|❌' || true)
red=$(printf '%s\n' "$vpre" | grep -c '❌' || true)
if [ "$rows" != "$checks" ] || [ "$red" = "0" ]; then
  echo "✗ verify_release.sql на базі до накату: рядків $rows із $checks, ❌ $red —"
  echo "  або запит обірвався, або стенд уже не «до накату» і гард нічого не міряє"
  exit 1
fi
echo "✓ verify_release.sql на базі до накату не падає: $checks пунктів, із них ❌ $red"

# І навпаки: якщо бракує чогось ОБОВʼЯЗКОВОГО, файл мусить сказати ЩО САМЕ,
# а не впасти на першому-ліпшому обʼєкті.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_bare" >/dev/null
$PSQL -d shadow_bare -f scripts/pg-shim.sql >/dev/null 2>&1
if out=$($PSQL -d shadow_bare -f supabase/RELEASE.sql 2>&1); then
  echo "✗ RELEASE.sql пройшов на ПОРОЖНІЙ базі — передпольотна перевірка не працює"
  exit 1
fi
if ! echo "$out" | grep -q "бракує того, на що спирається"; then
  echo "✗ на порожній базі впало БЕЗ зрозумілого пояснення:"
  echo "$out" | grep -E "ERROR" | head -3
  exit 1
fi
echo "✓ на базі без передумов файл називає, ЧОГО бракує і яку міграцію запустити"


# ── Прогалина в КОЛОНЦІ, а не у функції ────────────────────────────────────
# Той самий клас, інший бік: `mark_overdue_payments` бракувало функції, і це
# видно на ACL — тобто на початку. Колонка з пізньої міграції проявляється
# ПОСЕРЕД накату, у тілі превʼю, і повідомлення Postgres назве саму колонку,
# не сказавши, якої міграції бракує. Стенд без 042 доводить, що передпольотна
# перевірка ловить це РАНІШЕ і називає міграцію.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_colgap" >/dev/null
$PSQL -d shadow_colgap -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*|042_*) continue;; esac
  if [[ "$b" =~ ^([0-9]{3})_ ]]; then n=$((10#${BASH_REMATCH[1]})); else n=0; fi
  [ "$n" -ge 48 ] && continue
  $PSQL -d shadow_colgap -f "$f" >/dev/null 2>&1 || true
done
if out=$($PSQL -d shadow_colgap -f supabase/RELEASE.sql 2>&1); then
  echo "✗ RELEASE.sql пройшов без 042 — колонку area_basis читають тіла превʼю, це не могло спрацювати"
  exit 1
fi
if ! echo "$out" | grep -q "properties.area_basis (042_area_basis)"; then
  echo "✗ прогалина в колонці впала БЕЗ називання міграції:"
  echo "$out" | grep -E "ERROR" | head -3
  exit 1
fi
echo "✓ прогалина в колонці називається передпольотною перевіркою, а не помилкою посеред накату"

# ── ЛЕГАСІ-СТЕНД: пермісивні політики й відкритий грант, як у справжньому проді
# Прод дав два MISSING там, де всі мої стенди були зелені: 038 туди ніколи не
# доїхала, тож пермісивні `photos_insert_auth`/`photos_delete_auth` (008) живі
# й перебивають строгі правила 054 (політики обʼєднуються через OR), а на
# функції нагадувань лишився дефолтний PUBLIC, якого точний REVOKE із 052 не
# зняв. Обидва невидимі на чистому наканаті — тут вони СІЮТЬСЯ навмисно.
#
# Порада «виконай 038» була б небезпечною: 038 несе копію
# get_app_user_id_from_auth_uid() ДО 031, тобто відкотила б фікс 045. Тому
# стенд окремо перевіряє, що після накату захист 045 НА МІСЦІ.
psql -h "$SOCK" -p $PORT -U postgres -q -c "CREATE DATABASE shadow_legacy" >/dev/null
$PSQL -d shadow_legacy -f scripts/pg-shim.sql >/dev/null 2>&1
for f in $(ls supabase/migrations/*.sql | sort); do
  b=$(basename "$f"); case "$b" in 0041_*|009_*|024_*|038_*) continue;; esac
  if [[ "$b" =~ ^([0-9]{3})_ ]]; then n=$((10#${BASH_REMATCH[1]})); else n=0; fi
  [ "$n" -ge 48 ] && continue
  $PSQL -d shadow_legacy -f "$f" >/dev/null 2>&1 || true
done
# Пермісивні політики тут переважно вже Є — їх створює 008/033, а 038, яка їх
# прибирає, у цьому стенді пропущена (як і в проді). Сіємо все одно, щоб намір
# стенда був явним, а не залежав від того, що саме лишили попередні міграції;
# `|| true` — бо «вже існує» тут очікуваний, а не збій.
$PSQL -d shadow_legacy -c "CREATE POLICY photos_insert_auth ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id='photos')" >/dev/null 2>&1 || true
$PSQL -d shadow_legacy -c "CREATE POLICY photos_delete_auth ON storage.objects FOR DELETE TO authenticated USING (bucket_id='photos')" >/dev/null 2>&1 || true
$PSQL -d shadow_legacy -c "CREATE POLICY pfiles_insert_realtor ON property_files FOR INSERT TO authenticated WITH CHECK (true)" >/dev/null 2>&1 || true
# АНТИВАКУУМ: без цього «нуль MISSING» означало б і «сіяти не вдалось».
seeded=$($PSQL -d shadow_legacy -t -A -c "SELECT count(*) FROM pg_policies WHERE policyname IN ('photos_insert_auth','photos_delete_auth','pfiles_insert_realtor')")
if [ "$seeded" -lt 3 ]; then echo "✗ легасі-стенд порожній: пермісивних політик $seeded із 3"; exit 1; fi
if ! out=$($PSQL -d shadow_legacy -f supabase/RELEASE.sql 2>&1); then
  echo "✗ RELEASE.sql падає на легасі-стенді:"; echo "$out" | grep -E "ERROR" | head -3; exit 1
fi
# Дефолтний PUBLIC, що пережив 052 у проді — відтворюємо і вимагаємо зняття.
$PSQL -d shadow_legacy -c "GRANT EXECUTE ON FUNCTION get_due_reminders_today() TO PUBLIC" >/dev/null 2>&1 || true
$PSQL -d shadow_legacy -f supabase/migrations/062_legacy_permissive_and_acl.sql >/dev/null 2>&1 || true
vr=$($PSQL -d shadow_legacy -f supabase/verify_release.sql 2>&1)
# Позитивний контроль: без нього «нуль MISSING» означало б і «файл не виконався».
oks=$(echo "$vr" | grep -c "OK")
if [ "$oks" -lt 30 ]; then echo "✗ verify_release не виконався на легасі-стенді (OK=$oks)"; exit 1; fi
if echo "$vr" | grep -qi MISSING; then
  echo "✗ легасі-стенд: лишились MISSING після накату"; echo "$vr" | grep -i MISSING; exit 1
fi
echo "✓ легасі-стенд: пермісивні політики й відкритий грант знято, фікс 045 на місці"

# ── Колонки, які ЧИТАЄ застосунок, існують у справжній схемі ──────────────────
#
# Невідома колонка в `select()` — це не порожнє поле, а PostgREST 400 на ВЕСЬ
# запит. Для `USER_COLUMNS` це означає, що ламається ВХІД: `refreshSessionSilently`
# і `loginViaTelegram` читають профіль саме ним. Урок уже коштував раунду (042:
# `area_basis` довелось накочувати ПЕРЕД деплоєм фронта), і CLAUDE.md прямо
# застерігає не додавати `public_phone` в цей список.
#
# Списки беруться З КОДУ, а не дублюються тут: копія розійшлася б за раунд.
col_check() {  # $1 = таблиця, $2 = кома-список колонок
  local missing
  missing=$($PSQL -d shadow -t -A -c "
    SELECT string_agg(c, ', ') FROM unnest(string_to_array('$2', ',')) AS c
     WHERE c NOT IN (SELECT column_name FROM information_schema.columns
                      WHERE table_schema='public' AND table_name='$1')")
  if [ -n "$missing" ]; then
    echo "✗ $1: застосунок читає неіснуючі колонки → PostgREST 400 на весь запит: $missing"
    exit 1
  fi
}
extract() {  # витягти рядок-константу з коду (лише літерал, без бектик-шаблонів)
  grep -oP "(?<=$2 = ')[a-z_,0-9]+(?=')" "$1" | head -1
}
USER_COLS=$(extract src/lib/supabase.ts 'USER_COLUMNS')
DB_COLS=$(extract src/hooks/useDatabases.ts 'DB_COLUMNS')
RP_COLS=$(grep -A2 "RENT_PAYMENT_COLUMNS =" src/lib/rentPayments.ts | grep -oP "'\K[a-z_,0-9]+(?=')" | head -1)
[ -z "$USER_COLS" ] && { echo "✗ не вдалось витягти USER_COLUMNS — формат константи змінився"; exit 1; }
[ -z "$DB_COLS" ]   && { echo "✗ не вдалось витягти DB_COLUMNS — формат константи змінився"; exit 1; }
col_check users "$USER_COLS"
col_check databases "$DB_COLS"
[ -n "$RP_COLS" ] && col_check rent_payments "$RP_COLS"
echo "✓ колонки USER_COLUMNS/DB_COLUMNS існують у схемі (вхід не впаде на PostgREST 400)"

# ── Реєстрація НОВОГО користувача сумісна зі схемою ───────────────────────────
#
# `telegram-auth` вставляє рядок у `public.users` рівно з полів `userPayload`
# (+ `role`). Якщо в таблиці зʼявиться NOT NULL колонка без DEFAULT, якої там
# немає, INSERT падатиме — але ЛИШЕ для нових акаунтів: наявні користувачі йдуть
# гілкою UPDATE і нічого не помітять. Тобто реєстрація ламається тихо й
# вибірково, і жоден e2e цього не побачить (вони мокають edge-функцію).
EDGE=supabase/functions/telegram-auth/index.ts
ins_cols=$(sed -n '/const userPayload = {/,/^    }/p' "$EDGE" | grep -oP '^\s+\K[a-z_]+(?=:)' | tr '\n' ',')ROLE
ins_cols="${ins_cols%ROLE}role"
[ "$(echo "$ins_cols" | tr -cd ',' | wc -c)" -lt 4 ] && { echo "✗ не вдалось витягти userPayload з $EDGE"; exit 1; }
req_missing=$($PSQL -d shadow -t -A -c "
  SELECT string_agg(column_name, ', ') FROM information_schema.columns
   WHERE table_schema='public' AND table_name='users'
     AND is_nullable='NO' AND column_default IS NULL
     AND column_name <> ALL (string_to_array('$ins_cols', ','))")
if [ -n "$req_missing" ]; then
  echo "✗ реєстрація нового користувача впаде: users має обовʼязкові колонки без DEFAULT, яких telegram-auth не пише: $req_missing"
  exit 1
fi
echo "✓ INSERT нового користувача покриває всі обовʼязкові колонки users"
