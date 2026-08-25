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

# ── verify_release.sql теж мусить бути живим ────────────────────────────────
# Це ЄДИНЕ джерело правди для власника про стан живої БД (мережі до Supabase
# звідси немає). Але його рядки — це підрядкові збіги по `prosrc`, і вони
# тихо протухають: перевірка №1 шукала термін дії в `get_shared_collection`,
# яку 049 ВИДАЛИЛА як IDOR, тобто вічно світила «MISSING → виконай 026» і
# посилала оператора не туди. На свіжозібраній БД MISSING не має бути жодного.
miss=$($PSQL -d shadow -At -f supabase/verify_release.sql | grep -c '❌' || true)
if [ "$miss" != "0" ]; then
  echo "✗ verify_release.sql звітує $miss MISSING на БД, зібраній з УСІХ міграцій —"
  echo "  тобто протухла сама перевірка, а не база:"
  $PSQL -d shadow -At -f supabase/verify_release.sql | grep '❌'
  exit 1
fi
echo "✓ verify_release.sql: 0 MISSING"

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
$PSQL -d shadow_rel -f supabase/RELEASE.sql >/dev/null
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
