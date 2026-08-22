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
