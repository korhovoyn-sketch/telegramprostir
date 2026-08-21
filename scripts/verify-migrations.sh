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
sleep 3

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
